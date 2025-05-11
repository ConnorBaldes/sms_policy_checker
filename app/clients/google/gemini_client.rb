# app/clients/google/gemini_client.rb
require 'faraday'
require 'faraday_json'
require 'json'

module Google
  class GeminiClient
    # Consider making model name configurable or choosing the latest suitable one.
    # gemini-1.5-flash is often a good balance of capability and speed/cost for structured output.
    # Make sure the chosen model supports responseSchema with application/json.
    DEFAULT_MODEL_NAME = 'gemini-1.5-flash-latest' # Or 'gemini-1.0-pro', 'gemini-1.5-pro-latest'
    BASE_URL = 'https://generativelanguage.googleapis.com'
    API_VERSION = 'v1beta' # v1beta is often needed for responseSchema
    GENERATION_ENDPOINT_TEMPLATE = "#{API_VERSION}/models/%{model}:generateContent"

    attr_reader :api_key, :connection, :model_name

    def initialize(api_key: ENV['GOOGLE_API_KEY'], model_name: DEFAULT_MODEL_NAME)
      @api_key = api_key
      @model_name = model_name

      unless @api_key && !@api_key.empty?
        Rails.logger.warn "Google::GeminiClient initialized without a valid API key. Real API calls will fail."
      end

      @connection = Faraday.new(url: BASE_URL) do |faraday|
        faraday.request :json
        faraday.response :json, content_type: /\bjson$/, parser_options: { symbolize_names: false } # Keep keys as strings
        faraday.response :raise_error # Raise exceptions for 4xx/5xx responses
        faraday.adapter Faraday.default_adapter
        faraday.options.timeout = 60        # Read timeout
        faraday.options.open_timeout = 10   # Connection timeout
      end
    end

    # This is the schema we expect Gemini to return for our policy checks.
    EXPECTED_RESPONSE_SCHEMA = {
      type: "OBJECT",
      properties: {
        confidence_score: { type: "NUMBER" }, # Gemini seems to prefer NUMBER for floats here
        rationale: { type: "STRING" }
      },
      required: ["confidence_score", "rationale"]
    }.freeze

    # Analyzes text for a specific characteristic using a given prompt.
    #
    # @param prompt_text [String] The full prompt to send to Gemini.
    # @return [Hash, nil] The parsed JSON content part from Gemini's response (containing confidence_score and rationale),
    #                     or a hash with an "error" key if an issue occurred.
    def analyze_characteristic(prompt_text)
      unless @api_key && !@api_key.empty?
        Rails.logger.error "Google::GeminiClient: API key is missing. Cannot make API call."
        return { "error" => "API key missing for GeminiClient" }
      end

      generation_endpoint = GENERATION_ENDPOINT_TEMPLATE % { model: @model_name }

      request_body = {
        contents: [{
          parts: [{ text: prompt_text }]
        }],
        generationConfig: {
          responseMimeType: "application/json",
          responseSchema: EXPECTED_RESPONSE_SCHEMA,
          # Optional: Add temperature, topP, maxOutputTokens if needed for policy analysis
          # temperature: 0.7, # Adjust for desired creativity/determinism
          # maxOutputTokens: 256 # Ensure it's enough for rationale
        }
        # Optional: Add safetySettings if you need to adjust content filtering
        # safetySettings: [ { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" }, ... ]
      }

      begin
        response = @connection.post(generation_endpoint) do |req|
          req.params['key'] = @api_key
          req.headers['Content-Type'] = 'application/json' # Ensure this is set
          req.body = request_body
        end

        # Gemini API nests the actual content within candidates -> content -> parts -> text
        # and this 'text' should be a JSON string because of responseMimeType and responseSchema.
        # The Faraday :json response middleware should have already parsed the outer JSON response.
        # Now we need to parse the JSON string within the 'text' part.

        # Validate response structure based on typical Gemini output
        candidates = response.body&.dig("candidates")
        if candidates.is_a?(Array) && !candidates.empty?
          first_candidate_parts = candidates.first&.dig("content", "parts")
          if first_candidate_parts.is_a?(Array) && !first_candidate_parts.empty?
            json_text_part = first_candidate_parts.first&.dig("text")
            if json_text_part.is_a?(String)
              begin
                parsed_json_content = JSON.parse(json_text_part)
                # Validate against our expected keys
                if parsed_json_content.key?("confidence_score") && parsed_json_content.key?("rationale")
                  return parsed_json_content # This is the {confidence_score: ..., rationale: ...} hash
                else
                  Rails.logger.error "Google::GeminiClient: Parsed JSON from 'text' part missing required keys. Content: #{parsed_json_content.inspect}"
                  return { "error" => "LLM response missing required keys", "details" => parsed_json_content }
                end
              rescue JSON::ParserError => e
                Rails.logger.error "Google::GeminiClient: Failed to parse JSON from 'text' part: #{e.message}. Content: #{json_text_part.truncate(200)}"
                return { "error" => "LLM response was not valid JSON in 'text' part", "details" => json_text_part.truncate(200) }
              end
            else
              Rails.logger.error "Google::GeminiClient: Expected 'text' part in Gemini response to be a String, but got #{json_text_part.class}. Parts: #{first_candidate_parts.inspect}"
              return { "error" => "LLM 'text' part was not a string" }
            end
          else
            Rails.logger.error "Google::GeminiClient: 'parts' array in Gemini response is missing or empty. Candidate: #{candidates.first.inspect}"
            return { "error" => "LLM response 'parts' array missing or empty" }
          end
        elsif response.body&.dig("promptFeedback", "blockReason")
          block_reason = response.body.dig("promptFeedback", "blockReason")
          safety_ratings = response.body.dig("promptFeedback", "safetyRatings")
          Rails.logger.warn "Google::GeminiClient: Prompt blocked by API. Reason: #{block_reason}. Ratings: #{safety_ratings.inspect}"
          return { "error" => "LLM prompt blocked by API", "block_reason" => block_reason, "safety_ratings" => safety_ratings }
        else
          Rails.logger.error "Google::GeminiClient: Unexpected Gemini response structure. No 'candidates' found or prompt was blocked without standard feedback. Body: #{response.body.inspect}"
          return { "error" => "LLM response structure was unexpected", "details" => response.body&.inspect }
        end

      rescue Faraday::ClientError, Faraday::ServerError => e
        Rails.logger.error "Google::GeminiClient API Error: #{e.class} - #{e.message}"
        error_body = e.response&.dig(:body) # This might be parsed JSON from Faraday
        api_error_message = "Gemini API Error (Status: #{e.response&.dig(:status)})"
        if error_body.is_a?(Hash) && error_body.dig("error", "message")
          api_error_message = error_body.dig("error", "message")
        elsif error_body.is_a?(String)
          api_error_message = error_body.truncate(200)
        end
        Rails.logger.error "Full API Error Details: Status: #{e.response&.dig(:status)}. Message: #{api_error_message}. Response Body: #{error_body.inspect}"
        return { "error" => api_error_message }

      rescue JSON::ParserError => e # Should be caught by the inner parse, but as a fallback
        Rails.logger.error "Google::GeminiClient General JSON Parsing Error: #{e.message}"
        return { "error" => "General JSON parsing error" }

      rescue StandardError => e
        Rails.logger.error "Google::GeminiClient Unexpected Error: #{e.class} - #{e.message}\n#{e.backtrace.first(5).join("\n")}"
        return { "error" => "Unexpected client error: #{e.class}" }
      end
    end
  end
end