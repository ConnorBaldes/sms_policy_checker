# app/clients/google/gemini_client.rb
require 'faraday'
require 'faraday_json' # Ensures Faraday::Request::Json is available
require 'json'

module Google
  # == Google::GeminiClient
  #
  # Client for interacting with Google's Generative Language API (Gemini).
  # It supports generating content based on prompts, with specific configurations
  # for schema-enforced JSON output.
  #
  # This client is used for:
  #   - Analyzing SMS message characteristics against policies (`analyze_characteristic`).
  #   - Generating rewrite suggestions for non-compliant SMS messages (`generate_rewrite`).
  #
  # === Configuration
  # - API Key: Requires a Google API key (via `GOOGLE_API_KEY` env var or param).
  # - Model Name: Defaults to `DEFAULT_MODEL_NAME` but can be overridden.
  #
  # === Error Handling
  # - Methods return a Hash. On failure, this hash contains an `"error"` key with a
  #   description. Additional keys like `"details"`, `"block_reason"`, or `"safety_ratings"`
  #   may be present depending on the error context.
  # - For `generate_rewrite`, a plain String response is also possible if the LLM
  #   determines a message is uncorrectable.
  # - Logs detailed errors to `Rails.logger`.
  #
  # @example Analyze Characteristic
  #   client = Google::GeminiClient.new
  #   prompt = "Analyze this text for compliance."
  #   response = client.analyze_characteristic(prompt)
  #   if response["error"]
  #     puts "Error: #{response['error']}"
  #   else
  #     puts "Confidence: #{response['confidence_score']}, Rationale: #{response['rationale']}"
  #   end
  #
  # @example Generate Rewrite
  #   client = Google::GeminiClient.new
  #   original_sms = "This is a bad message."
  #   reason = "Contains forbidden words."
  #   confidence = 0.9
  #   rewrite_suggestion = client.generate_rewrite(original_sms, reason, confidence)
  #   if rewrite_suggestion.is_a?(Hash) && rewrite_suggestion["error"]
  #     puts "Rewrite Error: #{rewrite_suggestion['error']}"
  #   elsif rewrite_suggestion.is_a?(String)
  #     puts "Uncorrectable: #{rewrite_suggestion}"
  #   else # Is a Hash with suggestions
  #     puts "Suggestions: #{rewrite_suggestion['general_fix_suggestions']}"
  #     puts "Rewrite: #{rewrite_suggestion['literal_rewrite']}"
  #   end
  #
  class GeminiClient
    # Default Gemini model to be used if not specified during initialization.
    DEFAULT_MODEL_NAME = 'gemini-1.5-flash-latest'
    # Base URL for the Google Generative Language API.
    BASE_URL = 'https://generativelanguage.googleapis.com'
    # API version for the Generative Language API.
    API_VERSION = 'v1beta'
    # Template for the generateContent API endpoint, requires model name interpolation.
    GENERATION_ENDPOINT_TEMPLATE = "#{API_VERSION}/models/%{model}:generateContent"

    # JSON schema definition expected for responses from `analyze_characteristic`.
    # Used in `generationConfig.responseSchema` to enforce JSON output structure.
    EXPECTED_RESPONSE_SCHEMA = {
      type: "OBJECT",
      properties: {
        confidence_score: { type: "NUMBER" },
        rationale: { type: "STRING" }
      },
      required: ["confidence_score", "rationale"]
    }.freeze

    # JSON schema definition expected for 'correctable' rewrite suggestions from `generate_rewrite`.
    # Used in `generationConfig.responseSchema`.
    REWRITE_RESPONSE_SCHEMA = {
      type: "OBJECT",
      properties: {
        general_fix_suggestions: { type: "STRING" },
        literal_rewrite: { type: "STRING" }
      },
      required: ["general_fix_suggestions", "literal_rewrite"]
    }.freeze

    attr_reader :api_key, :connection, :model_name

    # Initializes a new GeminiClient.
    #
    # @param api_key [String, nil] The Google API key. Defaults to `ENV['GOOGLE_API_KEY']`.
    # @param model_name [String] The name of the Gemini model to use (e.g., 'gemini-1.5-flash-latest').
    #   Defaults to `DEFAULT_MODEL_NAME`.
    def initialize(api_key: ENV['GOOGLE_API_KEY'], model_name: DEFAULT_MODEL_NAME)
      @api_key = api_key
      @model_name = model_name
      if @api_key.nil? || @api_key.empty?
        Rails.logger.warn "Google::GeminiClient initialized without a valid API key. API calls will fail without it."
      end

      @connection = Faraday.new(url: BASE_URL) do |faraday|
        faraday.request :json # Encode request body as JSON.
        # Parse JSON responses; symbolize_names: false to keep string keys as returned by Google API.
        faraday.response :json, content_type: /\bjson$/, parser_options: { symbolize_names: false }
        faraday.response :raise_error # Raise exceptions on 4xx/5xx HTTP responses.
        faraday.adapter Faraday.default_adapter # Use the default HTTP adapter.
        # Gemini calls can be longer, especially with complex prompts or schemas.
        faraday.options.timeout = 60      # Overall request timeout in seconds.
        faraday.options.open_timeout = 10 # Connection opening timeout in seconds.
      end
    end

    # Generates content from the Gemini model for analyzing a specific characteristic,
    # expecting a JSON response conforming to `EXPECTED_RESPONSE_SCHEMA`.
    #
    # @param prompt_text [String] The prompt to send to the LLM.
    # @return [Hash]
    #   - On success: A hash matching `EXPECTED_RESPONSE_SCHEMA` (e.g., `{ "confidence_score": Float, "rationale": String }`).
    #   - On failure: A hash with an `"error"` key and potentially other keys like `"details"`,
    #     `"block_reason"`, or `"safety_ratings"`.
    # @see #process_gemini_response_content for details on how the LLM's response is parsed.
    # @see #_make_gemini_api_request for the underlying API call.
    def analyze_characteristic(prompt_text)
      method_name = "analyze_characteristic"
      if @api_key.nil? || @api_key.empty?
        Rails.logger.error "Google::GeminiClient (#{method_name}): API key is missing."
        return { "error" => "API key missing for GeminiClient" }
      end

      generation_endpoint = GENERATION_ENDPOINT_TEMPLATE % { model: @model_name }
      # generationConfig with responseMimeType and responseSchema is crucial for forcing JSON output.
      request_body = {
        contents: [{ parts: [{ text: prompt_text }] }],
        generationConfig: {
          responseMimeType: "application/json",
          responseSchema: EXPECTED_RESPONSE_SCHEMA
        }
      }

      outer_response_body = _make_gemini_api_request(generation_endpoint, request_body, method_name)
      return outer_response_body if outer_response_body.key?("error") # Error from API call itself

      # Process the content within the successful API response
      process_gemini_response_content(outer_response_body)
    end

    # Attempts to generate rewrite suggestions for a non-compliant SMS message.
    #
    # The method instructs the LLM to either:
    # 1. State the message is uncorrectable (specific string format).
    # 2. Provide a JSON object with suggestions, conforming to `REWRITE_RESPONSE_SCHEMA`.
    #
    # @param original_message [String] The original SMS message content.
    # @param failure_reason [String] The reason the message failed policy checks.
    # @param failure_confidence [Float] The confidence score of the policy failure.
    # @return [Hash, String]
    #   - If correctable: A Hash matching `REWRITE_RESPONSE_SCHEMA` (e.g.,
    #     `{ "general_fix_suggestions": String, "literal_rewrite": String }`).
    #   - If uncorrectable by LLM's judgment: A String starting with
    #     "This message cannot be made compliant due to:".
    #   - On client/API error: A Hash with an `"error"` key and potentially `"details"`.
    # @see #_build_rewrite_prompt For prompt construction.
    # @see #extract_text_from_gemini_candidates For initial processing of LLM output.
    # @see #_parse_rewrite_llm_output For interpreting the extracted text.
    # @see #_make_gemini_api_request for the underlying API call.
    def generate_rewrite(original_message, failure_reason, failure_confidence)
      method_name = "generate_rewrite"
      if @api_key.nil? || @api_key.empty?
        Rails.logger.error "Google::GeminiClient (#{method_name}): API key is missing."
        return { "error" => "API key missing for GeminiClient rewrite" }
      end

      prompt_text = _build_rewrite_prompt(original_message, failure_reason, failure_confidence)
      generation_endpoint = GENERATION_ENDPOINT_TEMPLATE % { model: @model_name }
      # The REWRITE_RESPONSE_SCHEMA is used to guide the LLM if it decides the message is correctable.
      # The LLM is also instructed to return a plain string if uncorrectable.
      request_body = {
        contents: [{ parts: [{ text: prompt_text }] }],
        generationConfig: {
          responseMimeType: "application/json", # Expect JSON if correctable, LLM might override with text.
          responseSchema: REWRITE_RESPONSE_SCHEMA
        }
      }

      outer_response_body = _make_gemini_api_request(generation_endpoint, request_body, method_name)
      return outer_response_body if outer_response_body.key?("error") # Error from API call itself

      raw_llm_output_text = extract_text_from_gemini_candidates(outer_response_body)

      if raw_llm_output_text.nil?
        Rails.logger.error "Google::GeminiClient (#{method_name}): No text found in Gemini response. Body: #{outer_response_body.inspect.truncate(500)}"
        return { "error" => "LLM response for rewrite missing text content", "details" => outer_response_body&.inspect&.truncate(500) }
      end

      _parse_rewrite_llm_output(raw_llm_output_text, method_name)
    end

    private

    # Constructs the prompt for the `generate_rewrite` method.
    # @private
    # @param original_message [String]
    # @param failure_reason [String]
    # @param failure_confidence [Float]
    # @return [String] The constructed prompt text.
    def _build_rewrite_prompt(original_message, failure_reason, failure_confidence)
      # Using a HEREDOC for better readability of the multi-line prompt.
      <<~PROMPT.strip
        The following SMS message was analyzed and failed a policy check:
        Original Message: "#{original_message}"
        Reason for Failure: "#{failure_reason}"
        Confidence of Failure: #{failure_confidence.round(3)}

        Your task is to provide advice.
        1. First, determine if this message can be reasonably corrected to become compliant while retaining its original intent as much as possible.
        2. If you determine the message is fundamentally uncorrectable (e.g., due to promoting illegal activities, severe hate speech that cannot be salvaged), respond ONLY with the exact phrase:
           "This message cannot be made compliant due to: [briefly explain why, e.g., its promotion of illegal content]."
           Do NOT include any other text or JSON if it's uncorrectable.
        3. If the message IS correctable, provide a JSON object conforming to the schema: #{REWRITE_RESPONSE_SCHEMA.to_json}.
           Do NOT include any text outside of the JSON object itself. The JSON should contain 'general_fix_suggestions' (string) and 'literal_rewrite' (string).
      PROMPT
    end

    # Parses the raw text output from the LLM for the rewrite generation task.
    # The output can be a string indicating uncorrectability or a JSON string with suggestions.
    # @private
    # @param raw_llm_output_text [String] The text extracted from the LLM's response.
    # @param method_name [String] Calling method context for logging.
    # @return [String, Hash] The uncorrectable message string, a hash of suggestions, or an error hash.
    def _parse_rewrite_llm_output(raw_llm_output_text, method_name)
      # Check for the specific "uncorrectable" message first.
      if raw_llm_output_text.start_with?("This message cannot be made compliant due to:")
        return raw_llm_output_text
      end

      # If not the "uncorrectable" string, attempt to parse as JSON.
      begin
        parsed_json_content = JSON.parse(raw_llm_output_text)
        # Validate against the expected structure for a correctable rewrite.
        if parsed_json_content.is_a?(Hash) && parsed_json_content.key?("general_fix_suggestions") && parsed_json_content.key?("literal_rewrite")
          return parsed_json_content
        else
          Rails.logger.warn "Google::GeminiClient (#{method_name}): Parsed JSON but missing rewrite keys. Output: #{raw_llm_output_text.truncate(500)}"
          return { "error" => "LLM rewrite response JSON missing required keys", "details" => raw_llm_output_text.truncate(500) }
        end
      rescue JSON::ParserError
        Rails.logger.warn "Google::GeminiClient (#{method_name}): Output was not the 'uncorrectable' string nor valid JSON. Output: #{raw_llm_output_text.truncate(500)}"
        return { "error" => "LLM rewrite output was not in the expected format (string or valid JSON)", "details" => raw_llm_output_text.truncate(500) }
      end
    end

    # Makes a POST request to the specified Gemini API endpoint and handles common errors.
    # @private
    # @param endpoint [String] The API endpoint path.
    # @param request_body [Hash] The body of the request.
    # @param method_name [String] The calling public method's name (for logging and error details).
    # @return [Hash] The parsed JSON response body from the API on success (outer structure), or an error hash.
    #   An error hash will contain an `"error"` key.
    def _make_gemini_api_request(endpoint, request_body, method_name)
      response = @connection.post(endpoint) do |req|
        req.params['key'] = @api_key
        req.headers['Content-Type'] = 'application/json; charset=utf-8' # Ensure UTF-8
        req.body = request_body
      end
      response.body # Faraday's :json middleware parses this outer response.
    rescue Faraday::ClientError, Faraday::ServerError, Faraday::TimeoutError, Faraday::ConnectionFailed => e
      handle_faraday_error(e, method_name)
    rescue JSON::ParserError => e # Error parsing the *outer* API response, not the nested JSON content.
      Rails.logger.error "Google::GeminiClient (#{method_name}) Outer JSON Parsing Error: #{e.message}. Body: #{e.response&.body.to_s.truncate(500)}"
      { "error" => "Gemini API outer response was not valid JSON (#{method_name})" }
    rescue StandardError => e
      Rails.logger.error "Google::GeminiClient (#{method_name}) Unexpected Error during API call: #{e.class} - #{e.message}\n#{e.backtrace.first(5).join("\n")}"
      { "error" => "Unexpected error in GeminiClient (#{method_name}): #{e.class}" }
    end

    # Processes the raw response body from a Gemini generateContent call,
    # specifically for `analyze_characteristic` where a JSON string is expected
    # within the 'text' part of the first candidate.
    #
    # @private
    # @param outer_response_body [Hash, nil] The full parsed JSON response from the Gemini API.
    #   This is the direct output from `_make_gemini_api_request` if it was successful.
    # @return [Hash] The parsed inner JSON content if successful, or an error hash.
    #   Success example: `{ "confidence_score": Float, "rationale": String }`
    #   Error example: `{ "error": String, "details": ..., "block_reason": ..., "safety_ratings": ... }`
    def process_gemini_response_content(outer_response_body)
      method_context = "process_gemini_response_content" # For logging
      candidates = outer_response_body&.dig("candidates")

      if candidates.is_a?(Array) && !candidates.empty?
        first_candidate_content = candidates.first&.dig("content")
        first_candidate_parts = first_candidate_content&.dig("parts")

        if first_candidate_parts.is_a?(Array) && !first_candidate_parts.empty?
          json_text_part = first_candidate_parts.first&.dig("text")

          if json_text_part.is_a?(String)
            begin
              # The 'text' part itself should be a JSON string here due to responseSchema.
              parsed_json_content = JSON.parse(json_text_part)
              # Validate against the expected schema keys.
              if parsed_json_content.is_a?(Hash) && parsed_json_content.key?("confidence_score") && parsed_json_content.key?("rationale")
                return parsed_json_content
              else
                Rails.logger.error "Google::GeminiClient (#{method_context}): Parsed JSON from 'text' missing required keys. Content: #{parsed_json_content.inspect.truncate(500)}"
                return { "error" => "LLM response JSON missing required keys", "details" => parsed_json_content.inspect.truncate(500) }
              end
            rescue JSON::ParserError => e
              Rails.logger.error "Google::GeminiClient (#{method_context}): Failed to parse JSON from 'text' part: #{e.message}. Content: #{json_text_part.truncate(500)}"
              return { "error" => "LLM response content was not valid JSON in 'text' part", "details" => json_text_part.truncate(500) }
            end
          else
            Rails.logger.error "Google::GeminiClient (#{method_context}): Expected 'text' part in LLM response to be a String, got #{json_text_part.class}. Parts: #{first_candidate_parts.inspect.truncate(500)}"
            return { "error" => "LLM response 'text' part was not a string" }
          end
        else
          Rails.logger.error "Google::GeminiClient (#{method_context}): 'parts' array in LLM response is missing/empty or not an array. Candidate: #{candidates.first.inspect.truncate(500)}"
          return { "error" => "LLM response 'parts' array missing, empty, or invalid" }
        end
      # Handle cases where the prompt was blocked by safety filters.
      elsif outer_response_body&.dig("promptFeedback", "blockReason").present?
        block_reason = outer_response_body.dig("promptFeedback", "blockReason")
        safety_ratings = outer_response_body.dig("promptFeedback", "safetyRatings")
        Rails.logger.warn "Google::GeminiClient (#{method_context}): Prompt blocked by API. Reason: #{block_reason}. Ratings: #{safety_ratings.inspect}"
        return { "error" => "LLM prompt blocked by API safety filters", "block_reason" => block_reason, "safety_ratings" => safety_ratings }
      else
        Rails.logger.error "Google::GeminiClient (#{method_context}): Unexpected response structure. No 'candidates' or actionable 'promptFeedback'. Body: #{outer_response_body.inspect.truncate(1000)}"
        return { "error" => "LLM response structure was unexpected (no candidates or actionable feedback)", "details" => outer_response_body&.inspect&.truncate(1000) }
      end
    end

    # Extracts the raw text string from the first candidate in a Gemini API response.
    # This text is intended for `generate_rewrite`, where it might be a JSON string
    # or a plain text "uncorrectable" message.
    # Handles cases where the prompt might be blocked, returning a specific "uncorrectable" string.
    #
    # @private
    # @param outer_response_body [Hash, nil] The full parsed JSON response from the Gemini API.
    # @return [String, nil] The extracted text content, a specific string if blocked by API, or nil if text not found.
    def extract_text_from_gemini_candidates(outer_response_body)
      method_context = "extract_text_from_gemini_candidates" # For logging
      candidates = outer_response_body&.dig("candidates")

      if candidates.is_a?(Array) && !candidates.empty?
        first_candidate_content = candidates.first&.dig("content")
        first_candidate_parts = first_candidate_content&.dig("parts")
        if first_candidate_parts.is_a?(Array) && !first_candidate_parts.empty?
          # This text part could be a JSON string (for a correctable rewrite)
          # or a plain string (if LLM directly states it's uncorrectable, though prompt guides it to use JSON or specific phrase).
          return first_candidate_parts.first&.dig("text")
        end
      # If the prompt was blocked, treat it as uncorrectable for the rewrite flow.
      elsif outer_response_body&.dig("promptFeedback", "blockReason").present?
        block_reason = outer_response_body.dig("promptFeedback", "blockReason")
        safety_ratings = outer_response_body.dig("promptFeedback", "safetyRatings") # For logging context
        Rails.logger.warn "Google::GeminiClient (#{method_context}): Prompt blocked by API. Reason: #{block_reason}. Ratings: #{safety_ratings.inspect}"
        # Return a string that aligns with the "uncorrectable" message format expected by generate_rewrite.
        return "This message cannot be made compliant due to: Content generation blocked by API safety filters (#{block_reason})."
      end

      Rails.logger.warn "Google::GeminiClient (#{method_context}): Could not extract text from candidates, and no prompt block reason found. Body: #{outer_response_body.inspect.truncate(1000)}"
      nil # Text not found
    end

    # Handles errors raised by Faraday during API communication for GeminiClient methods.
    # Logs the error and constructs a standardized error hash.
    #
    # @private
    # @param exception [Faraday::Error] The exception object raised by Faraday.
    # @param method_name [String] The name of the public method (e.g., "analyze_characteristic").
    # @return [Hash] An error hash in the format `{ "error" => String }`.
    def handle_faraday_error(exception, method_name)
      error_type_for_log = exception.class.name
      status_code = exception.response&.dig(:status)
      response_headers = exception.response&.[](:headers)
      raw_error_body = exception.response&.[](:body) # Could be string or pre-parsed hash by Faraday
      parsed_json_error_message = nil

      Rails.logger.error "Google::GeminiClient (#{method_name}) API Communication Error: #{error_type_for_log} - #{exception.message} (Status: #{status_code})"

      # Attempt to extract a specific error message from the API's JSON response body.
      if raw_error_body.is_a?(String) && !raw_error_body.empty? && is_json_response?(response_headers)
        begin
          parsed_json_body = JSON.parse(raw_error_body)
          parsed_json_error_message = parsed_json_body.dig("error", "message") if parsed_json_body.is_a?(Hash)
        rescue JSON::ParserError
          Rails.logger.warn "Google::GeminiClient (#{method_name}) Failed to parse supposed JSON error body: #{raw_error_body.truncate(200)}"
        end
      elsif raw_error_body.is_a?(Hash) # Faraday might have already parsed it
        parsed_json_error_message = raw_error_body.dig("error", "message")
      end

      returned_api_error_message = if parsed_json_error_message.present?
                                     parsed_json_error_message
                                   elsif status_code
                                     if raw_error_body.is_a?(String) && !raw_error_body.empty? && !is_json_response?(response_headers)
                                       "Gemini API Error (#{method_name}, Status: #{status_code}): #{raw_error_body.truncate(150)}"
                                     else
                                       "Gemini API Error (#{method_name}, Status: #{status_code})"
                                     end
                                   else
                                     "Gemini Network/Timeout Error (#{method_name}): #{exception.message.truncate(100)}"
                                   end

      Rails.logger.error "Google::GeminiClient (#{method_name}) Processed Error for return: #{returned_api_error_message}. Original Status: #{status_code}. Response Body (truncated): #{raw_error_body.to_s.truncate(500)}"
      { "error" => returned_api_error_message }
    end

    # Helper to determine if response headers indicate a JSON content type.
    # @private
    # @param response_headers [Hash, nil] The headers from the Faraday response.
    # @return [Boolean] True if content type appears to be JSON, false otherwise.
    def is_json_response?(response_headers)
      response_headers&.[]('content-type')&.include?('application/json') || false
    end
  end
end