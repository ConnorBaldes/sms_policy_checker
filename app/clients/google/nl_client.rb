# app/clients/google/nl_client.rb
require 'faraday'
require 'faraday_json' # Ensures Faraday::Request::Json is available
require 'json'

module Google
  # == Google::NlClient
  #
  # Client for interacting with the Google Natural Language API (v2).
  # It provides methods to:
  #   - Analyze entities in text (`analyze_entities`).
  #   - Moderate text content for harmful categories (`moderate_text`).
  #
  # === Configuration
  # Requires a Google API key, which should be set in the `GOOGLE_API_KEY`
  # environment variable or passed explicitly during initialization.
  #
  # === Error Handling
  # - Network errors, timeouts, and API-specific errors are caught.
  # - Methods return a hash. In case of an error, the hash will contain an `"error"`
  #   key with a descriptive message, along with default values for other expected keys
  #   (e.g., "entities", "moderationCategories", "languageCode", "languageSupported").
  # - Detailed error information is logged to `Rails.logger`.
  #
  # @example
  #   client = Google::NlClient.new
  #   entities_response = client.analyze_entities("Google is a company based in Mountain View.")
  #   if entities_response["error"]
  #     puts "Entities Error: #{entities_response['error']}"
  #   else
  #     puts "Entities: #{entities_response['entities']}"
  #     puts "Language: #{entities_response['languageCode']}"
  #   end
  #
  #   moderation_response = client.moderate_text("This is some sample text to moderate.")
  #   if moderation_response["error"]
  #     puts "Moderation Error: #{moderation_response['error']}"
  #   else
  #     puts "Moderation Categories: #{moderation_response['moderationCategories']}"
  #   end
  #
  class NlClient
    # Base URL for the Google Natural Language API.
    BASE_URL = 'https://language.googleapis.com'
    # API version used.
    API_VERSION = 'v2'
    # API endpoint for analyzing entities.
    ANALYZE_ENTITIES_ENDPOINT = "#{API_VERSION}/documents:analyzeEntities"
    # API endpoint for moderating text.
    MODERATE_TEXT_ENDPOINT = "#{API_VERSION}/documents:moderateText"

    attr_reader :api_key, :connection

    # Initializes a new NlClient.
    #
    # Sets up the API key and a Faraday connection instance for making API requests.
    # Default timeouts are set for the connection.
    #
    # @param api_key [String, nil] The Google API key. Defaults to `ENV['GOOGLE_API_KEY']`.
    #   A warning is logged if the API key is missing or empty at initialization.
    def initialize(api_key: ENV['GOOGLE_API_KEY'])
      @api_key = api_key
      if @api_key.nil? || @api_key.empty?
        Rails.logger.warn "Google::NlClient initialized without a valid API key. API calls will fail without it."
      end

      @connection = Faraday.new(url: BASE_URL) do |faraday|
        faraday.request :json # Encode request body as JSON.
        # Parse JSON responses; symbolize_names: false to keep string keys from Google API.
        faraday.response :json, content_type: /\bjson$/, parser_options: { symbolize_names: false }
        faraday.response :raise_error # Raise exceptions on 4xx/5xx HTTP responses.
        faraday.adapter Faraday.default_adapter # Use the default HTTP adapter.
        # NL API can sometimes be slower, especially for larger texts or complex analysis.
        faraday.options.timeout = 30      # Overall request timeout in seconds.
        faraday.options.open_timeout = 10 # Connection opening timeout in seconds.
      end
    end

    # Analyzes entities in the provided text content.
    #
    # @param text_content [String, nil] The plain text to analyze.
    #   If nil or empty/whitespace-only, no API call is made and a default empty response is returned.
    # @param encoding_type [String] The encoding type of the text. Defaults to "UTF8".
    #   Other possible values include "UTF16", "UTF32".
    # @return [Hash]
    #   - On success:
    #     `{ "entities" => Array<Hash>, "languageCode" => String, "languageSupported" => Boolean, ... }`
    #     (other top-level keys from API response may be present).
    #     `"entities"` lists the recognized entities.
    #     `"languageCode"` is the detected language (e.g., "en", "und" if undetermined).
    #     `"languageSupported"` indicates if the detected language is officially supported for entity analysis.
    #   - On failure (e.g., API key missing, network error, API error, malformed success response):
    #     `{ "entities" => [], "error" => String, "languageCode" => "und", "languageSupported" => false }`
    #     The `"details"` key may be present in the error hash if the API returned an unexpected body
    #     for an otherwise successful (2xx) HTTP request.
    # @see https://cloud.google.com/natural-language/docs/reference/rest/v2/documents/analyzeEntities
    def analyze_entities(text_content, encoding_type: "UTF8")
      method_name = "analyzeEntities"
      data_key = "entities"
      default_data_structure = { data_key => [], "languageCode" => "und", "languageSupported" => false }

      if @api_key.nil? || @api_key.empty?
        Rails.logger.warn "Google::NlClient (#{method_name}): API key is missing."
        return { **default_data_structure, "error" => "API key missing for NlClient" }
      end

      text_content_str = text_content.to_s
      return default_data_structure if text_content_str.strip.empty?

      request_body = {
        document: { type: "PLAIN_TEXT", content: text_content_str },
        encodingType: encoding_type
      }

      api_response_body = _make_api_post_request(ANALYZE_ENTITIES_ENDPOINT, request_body, method_name)

      # Check if _make_api_post_request returned an error structure
      return api_response_body if api_response_body.is_a?(Hash) && api_response_body["error"]

      # Process successful response
      if api_response_body.is_a?(Hash) && api_response_body.key?(data_key)
        # Ensure consistent structure for success response
        api_response_body["languageCode"] ||= "und"
        api_response_body["languageSupported"] = api_response_body.fetch("languageSupported", false)
        api_response_body[data_key] ||= []
        api_response_body
      elsif api_response_body.is_a?(Hash) # Successful HTTP status but missing primary data key
        Rails.logger.warn "Google::NlClient (#{method_name}): Response missing '#{data_key}' key: #{api_response_body.inspect.truncate(500)}"
        {
          **default_data_structure,
          "error" => "Response from NL API (#{method_name}) missing '#{data_key}' key",
          "details" => api_response_body, # Include the problematic body
          "languageCode" => api_response_body.dig("languageCode") || "und", # Attempt to salvage language info
          "languageSupported" => api_response_body.fetch("languageSupported", false)
        }
      else # Successful HTTP status but unexpected body format (not a hash)
        Rails.logger.warn "Google::NlClient (#{method_name}): Unexpected non-hash response: #{api_response_body.inspect.truncate(500)}"
        { **default_data_structure, "error" => "Unexpected response format from NL API (#{method_name})" }
      end
    end

    # Moderates text content for harmful categories.
    #
    # @param text_content [String, nil] The plain text to moderate.
    #   If nil or empty/whitespace-only, no API call is made and a default empty response is returned.
    # @param model_version [String] The version of the moderation model to use.
    #   Defaults to "MODEL_VERSION_2". Other options like "MODEL_VERSION_UNSPECIFIED",
    #   "MODEL_VERSION_1" may be available.
    # @return [Hash]
    #   - On success:
    #     `{ "moderationCategories" => Array<Hash>, "languageCode" => String, "languageSupported" => Boolean, ... }`
    #     `"moderationCategories"` lists categories with confidence scores.
    #   - On failure:
    #     `{ "moderationCategories" => [], "error" => String, "languageCode" => "und", "languageSupported" => false }`
    #     The `"details"` key may be present if the API returned an unexpected body.
    # @see https://cloud.google.com/natural-language/docs/reference/rest/v2/documents/moderateText
    def moderate_text(text_content, model_version: "MODEL_VERSION_2")
      method_name = "moderateText"
      data_key = "moderationCategories"
      default_data_structure = { data_key => [], "languageCode" => "und", "languageSupported" => false }

      if @api_key.nil? || @api_key.empty?
        Rails.logger.warn "Google::NlClient (#{method_name}): API key is missing."
        return { **default_data_structure, "error" => "API key missing for NlClient" }
      end

      text_content_str = text_content.to_s
      return default_data_structure if text_content_str.strip.empty?

      request_body = {
        document: { type: "PLAIN_TEXT", content: text_content_str },
        modelVersion: model_version
      }

      api_response_body = _make_api_post_request(MODERATE_TEXT_ENDPOINT, request_body, method_name)

      return api_response_body if api_response_body.is_a?(Hash) && api_response_body["error"]

      if api_response_body.is_a?(Hash) && api_response_body.key?(data_key)
        api_response_body["languageCode"] ||= "und"
        api_response_body["languageSupported"] = api_response_body.fetch("languageSupported", false)
        api_response_body[data_key] ||= []
        api_response_body
      elsif api_response_body.is_a?(Hash) # Successful HTTP status but missing primary data key
        Rails.logger.warn "Google::NlClient (#{method_name}): Response missing '#{data_key}' key: #{api_response_body.inspect.truncate(500)}"
        {
          **default_data_structure,
          "error" => "Response from NL API (#{method_name}) missing '#{data_key}' key",
          "details" => api_response_body,
          "languageCode" => api_response_body.dig("languageCode") || "und",
          "languageSupported" => api_response_body.fetch("languageSupported", false)
        }
      else # Successful HTTP status but unexpected body format (not a hash)
        Rails.logger.warn "Google::NlClient (#{method_name}): Unexpected non-hash response: #{api_response_body.inspect.truncate(500)}"
        { **default_data_structure, "error" => "Unexpected response format from NL API (#{method_name})" }
      end
    end

    private

    # Makes a POST request to the specified NL API endpoint and handles common exceptions.
    #
    # @private
    # @param endpoint [String] The API endpoint path (e.g., ANALYZE_ENTITIES_ENDPOINT).
    # @param request_body [Hash] The body of the request.
    # @param method_name [String] The calling public method's name (for logging and error context).
    # @return [Hash, Array] The parsed JSON response body from the API on success,
    #   or an error hash (containing an "error" key) on failure.
    def _make_api_post_request(endpoint, request_body, method_name)
      response = @connection.post(endpoint) do |req|
        req.params['key'] = @api_key
        # Explicitly set Content-Type with charset, as recommended by Google NL API docs.
        req.headers['Content-Type'] = 'application/json; charset=utf-8'
        req.body = request_body
      end
      response.body # Faraday's :json middleware should have parsed this.
    rescue Faraday::ClientError, Faraday::ServerError, Faraday::TimeoutError, Faraday::ConnectionFailed => e
      handle_faraday_error(e, method_name)
    rescue JSON::ParserError => e
      # This occurs if the API returns a 2xx (Faraday doesn't raise_error) but with malformed JSON.
      Rails.logger.error "Google::NlClient (#{method_name}) JSON Parsing Error for successful response: #{e.message}. Body: #{e.response&.body.to_s.truncate(500)}"
      data_key = method_name == "analyzeEntities" ? "entities" : "moderationCategories"
      { data_key => [], "error" => "JSON parsing error from NL API (#{method_name}) success response", "languageCode" => "und", "languageSupported" => false }
    rescue StandardError => e
      Rails.logger.error "Google::NlClient (#{method_name}) Unexpected Error during API call: #{e.class} - #{e.message}\n#{e.backtrace.first(5).join("\n")}"
      data_key = method_name == "analyzeEntities" ? "entities" : "moderationCategories"
      { data_key => [], "error" => "Unexpected NlClient error during API call (#{method_name}): #{e.class}", "languageCode" => "und", "languageSupported" => false }
    end

    # Handles errors raised by Faraday during API communication for NLClient methods.
    # Logs the error and constructs a standardized error hash.
    #
    # @private
    # @param exception [Faraday::Error] The exception object raised by Faraday.
    # @param method_name [String] The name of the public method that was called.
    # @return [Hash] An error hash with default values for data keys, language info, and an `error` message.
    def handle_faraday_error(exception, method_name)
      error_type_for_log = exception.class.name
      status_code = exception.response&.dig(:status)
      raw_error_body = exception.response&.[](:body)
      response_headers = exception.response&.[](:headers)
      parsed_json_error_message = nil

      Rails.logger.error "Google::NlClient (#{method_name}) API Communication Error: #{error_type_for_log} - #{exception.message} (Status: #{status_code})"

      # Attempt to parse a JSON error message from the body if present.
      if raw_error_body.is_a?(String) && !raw_error_body.empty? && is_json_response?(response_headers)
        begin
          parsed_json = JSON.parse(raw_error_body)
          parsed_json_error_message = parsed_json.dig("error", "message") if parsed_json.is_a?(Hash)
        rescue JSON::ParserError
          # Body claimed to be JSON but wasn't parsable. Will be handled below.
        end
      elsif raw_error_body.is_a?(Hash) # Faraday might have already parsed it.
        parsed_json_error_message = raw_error_body.dig("error", "message")
      end

      returned_error_message = if parsed_json_error_message.present?
                                 parsed_json_error_message # Prefer specific message from API JSON error.
                               elsif status_code && raw_error_body.is_a?(String) && !raw_error_body.empty? && !is_json_response?(response_headers)
                                 # Non-JSON error body (e.g., HTML from a proxy, plain text).
                                 "NL API Error (#{method_name}, Status: #{status_code}): #{raw_error_body.truncate(150)}"
                               elsif status_code # Generic for HTTP errors if no more specific body message.
                                 "NL API Error (#{method_name}, Status: #{status_code})"
                               else # Fallback for network errors or timeouts.
                                 "NL Network/Timeout Error (#{method_name}): #{exception.message.truncate(100)}"
                               end

      Rails.logger.error "Google::NlClient (#{method_name}) Processed Error for return: #{returned_error_message}. Original Status: #{status_code}. Body (truncated): #{raw_error_body.to_s.truncate(500)}"

      data_key = method_name == "analyzeEntities" ? "entities" : "moderationCategories"
      { data_key => [], "error" => returned_error_message, "languageCode" => "und", "languageSupported" => false }
    end

    # Checks if the response headers indicate a JSON content type.
    # @private
    # @param response_headers [Hash, nil] The headers from the Faraday response.
    # @return [Boolean] True if content type appears to be JSON, false otherwise.
    def is_json_response?(response_headers)
      return false unless response_headers.is_a?(Hash)
      content_type = response_headers['content-type'] || response_headers['Content-Type']
      content_type.is_a?(String) && content_type.include?('application/json')
    end
  end
end