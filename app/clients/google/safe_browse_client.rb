# app/clients/google/safe_browse_client.rb
require 'faraday'
require 'faraday_json' # Ensures Faraday::Request.json and Faraday::Response.json are available
require 'json'

# == Google Module
# Namespace for all Google API client classes.
module Google
  # == Google::SafeBrowseClient
  #
  # Client for interacting with the Google Safe Browse API (v4).
  # It allows checking a list of URLs against Google's threat lists for malware,
  # social engineering, unwanted software, and potentially harmful applications.
  #
  # === Configuration
  # Requires a Google API key, which should be set in the `GOOGLE_API_KEY`
  # environment variable or passed explicitly during initialization.
  #
  # === Error Handling
  # - Network errors, timeouts, and API-specific errors (e.g., bad requests,
  #   authentication issues) are caught.
  # - Methods return a hash. In case of an error that prevents a successful API
  #   response or if the API indicates an error, the hash will contain an `"error"`
  #   key with a descriptive message. Otherwise, it contains the API data (e.g., `"matches"`).
  # - Detailed error information is logged to `Rails.logger`.
  #
  # @example Basic Usage
  #   client = Google::SafeBrowseClient.new
  #   urls_to_check = ["http://malware.testing.google.test/testing/malware/"]
  #   response = client.find_threat_matches(urls_to_check)
  #   if response["error"]
  #     puts "Error: #{response['error']}"
  #   elsif response["matches"]&.any?
  #     puts "Threats found: #{response['matches']}"
  #   else
  #     puts "No threats found for the given URLs."
  #   end
  #
  class SafeBrowseClient
    # Base URL for the Safe Browse API.
    BASE_URL = 'https://safebrowsing.googleapis.com'
    # API version used.
    API_VERSION = 'v4'
    # API endpoint for finding threat matches.
    THREAT_MATCHES_ENDPOINT = "#{API_VERSION}/threatMatches:find"

    attr_reader :api_key, :connection

    # Initializes a new SafeBrowseClient.
    #
    # Sets up the API key and a Faraday connection instance for making API requests.
    # Default timeouts are set for the connection.
    #
    # @param api_key [String, nil] The Google API key. Defaults to `ENV['GOOGLE_API_KEY']`.
    #   A warning is logged if the API key is missing or empty at initialization.
    #   API calls will fail if the key is not valid when they are made.
    def initialize(api_key: ENV['GOOGLE_API_KEY'])
      @api_key = api_key
      if @api_key.nil? || @api_key.empty?
        # Log a warning if initialized without a key. Actual enforcement happens per-call.
        Rails.logger.warn "Google::SafeBrowseClient initialized without a valid API key. API calls will not succeed without it."
      end

      @connection = Faraday.new(url: BASE_URL) do |faraday|
        faraday.request :json # Encode request body as JSON.
        # Parse JSON responses. `symbolize_names: false` keeps string keys from Google API.
        faraday.response :json, content_type: /\bjson$/, parser_options: { symbolize_names: false }
        faraday.response :raise_error # Raise exceptions on 4xx/5xx HTTP status codes.
        faraday.adapter Faraday.default_adapter # Use the default HTTP adapter (e.g., Net::HTTP).
        faraday.options.timeout = 15      # Overall request timeout in seconds.
        faraday.options.open_timeout = 5  # Connection opening timeout in seconds.
      end
    end

    # Checks a list of URLs against Google's Safe Browse threat lists.
    #
    # Constructs a request according to the Safe Browse API v4 `threatMatches:find`
    # specification. Handles various API response scenarios and network errors.
    #
    # @param urls [Array<String>, nil] An array of URLs to check. If nil or empty,
    #   no API call is made, and a response indicating no matches is returned.
    #   URLs should be valid strings.
    # @return [Hash]
    #   - On success (even if no threats are found):
    #     `{ "matches" => Array<Hash> }` where `matches` contains details of any
    #     threats found. An empty array means no threats were identified for the given URLs.
    #   - On failure (e.g., API key missing, network error, API error response, parsing issue):
    #     `{ "matches" => [], "error" => String }` where `error` provides a
    #     description of the issue.
    # @see https://developers.google.com/safe-Browse/v4/lookup-api Official API documentation.
    def find_threat_matches(urls)
      default_success_no_match = { "matches" => [] }

      if @api_key.nil? || @api_key.empty?
        Rails.logger.warn "Google::SafeBrowseClient#find_threat_matches: API key is missing. Cannot make API call."
        return { "matches" => [], "error" => "API key missing" } # Critical: No API key.
      end

      # If urls list is nil or effectively empty, no need to call the API.
      return default_success_no_match if urls.nil? || urls.compact.map(&:to_s).reject(&:empty?).empty?

      request_body = {
        client: { clientId: "SmsPolicyCheckerApp", clientVersion: "1.0.0" }, # Identifier for the application using the API.
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: urls.map { |url_item| { url: url_item.to_s } } # Ensure URLs are strings.
        }
      }

      begin
        response = @connection.post(THREAT_MATCHES_ENDPOINT) do |req|
          req.params['key'] = @api_key
          req.body = request_body
        end
        parsed_body = response.body # Faraday's :json middleware should have parsed this.

        # Ensure a consistent structure even if API omits "matches" key on no results.
        if parsed_body.is_a?(Hash)
          parsed_body["matches"] ||= [] # Ensure "matches" key exists.
          return parsed_body
        else
          # This case implies an unexpected response format from the API despite a 2xx status.
          Rails.logger.warn "Google::SafeBrowseClient#find_threat_matches: Unexpected non-hash response body: #{parsed_body.inspect}"
          return { "matches" => [], "error" => "Unexpected response body format from SafeBrowse API" }
        end

      rescue Faraday::ClientError, Faraday::ServerError, Faraday::TimeoutError, Faraday::ConnectionFailed => e
        # Handles 4xx, 5xx errors (from :raise_error), timeouts, or connection failures.
        return handle_faraday_api_error(e)

      rescue JSON::ParserError => e
        # This implies the server sent a 2xx status but the body was not valid JSON.
        # The Faraday :json response middleware would raise this.
        Rails.logger.error "Google::SafeBrowseClient#find_threat_matches JSON Parsing Error for successful response: #{e.message}. Response body snippet: #{response&.body&.to_s&.truncate(200)}"
        return { "matches" => [], "error" => "JSON parsing error from SafeBrowse API success response" }

      rescue StandardError => e
        # Catch-all for any other unexpected errors within this method.
        Rails.logger.error "Google::SafeBrowseClient#find_threat_matches Unexpected Error: #{e.class} - #{e.message}\n#{e.backtrace.first(5).join("\n")}"
        return { "matches" => [], "error" => "Unexpected error in SafeBrowseClient: #{e.class}" }
      end
    end

    private

    # Handles errors raised by Faraday during API communication (e.g., network issues, HTTP errors).
    # It logs detailed information and constructs a standardized error hash.
    #
    # @param exception [Faraday::Error] The exception object raised by Faraday.
    # @return [Hash] An error hash in the format `{ "matches" => [], "error" => String }`.
    def handle_faraday_api_error(exception)
      error_type_for_log = exception.class.name
      status_code = exception.response&.dig(:status) # HTTP status code if available (for Faraday::ClientError/ServerError)
      raw_error_body_string = exception.response&.[](:body) # Raw response body string or hash
      parsed_error_body = nil

      log_prefix = "Google::SafeBrowseClient#find_threat_matches Faraday API Error:"
      Rails.logger.error "#{log_prefix} #{error_type_for_log} - #{exception.message} (Status: #{status_code.inspect})"

      # Attempt to parse the error body if it's a string that looks like JSON
      if raw_error_body_string.is_a?(String) && !raw_error_body_string.empty?
        begin
          parsed_error_body = JSON.parse(raw_error_body_string)
        rescue JSON::ParserError
          # Not JSON, or malformed; parsed_error_body remains nil
        end
      elsif raw_error_body_string.is_a?(Hash) # If Faraday already parsed it (e.g., error with JSON content type)
        parsed_error_body = raw_error_body_string
      end

      # Determine the most specific error message for the returned hash
      returned_api_error_message = if parsed_error_body.is_a?(Hash) && parsed_error_body.dig("error", "message")
                                     # Prefer the specific error message from the API response body
                                     parsed_error_body.dig("error", "message")
                                   elsif status_code
                                     # Generic message based on HTTP status if no specific message found in body
                                     "SafeBrowse API Error (Status: #{status_code})"
                                   elsif raw_error_body_string.is_a?(String) && !raw_error_body_string.empty? && parsed_error_body.nil?
                                     # If body is a non-JSON string (e.g., HTML error page, plain text proxy error)
                                     "SafeBrowse API returned non-JSON error (Status: #{status_code || 'N/A'}): #{raw_error_body_string.truncate(150)}"
                                   else
                                     # Fallback for network errors or timeouts where no body/status might be present
                                     "SafeBrowse Network/Timeout Error: #{exception.message.truncate(100)}"
                                   end

      Rails.logger.error "#{log_prefix} Processed Error for return: '#{returned_api_error_message}'. Original Status: #{status_code.inspect}. Response Body: #{raw_error_body_string.inspect.truncate(500)}"
      { "matches" => [], "error" => returned_api_error_message }
    end
  end
end
