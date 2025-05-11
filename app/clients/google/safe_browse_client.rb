# app/clients/google/safe_browse_client.rb
require 'faraday'
require 'faraday_json' # For JSON request/response processing
require 'json'         # For constructing request body if needed, though faraday_json handles much of it

module Google
  class SafeBrowseClient
    BASE_URL = 'https://safebrowsing.googleapis.com'
    API_VERSION = 'v4'
    THREAT_MATCHES_ENDPOINT = "#{API_VERSION}/threatMatches:find"

    attr_reader :api_key, :connection

    def initialize(api_key: ENV["GOOGLE_API_KEY"])
      @api_key = api_key

      unless @api_key && !@api_key.empty?
        Rails.logger.warn "Google::SafeBrowseClient initialized without a valid API key. Real API calls will fail or be rejected."
      end
      @connection = Faraday.new(url: BASE_URL) do |faraday|
        faraday.request :json # Encodes request body as JSON
        # Parses JSON response body. Keeps keys as strings.
        faraday.response :json, content_type: /\bjson$/, parser_options: { symbolize_names: false }
        # IMPORTANT: This middleware will raise exceptions for 4xx/5xx responses
        faraday.response :raise_error
        faraday.adapter Faraday.default_adapter # Uses Net::HTTP by default
      end
    end

    def find_threat_matches(urls)
      default_success_no_match = { "matches" => [] }

      unless @api_key && !@api_key.empty?
        Rails.logger.warn "Google::SafeBrowseClient: API key is missing. Cannot make API call."
        # This matches the test expectation of returning a hash, not raising an error here.
        return { "matches" => [], "error" => "API key missing" }
      end

      return default_success_no_match if urls.nil? || urls.empty?

      request_body = {
        client: { clientId: "SmsPolicyCheckerApp", clientVersion: "1.0.0" }, # Use your app's name
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: urls.map { |url_item| { url: url_item.to_s } } # Ensure url_item is a string
        }
      }

      begin
        # This is where Faraday::ClientError would be raised by the :raise_error middleware
        # if the API returns a 4xx error (like 400 or 403 for a bad/invalid key).
        response = @connection.post(THREAT_MATCHES_ENDPOINT) do |req|
          req.params['key'] = @api_key # The API key goes in the query parameters
          req.body = request_body
        end

        parsed_body = response.body

        if parsed_body.is_a?(Hash)
          parsed_body["matches"] ||= [] # Ensure "matches" key exists, defaulting to an empty array
          return parsed_body
        else
          Rails.logger.warn "Google::SafeBrowseClient: Unexpected non-hash response body: #{parsed_body.inspect}"
          return { "matches" => [], "error" => "Unexpected response body format from API" }
        end


      rescue Faraday::ClientError, Faraday::ServerError => e
      initial_faraday_error_message = "Google::SafeBrowseClient Raw Faraday Error: #{e.class} - #{e.message} (Status: #{e.response&.dig(:status)})"
      Rails.logger.error initial_faraday_error_message

      raw_error_body_string = e.response&.[](:body) # This is the string
      parsed_error_body = nil
      returned_api_error_message = "API Error (Status: #{e.response&.dig(:status)})" # Default

      if raw_error_body_string.is_a?(String) && !raw_error_body_string.empty?
        begin
          parsed_error_body = JSON.parse(raw_error_body_string)
        rescue JSON::ParserError
          Rails.logger.warn "Google::SafeBrowseClient: Could not parse error response body as JSON: #{raw_error_body_string.truncate(100)}"
          returned_api_error_message = raw_error_body_string.truncate(200) # Use raw string if not JSON
        end
      end

      # Now check the parsed_error_body
      if parsed_error_body.is_a?(Hash)
        google_error_details = parsed_error_body["error"]
        if google_error_details.is_a?(Hash) && google_error_details["message"]
          returned_api_error_message = google_error_details["message"]
        # If not the expected Google structure, but still a parsed hash, maybe log it differently or use a generic message
        elsif !parsed_error_body.empty? && returned_api_error_message == "API Error (Status: #{e.response&.dig(:status)})" # only if not already set by JSON parse fail
          returned_api_error_message = "API Error: #{parsed_error_body.to_s.truncate(100)}"
        end
      # elsif raw_error_body_string already handled the case where it's a string and not parsable
      end

      Rails.logger.error "Google::SafeBrowseClient Processed Error for return: #{returned_api_error_message}. Original Status: #{e.response&.dig(:status)}."
      return { "matches" => [], "error" => returned_api_error_message }

      rescue JSON::ParserError => e
        Rails.logger.error "Google::SafeBrowseClient JSON Parsing Error: #{e.message}"
        return { "matches" => [], "error" => "JSON parsing error from API response" }

      rescue StandardError => e # Catch any other unexpected errors during the process
        Rails.logger.error "Google::SafeBrowseClient Unexpected Error: #{e.class} - #{e.message}\n#{e.backtrace.first(5).join("\n")}"
        return { "matches" => [], "error" => "Unexpected client error: #{e.class}" }
      end
    end
  end
end
