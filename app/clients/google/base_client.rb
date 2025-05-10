# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'

module Google
  # == Google::BaseClient
  #
  # Optional base class for Google API clients, handling common logic
  # like making HTTP requests, basic error handling, and authentication.
  #
  # Subclasses would implement specific API endpoint logic.
  #
  class BaseClient
    # @return [String] The API key for authentication.
    attr_reader :api_key

    # @return [String] The base URL for the Google API service.
    attr_reader :base_url

    # Initializes a new base client.
    #
    # @param api_key [String] The API key.
    # @param base_url [String] The base URL for the specific Google service.
    def initialize(api_key:, base_url:)
      @api_key = api_key
      @base_url = base_url
      # TODO: More sophisticated auth (OAuth2, service accounts) might be needed
      # For now, simple API key usage is assumed for some Google APIs.
    end

    protected

    # Makes an HTTP POST request.
    #
    # @param endpoint [String] The API endpoint path (e.g., '/v1/analyzeText').
    # @param body [Hash] The request body to be sent as JSON.
    # @return [Hash] The parsed JSON response.
    # @raise [StandardError] on HTTP errors or if response is not successful.
    def post(endpoint, body)
      uri = URI.join(@base_url, endpoint)
      uri.query = URI.encode_www_form({ key: @api_key }) if @api_key # Append API key if present

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      # TODO: Configure timeouts (open_timeout, read_timeout)

      request = Net::HTTP::Post.new(uri.request_uri)
      request['Content-Type'] = 'application/json'
      request.body = body.to_json

      response = http.request(request)

      handle_response(response)
    end

    # Makes an HTTP GET request.
    #
    # @param endpoint [String] The API endpoint path.
    # @param params [Hash] Query parameters.
    # @return [Hash] The parsed JSON response.
    # @raise [StandardError] on HTTP errors or if response is not successful.
    def get(endpoint, params = {})
      uri = URI.join(@base_url, endpoint)
      query_params = params
      query_params[:key] = @api_key if @api_key # Append API key
      uri.query = URI.encode_www_form(query_params) unless query_params.empty?


      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')

      request = Net::HTTP::Get.new(uri.request_uri)
      request['Accept'] = 'application/json'

      response = http.request(request)
      handle_response(response)
    end


    # Handles the HTTP response, parsing JSON and checking for errors.
    #
    # @param response [Net::HTTPResponse] The HTTP response object.
    # @return [Hash] The parsed JSON body if successful.
    # @raise [StandardError] if the response indicates an error.
    def handle_response(response)
      case response
      when Net::HTTPSuccess
        begin
          JSON.parse(response.body) if response.body && !response.body.empty?
        rescue JSON::ParserError => e
          raise "API Error: Failed to parse JSON response. Body: #{response.body}. Error: #{e.message}"
        end
      else
        # TODO: More specific error handling for 4xx/5xx errors.
        # Could raise custom error classes (e.g., Google::ApiError::AuthenticationError)
        raise "API Error: #{response.code} #{response.message}. Body: #{response.body}"
      end
    end
  end
end
