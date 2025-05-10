# frozen_string_literal: true

require 'rails_helper' # Or 'spec_helper'
# require_relative '../../../app/clients/google/safe_browse_client'

RSpec.describe Google::SafeBrowseClient do
  let(:api_key) { 'test_safebrowse_api_key' }
  let(:client) { described_class.new(api_key: api_key) }
  let(:base_url) { "https://safeBrowse.googleapis.com/v4" }
  let(:threat_matches_endpoint) { "#{base_url}/threatMatches:find" }

  describe '#find_threat_matches' do
    let(:urls_to_check) { ["http://example.com/bad", "http://example.org/alsobad"] }
    let(:client_info) { { clientId: "your-company-name", clientVersion: "1.0.0" } } # From client skeleton
    let(:threat_types) { ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"] }
    let(:platform_types) { ["ANY_PLATFORM"] }
    let(:threat_entry_types) { ["URL"] }

    let(:expected_request_body) do
      {
        client: client_info,
        threatInfo: {
          threatTypes: threat_types,
          platformTypes: platform_types,
          threatEntryTypes: threat_entry_types,
          threatEntries: urls_to_check.map { |url| { url: url } }
        }
      }.to_json
    end

    let(:mock_api_response_with_matches) do
      {
        "matches" => [
          { "threatType" => "SOCIAL_ENGINEERING", "platformType" => "ANY_PLATFORM", "threat" => { "url" => urls_to_check.first } },
          { "threatType" => "MALWARE", "platformType" => "WINDOWS", "threat" => { "url" => urls_to_check.last } }
        ]
      }
    end
    let(:mock_api_response_no_matches) { {} } # Empty object for no matches as per API docs

    context 'when the API call is successful and finds matches' do
      before do
        stub_request(:post, threat_matches_endpoint)
          .with(query: { key: api_key }, body: expected_request_body)
          .to_return(status: 200, body: mock_api_response_with_matches.to_json, headers: { 'Content-Type' => 'application/json' })
      end

      it 'makes a POST request to the Safe Browse API with correct parameters' do
        pending "Implementation of client logic needed"
        # client.find_threat_matches(urls_to_check)
        # expect(a_request(:post, threat_matches_endpoint)
        #   .with(query: { key: api_key }, body: expected_request_body))
        #   .to have_been_made.once
        raise NotImplementedError
      end

      it 'returns the parsed matches' do
        pending "Implementation of client logic and response parsing needed"
        # result = client.find_threat_matches(urls_to_check)
        # expect(result).to eq(mock_api_response_with_matches)
        raise NotImplementedError
      end
    end

    context 'when the API call is successful and finds no matches' do
      before do
        stub_request(:post, threat_matches_endpoint)
          .with(query: { key: api_key }, body: expected_request_body)
          .to_return(status: 200, body: mock_api_response_no_matches.to_json, headers: { 'Content-Type' => 'application/json' })
      end

      it 'returns an empty hash or structure indicating no matches' do
        pending "Implementation of client logic needed"
        # result = client.find_threat_matches(urls_to_check)
        # expect(result).to eq(mock_api_response_no_matches) # Or specifically check for empty `matches` array if client normalizes
        raise NotImplementedError
      end
    end


    context 'when the list of URLs is empty' do
      it 'returns an empty hash without making an API call' do
        pending "Implementation of client pre-check needed"
        # expect(client.find_threat_matches([])).to eq({})
        # expect(a_request(:post, threat_matches_endpoint)).not_to have_been_made
        raise NotImplementedError
      end
    end

    context 'when the API returns an error' do
      before do
        stub_request(:post, threat_matches_endpoint)
          .with(query: { key: api_key }, body: expected_request_body)
          .to_return(status: 500, body: { error: { message: "Server error" } }.to_json, headers: { 'Content-Type' => 'application/json' })
      end

      it 'raises a StandardError (or custom error)' do
        pending "Implementation of client error handling needed"
        # expect { client.find_threat_matches(urls_to_check) }.to raise_error(StandardError, /API Error: 500 Internal Server Error/)
        raise NotImplementedError
      end
    end
  end
end
