# spec/clients/google/safe_browse_client_spec.rb
require 'rails_helper'
require_relative '../../../app/clients/google/safe_browse_client'

RSpec.describe Google::SafeBrowseClient do
  # --- Get the API key ONCE when the describe block is loaded ---
  # This ensures we capture it after dotenv has hopefully done its job.
  THE_VALID_API_KEY_FOR_TESTS = ENV['GOOGLE_API_KEY']

  let(:client_with_valid_key) { described_class.new(api_key: THE_VALID_API_KEY_FOR_TESTS) }
  let(:invalid_api_key) { "DEFINITELY_INVALID_API_KEY_FOR_TESTING" }
  let(:client_with_invalid_key) { described_class.new(api_key: invalid_api_key) }
  let(:client_with_nil_key) { described_class.new(api_key: nil) }

  let(:malware_url) { "http://malware.testing.google.test/testing/malware/" }
  let(:social_engineering_url) { "http://testsafeBrowse.appspot.com/s/phishing.html" }
  let(:unwanted_software_url) { "http://unwanted.testing.google.test/testing/unwanted/" }
  let(:safe_url) { "https://www.google.com" }

  # This before block is just a warning for the developer, not a test itself.
  before(:all) do
    # Print only if the constant ended up being nil/empty
    unless THE_VALID_API_KEY_FOR_TESTS && !THE_VALID_API_KEY_FOR_TESTS.empty?
      puts "\n\n[TEST SUITE WARNING] GOOGLE_API_KEY was not captured correctly at load time for SafeBrowseClient specs. It was '#{THE_VALID_API_KEY_FOR_TESTS}'. Live API tests requiring a valid key will be skipped or fail.\n\n"
    end
  end

  describe '#find_threat_matches', :live_api do
    context 'when API key is explicitly nil or empty string (handled by client before API call)' do

      it 'returns an error structure for nil API key without making an API call' do
        # Allow the initialize warning to occur without fuss
        allow(Rails.logger).to receive(:warn).with("Google::SafeBrowseClient initialized without a valid API key. Real API calls will fail or be rejected.")

        # Now specifically expect the warning from the method call
        expect(Rails.logger).to receive(:warn).with("Google::SafeBrowseClient: API key is missing. Cannot make API call.").at_least(:once)

        expect(client_with_nil_key.connection).not_to receive(:post)
        result = client_with_nil_key.find_threat_matches([safe_url])
        expect(result).to eq({ "matches" => [], "error" => "API key missing" })
      end

      it 'returns an error structure for an empty string API key without making an API call' do
        client_with_empty_key = described_class.new(api_key: "")
        expect(Rails.logger).to receive(:warn).with("Google::SafeBrowseClient: API key is missing. Cannot make API call.").at_least(:once)
        expect(client_with_empty_key.connection).not_to receive(:post)
        result = client_with_empty_key.find_threat_matches([safe_url])
        expect(result).to eq({ "matches" => [], "error" => "API key missing" })
      end
    end

    context 'when a truly invalid API key is used (testing real API error response)' do
      it 'returns a hash containing the specific API error message from Google' do
        # Allow any error logging to occur, we'll verify the returned error.
        # If you want to be strict, you can refine these logger expectations.
        allow(Rails.logger).to receive(:error) # Allow any error logs for now

        result = client_with_invalid_key.find_threat_matches([malware_url])

        expect(result).to be_a(Hash)
        expect(result["matches"]).to eq([])
        expect(result["error"]).to be_a(String)
        expect(result["error"].downcase).to include("api key not valid. please pass a valid api key.")
      end
    end

    # The following tests require a VALID API key to be set in ENV['GOOGLE_API_KEY']
    # They will be skipped if the key is not present to avoid false failures.
    describe 'with a valid API key' do
      before do
        # Use the constant captured at load time
        skip("GOOGLE_API_KEY is not properly set for these tests, skipping live API tests.") unless THE_VALID_API_KEY_FOR_TESTS && !THE_VALID_API_KEY_FOR_TESTS.empty?
      end

      context 'when checking a known malicious URL (malware)' do
        it 'returns a threat match for malware' do
          # client_with_valid_key is now used here
          result = client_with_valid_key.find_threat_matches([ malware_url ])
          expect(result["error"]).to be_nil, "Expected no error, but got: #{result['error']}. Full response: #{result.inspect}"
          expect(result["matches"]).not_to be_empty, "Expected matches for malware URL, got empty. Full response: #{result.inspect}"
          expect(result["matches"].any? { |m| m["threatType"] == "MALWARE" && m["threat"]["url"] == malware_url }).to be true
        end
      end

      context 'when checking a known malicious URL (social engineering)' do
        it 'returns a threat match for social engineering' do
          result = client_with_valid_key.find_threat_matches([ social_engineering_url ])
          expect(result["error"]).to be_nil, "Expected no error, but got: #{result['error']}. Full response: #{result.inspect}"
          expect(result["matches"]).not_to be_empty, "Expected matches for social engineering URL, got empty. Full response: #{result.inspect}"
          expect(result["matches"].any? { |m| m["threatType"] == "SOCIAL_ENGINEERING" && m["threat"]["url"] == social_engineering_url }).to be true
        end
      end

      context 'when checking a known safe URL' do
        it 'returns no matches (empty "matches" array)' do
          result = client_with_valid_key.find_threat_matches([safe_url])
          expect(result["error"]).to be_nil, "Expected no error, but got: #{result['error']}. Full response: #{result.inspect}"
          expect(result["matches"]).to be_an(Array), "Expected 'matches' to be an Array. Full response: #{result.inspect}"
          expect(result["matches"]).to be_empty, "Expected no matches for safe URL, got: #{result.inspect}"
        end
      end

      context 'when checking a mix of safe and unsafe URLs' do
        it 'returns matches only for the unsafe URLs' do
          result = client_with_valid_key.find_threat_matches([safe_url, unwanted_software_url, malware_url])
          expect(result["error"]).to be_nil, "Expected no error, but got: #{result['error']}. Full response: #{result.inspect}"
          expect(result["matches"].size).to eq(2), "Expected 2 matches, got: #{result["matches"].size}. Full response: #{result.inspect}"

          has_uws = result["matches"].any? { |m| m["threatType"] == "UNWANTED_SOFTWARE" && m["threat"]["url"] == unwanted_software_url }
          has_malware = result["matches"].any? { |m| m["threatType"] == "MALWARE" && m["threat"]["url"] == malware_url }

          expect(has_uws).to be true, "Expected UNWANTED_SOFTWARE match not found. Got: #{result.inspect}"
          expect(has_malware).to be true, "Expected MALWARE match not found. Got: #{result.inspect}"
        end
      end
    end # end 'with a valid API key'

    context 'when no URLs are provided' do
      it 'returns an empty matches structure without making an API call' do
        # This client instance would use the valid_api_key if set, or nil if not.
        # The .connection method should exist on the client.
        expect(client.connection).not_to receive(:post)

        result = client.find_threat_matches([])
        expect(result["matches"]).to be_empty
        expect(result["error"]).to be_nil # No error should be reported by the client for this case
      end
    end
  end
end
