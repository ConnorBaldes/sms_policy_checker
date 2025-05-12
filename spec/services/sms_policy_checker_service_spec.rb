# spec/services/sms_policy_checker_service_spec.rb
require 'rails_helper' # Loads Rails environment, including initializers

# == SmsPolicyCheckerService RSpec Tests
#
# These tests are designed to be "live" tests, meaning they will interact
# with actual Google APIs (Safe Browse, Natural Language, Gemini) using the
# configurations defined in your project (L1 rules, LLM prompts, thresholds).
#
# === Prerequisites for Running Live Tests:
# 1.  **API Key**:
#     - The `GOOGLE_API_KEY` environment variable MUST be set with a valid Google Cloud API key
#       that has Safe Browse, Natural Language, and Generative Language (Gemini) APIs enabled.
#     - If not set, these live tests will be skipped.
# 2.  **Configuration Files**:
#     - `config/sms_policy_checker_rules.yml`
#     - `config/sms_policy_checker_llm_config.yml`
#     - `config/sms_policy_checker_thresholds.yml`
#     These files must be present and correctly configured as per your project's requirements.
#     The application initializer (`config/initializers/sms_policy_checker_config.rb`)
#     is expected to load these into `SmsPolicyCheckerService` constants.
# 3.  **Internet Connection**: Required for all API calls.
# 4.  **Potential Costs and Rate Limits**:
#     - Live API calls WILL incur costs on your Google Cloud account.
#     - API calls are subject to rate limits. Frequent execution might lead to temporary blocks.
#     - Run these tests judiciously, especially in CI environments. Consider tagging them
#       (e.g., `:live_api`) for selective execution.
# 5.  **Non-Determinism of LLM Responses**:
#     - LLM-generated confidence scores, rationales, and rewrite suggestions can vary.
#     - Tests focus on:
#       - Plausible outcomes (pass/fail based on strong signals).
#       - Presence, type, and general structure of report components.
#       - Correct Layer 1 rule identification.
#     - Assertions on exact LLM-generated text or precise scores are generally avoided
#       or made flexible (e.g., checking ranges, presence rather than equality).
#
# === Important Note on Test Data & L1 Rules:
# -   For these tests to be effective, your actual `config/sms_policy_checker_rules.yml`
#     MUST define these rules with patterns that reliably trigger the intended violations.
#     For example, "EXAMPLE_SEVERE_SLUR" should be a string that your L1 rule for severe
#     hate speech is designed to catch.
# -   Adjust message content in tests or rule definitions in your YAML files as needed
#     to ensure correct interactions and triggers based on your specific rule patterns
#     and LLM prompts.
#
RSpec.describe SmsPolicyCheckerService, type: :service do
  # Determine if live API tests should be skipped
  # Convert to boolean strictly to satisfy RSpec's conditional `if:`
  skip_live_api_tests = !(ENV['GOOGLE_API_KEY'].present? && ENV['GOOGLE_API_KEY'] != "your_actual_google_api_key_for_testing")

  # Guard message if tests are skipped
  if skip_live_api_tests
    RSpec.configuration.reporter.message "\nINFO: GOOGLE_API_KEY not set or is placeholder. Skipping SmsPolicyCheckerService live API tests."
  end

  # This before(:all) block runs once before any tests in this describe block.
  # It checks if the critical configurations have been loaded by the initializer.
  before(:all) do
    # These checks ensure the initializer has run and set up the service correctly.
    # If these constants are not defined, the tests cannot meaningfully run.
    %w[LAYER1_RULES LLM_CONFIG THRESHOLDS CRITICAL_FAILURE_THRESHOLDS].each do |const_name|
      unless SmsPolicyCheckerService.const_defined?(const_name)
        raise NameError, "SmsPolicyCheckerService constant `#{const_name}` is not defined. " \
                         "Please ensure `config/initializers/sms_policy_checker_config.rb` " \
                         "has run successfully and loaded all configurations."
      end
    end
  end

  # Helper lambda to call the service with a message
  let(:call_service) { ->(message_body) { described_class.call(message_body) } }

  # Group tests that require live API interaction
  context "when GOOGLE_API_KEY is available (Live API Tests)", if: !skip_live_api_tests do
    describe ".call with various message types" do
      context "with a clearly compliant message" do
        let(:message) { "Hello, just wanted to follow up on our meeting from yesterday. Let me know if you have any questions. Thanks!" }

        it "returns a :pass result with 'Compliant' reason and no violation details" do
          report = call_service.call(message)
          expect(report[:result]).to eq(:pass), "Report: #{report.inspect}"
          expect(report[:reason]).to eq("Compliant")
          expect(report[:confidence]).to be_a(Float) # Actual value depends on processing
          # expect(report[:violation_details]).to be_empty # Gemini will return violation details even if the message is deemed compliant.
          # expect(report[:policy_category_scores]).to be_empty # Gemini will return policy categories even if the message is deemed compliant.
          expect(report[:processing_mode]).to eq(:full_analysis)
        end
      end

      context "with a Layer 1 early-exit violation (URL Shortener)" do
        # Assumes "L1_PUBLIC_URL_SHORTENER_SEVERE" rule exists in config:
        # type: "regex"
        # patterns: [ '(?:https?:\/\/)?(?:www\.)?(bit\.ly|tinyurl\.com|...)\/[a-zA-Z0-9\-_.~]+' ]
        # mapped_policy_category: "ProhibitedPublicURLShorteners"
        # individual_confidence: 1.0
        # is_early_exit_rule: true
        # early_exit_threshold: 1.0
        let(:message) { "Urgent update! Check this out: http://bit.ly/totallyLegitLink123" }

        it "returns a :fail result due to L1 early exit for URL shortener" do
          report = call_service.call(message)
          expect(report[:result]).to eq(:fail), "Report: #{report.inspect}"
          expect(report[:reason]).to eq("Early Exit - Violation Category: ProhibitedPublicURLShorteners")
          expect(report[:confidence]).to eq(1.0) # Based on typical L1 early exit confidence

          detail = report[:violation_details].find { |vd| vd[:filter_type] == "L1_PUBLIC_URL_SHORTENER_SEVERE" }
          expect(detail).not_to be_nil
          expect(detail[:layer]).to eq(1)
          expect(detail[:policy_category]).to eq("ProhibitedPublicURLShorteners")
          expect(detail[:matched_value]).to include("bit.ly/totallyLegitLink123")
          expect(report[:processing_mode]).to eq(:full_analysis) # Early exit happens within full_analysis
        end
      end

      context "with a Layer 1 violation for Hateful Content (Severe Slur)" do
        # Assumes "L1_HATE_SPEECH_SEVERE_SLURS" rule exists in config:
        # patterns: includes severe slurs
        # mapped_policy_category: "HatefulContent"
        # individual_confidence: 1.0
        # is_early_exit_rule: true
        # early_exit_threshold: 1.0
        let(:message) { "This is an awful message containing 'white power now' and other bad words." }

        it "returns a :fail result due to L1 Hateful Content early exit" do
          report = call_service.call(message)
          expect(report[:result]).to eq(:fail), "Report: #{report.inspect}"
          expect(report[:reason]).to eq("Early Exit - Violation Category: HatefulContent")
          expect(report[:confidence]).to eq(1.0)

          detail = report[:violation_details].find { |vd| vd[:filter_type] == "L1_HATE_SPEECH_SEVERE_SLURS" }
          expect(detail).not_to be_nil
          expect(detail[:policy_category]).to eq("HatefulContent")
          expect(detail[:matched_value]).to eq("white power now") # Assumes keyword type and exact match
        end
      end

      context "with a Layer 1 non-early-exit violation (False Prize) leading to failure" do
        # Assumes "L1_FALSE_PRIZE_WINNING_HIGH_CONF" rule:
        # patterns: includes "you have won a million dollars click here"
        # mapped_policy_category: "FalseOrInaccurateContent"
        # individual_confidence: 0.90 (or high enough to cross FINAL_THRESHOLD_FLAG)
        # is_early_exit_rule: false
        # And FINAL_THRESHOLD_FLAG is <= 0.90
        let(:message) { "Congratulations! you have won a million dollars click here to claim your fortune now!" }

        it "returns a :fail result due to high L1 score exceeding threshold" do
          report = call_service.call(message)
          expect(report[:result]).to eq(:fail), "Report: #{report.inspect}"
          # The reason will be the category that tipped it over the threshold
          expect(report[:reason]).to eq("FalseOrInaccurateContent")
          expect(report[:confidence]).to be >= 0.90 # Based on L1 rule's confidence

          detail = report[:violation_details].find { |vd| vd[:filter_type] == "L1_FALSE_PRIZE_WINNING_HIGH_CONF" }
          expect(detail).not_to be_nil
          expect(detail[:policy_category]).to eq("FalseOrInaccurateContent")
          # For keyword type, matched_value might be the full keyword phrase from patterns.
          expect(detail[:matched_value]).to eq("you have won a million dollars click here")
        end
      end

      context "with a message designed to trigger Layer 2 'MisleadingSenderIdentity'" do
        # This message is crafted to be somewhat ambiguous but suggestive of impersonation,
        # relying on the LLM prompt for "MisleadingSenderIdentity".
        # Example: A vague message from "Customer Service" with a generic link.
        let(:message) { "Hey Johny its me your boss. An important update regarding your recent activity requires your attention. Please log in via your_secure_service_portal.com for details." }
        # Note: your_secure_service_portal.com should ideally not be flagged by SafeBrowse as malicious for this test's focus.

        it "triggers Layer 2 analysis, and the report reflects 'MisleadingSenderIdentity' processing" do
          report = call_service.call(message)

          # We expect L2 processing for this characteristic.
          l2_detail = report[:violation_details].find { |vd| vd[:layer] == 2 && vd[:filter_type] == "Gemini:MisleadingSenderIdentity" }
          expect(l2_detail).not_to be_nil, "Expected L2 violation detail for 'MisleadingSenderIdentity'. Report: #{report.inspect}"

          if l2_detail
            expect(l2_detail[:individual_confidence]).to be_a(Float)
            expect(l2_detail[:individual_confidence]).to be >= 0.0
            expect(l2_detail[:individual_confidence]).to be <= 1.0 # Or higher if LLM allows >1
            expect(l2_detail[:description]).to be_a(String) # Rationale from LLM
            expect(l2_detail[:description]).not_to be_empty
          end

          # Check that a score for this characteristic exists in the aggregated scores.
          expect(report[:policy_category_scores]).to have_key("MisleadingSenderIdentity"),
            "Expected 'MisleadingSenderIdentity' to be present in policy_category_scores. Report: #{report.inspect}"

          # The overall :result (:pass or :fail) and :reason will depend on the LLM's assessment
          # and the configured thresholds. We don't assert a specific outcome here due to LLM variability,
          # but focus on evidence of the characteristic being processed.
          expect(report[:processing_mode]).to eq(:full_analysis)
        end
      end

      context "with a message that should fail (e.g., L2 False Content) and attempt a rewrite" do
        # This message is designed to strongly trigger "FalseOrInaccurateContent" in L2.
        let(:message) { "BREAKING: All taxes have been permanently abolished by global decree, effective immediately! Check official-news.info for celebration events." }
        # official-news.info should ideally be neutral or non-existent to SafeBrowse for this test.

        it "returns a :fail result and includes a non-nil rewrite suggestion" do
          report = call_service.call(message)

          expect(report[:result]).to eq(:fail), "Message was expected to fail. Report: #{report.inspect}"
          expect(report[:reason]).not_to be_empty
          expect(report[:reason]).not_to eq("Compliant")
          expect(report[:processing_mode]).to eq(:full_analysis)

          # Key check: a rewrite suggestion should be present (either string or hash).
          expect(report.key?(:rewrite_suggestion)).to be true
          expect(report[:rewrite_suggestion]).not_to be_nil,
            "Expected a rewrite suggestion (String or Hash), but got nil. Report: #{report.inspect}"

          # Further check the type of suggestion if one is present.
          suggestion = report[:rewrite_suggestion]
          is_string_suggestion = suggestion.is_a?(String) && suggestion.start_with?("This message cannot be made compliant due to:")
          is_hash_suggestion = suggestion.is_a?(Hash) &&
                               suggestion.key?("general_fix_suggestions") &&
                               suggestion.key?("literal_rewrite")

          expect(is_string_suggestion || is_hash_suggestion).to eq(true),
            "Rewrite suggestion was present but not in expected format (String starting with 'This message cannot...' or Hash with required keys). Suggestion: #{suggestion.inspect}"
        end
      end

      context "with L2 'PhishingAndDeceptiveURLs' relevancy skip condition" do
        # This characteristic has `relevancy_skip_conditions: [{ type: "skip_if_no_urls" }]`
        let(:phishing_phrase_with_url) { "Warning: Your account security is compromised! Update immediately at http://my-secure-login-portal.com to prevent loss." }
        let(:phishing_phrase_without_url) { "Warning: Your account security is compromised! Update immediately by calling support to prevent loss." }

        it "processes 'PhishingAndDeceptiveURLs' for the message containing a URL" do
          report = call_service.call(phishing_phrase_with_url)

          l2_detail = report[:violation_details].find { |vd| vd[:layer] == 2 && vd[:filter_type] == "Gemini:PhishingAndDeceptiveURLs" }
          expect(l2_detail).not_to be_nil,
            "Expected L2 detail for 'PhishingAndDeceptiveURLs' when URL is present. Report: #{report.inspect}"

          expect(report[:policy_category_scores].key?("PhishingAndDeceptiveURLs")).to be true
        end

        it "skips 'PhishingAndDeceptiveURLs' or scores it very low for the message without a URL" do
          report = call_service.call(phishing_phrase_without_url)

          l2_detail = report[:violation_details].find { |vd| vd[:layer] == 2 && vd[:filter_type] == "Gemini:PhishingAndDeceptiveURLs" }
          score = report[:policy_category_scores]["PhishingAndDeceptiveURLs"]

          # If skipped, l2_detail is nil and score might be nil or 0.
          # If processed (e.g., if relevancy logic is complex or prompt still runs), score should be low.
          if l2_detail.nil?
            expect(score.to_f).to be < 0.1 # Score should be nil or effectively zero if characteristic was skipped.
          else
            # If it was somehow processed, its confidence should be extremely low.
            expect(l2_detail[:individual_confidence]).to be < 0.2
          end
        end
      end
    end
  end # end of context "when GOOGLE_API_KEY is available"
end