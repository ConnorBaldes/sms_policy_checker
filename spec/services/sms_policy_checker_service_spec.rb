# frozen_string_literal: true

require 'rails_helper' # Or 'spec_helper' if not a full Rails app context for the service
# require 'sms_policy_checker_service' # Explicit require if not autoloaded

# Mock API Client Wrappers
# These would live in spec/support/mocks or similar and be required.
module Google
  class MockGeminiClient
    def analyze_characteristic(prompt_payload)
      # Simulate response based on prompt_payload or test scenario
      { confidence_score: 0.1, rationale: "Mock Gemini: Looks okay." }.to_json
    end
    def generate_rewrite(prompt_payload)
      { general_fix_suggestions: "Mock fix.", literal_rewrite: "Mock rewrite." }.to_json
    end
  end

  class MockSafeBrowseClient
    def find_threat_matches(urls)
      # Simulate no threats
      {}
    end
  end

  class MockPerspectiveClient
    def analyze_comment(text, requested_attributes: nil)
      # Simulate low scores
      { "attributeScores" => { "TOXICITY" => { "summaryScore" => { "value" => 0.1 } } } }
    end
  end

  class MockNlClient
    def analyze_entities(text, encoding_type: "UTF8")
      # Simulate no relevant entities
      { "entities" => [] }
    end
  end
end


RSpec.describe SmsPolicyCheckerService do

  # --- Mocked Clients (Needed even if not used by L1, for service instantiation) ---
  let(:mock_gemini_client) { instance_double(Google::GeminiClient) }
  let(:mock_safe_browse_client) { instance_double(Google::SafeBrowseClient) }
  let(:mock_perspective_client) { instance_double(Google::PerspectiveClient) }
  let(:mock_nl_client) { instance_double(Google::NlClient) }

  # --- Service Instance ---
  # Use `build_service` to easily change message_body per test context
  let(:build_service) { ->(msg_body) { described_class.new(msg_body) } }
  let(:message_body) { "This is a default test message." } # Default, can be overridden
  let(:service_instance) { build_service.call(message_body) } # Instance for direct method testing

  # --- Service Invocation ---
  # Use a helper to easily invoke the class method .call
  let(:run_service_call) { ->(msg_body) { described_class.call(msg_body) } }

  # --- Configuration Setup ---
  # This ensures constants are loaded. Your previous fixes should make this work.
  # If these constants are not set, the `#process_layer1_rules` will log an error and skip.
  before(:all) do
    # Force load the initializer if it hasn't run or if constants are not set.
    # This is a bit of a sledgehammer for tests but ensures config is present.
    # In a mature setup, you might rely on Rails booting fully once.
    initializer_path = Rails.root.join('config/initializers/sms_policy_checker_config.rb')
    # Ensure SmsPolicyCheckerService itself is loaded before trying to load its constants if initializer didn't catch it
    require_dependency Rails.root.join('app/services/sms_policy_checker_service.rb').to_s unless defined?(SmsPolicyCheckerService)
    load initializer_path if defined?(Rails) && File.exist?(initializer_path) && !SmsPolicyCheckerService.const_defined?(:LAYER1_RULES)

    # Define a default set of rules for .call tests if needed, or rely on loaded config.
    # For these .call tests, it's often better to rely on the actual loaded config
    # or a shared, comprehensive test rule set loaded via `stub_const`.
    @default_test_layer1_rules_for_call_spec = [
      {
        'name' => "L1_CALL_EARLY_EXIT", 'description' => ".call Early Exit", 'type' => "keyword",
        'patterns' => ["critical system failure"], 'compiled_patterns' => [/\bcritical\ system\ failure\b/i],
        'mapped_policy_category' => "SystemAlert", 'individual_confidence' => 1.0,
        'is_early_exit_rule' => true, 'early_exit_threshold' => 0.95
      },
      {
        'name' => "L1_CALL_HIGH_SCORE_NO_EXIT", 'description' => ".call High Score, No Exit", 'type' => "keyword",
        'patterns' => ["major policy concern"], 'compiled_patterns' => [/\bmajor\ policy\ concern\b/i],
        'mapped_policy_category' => "MajorConcern", 'individual_confidence' => 0.8, # Assume L1 fallback threshold is 0.7
        'is_early_exit_rule' => false
      },
      {
        'name' => "L1_CALL_LOW_SCORE", 'description' => ".call Low Score", 'type' => "keyword",
        'patterns' => ["minor note"], 'compiled_patterns' => [/\bminor\ note\b/i],
        'mapped_policy_category' => "MinorNote", 'individual_confidence' => 0.3,
        'is_early_exit_rule' => false
      }
    ].freeze
  end

  before do
    # Mock client instantiation (as per previous fixes, these should be class-level mocks)
    allow(Google::GeminiClient).to receive(:new).and_return(mock_gemini_client)
    allow(Google::SafeBrowseClient).to receive(:new).and_return(mock_safe_browse_client)
    allow(Google::PerspectiveClient).to receive(:new).and_return(mock_perspective_client)
    allow(Google::NlClient).to receive(:new).and_return(mock_nl_client)

    # Stub the LAYER1_RULES constant for these .call tests for predictability
    # You might want to manage this more globally or per context.
    stub_const("SmsPolicyCheckerService::LAYER1_RULES", @default_test_layer1_rules_for_call_spec)
    # Ensure THRESHOLDS are also sensible for testing
    # For this step, we care about FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK.
    # The initializer should load this, but we can override for test precision if needed.
    # Example:
    # current_thresholds = SmsPolicyCheckerService::THRESHOLDS.dup
    # current_thresholds['FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK'] = 0.70
    # stub_const("SmsPolicyCheckerService::THRESHOLDS", current_thresholds.freeze)
    # Ensure the default loaded FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK from your YAML is e.g. 0.70 for the tests below.
  end

  # Test configuration loading (can also be in a separate spec file for the initializer)
  describe 'Configuration Loading' do
    it 'makes LAYER1_RULES constant available and an array' do
      expect(SmsPolicyCheckerService::LAYER1_RULES).to be_an(Array)
      # You can add more specific checks based on your minimal YAML
      unless SmsPolicyCheckerService::LAYER1_RULES.empty?
        expect(SmsPolicyCheckerService::LAYER1_RULES.first).to be_a(Hash)
        expect(SmsPolicyCheckerService::LAYER1_RULES.first['compiled_patterns'].first).to be_a(Regexp)
      end
    end

    it 'makes LLM_CONFIG constant available and a hash with characteristics' do
      expect(SmsPolicyCheckerService::LLM_CONFIG).to be_a(Hash)
      expect(SmsPolicyCheckerService::LLM_CONFIG['characteristics']).to be_an(Array)
      unless SmsPolicyCheckerService::LLM_CONFIG['characteristics'].empty?
        expect(SmsPolicyCheckerService::LLM_CONFIG['characteristics'].first).to be_a(Hash)
        expect(SmsPolicyCheckerService::LLM_CONFIG['characteristics'].first).to have_key('name')
        expect(SmsPolicyCheckerService::LLM_CONFIG['characteristics'].first).to have_key('prompt_template')
      end
    end

    it 'makes THRESHOLDS constant available and a hash' do
      expect(SmsPolicyCheckerService::THRESHOLDS).to be_a(Hash)
      expect(SmsPolicyCheckerService::THRESHOLDS).to have_key('FINAL_THRESHOLD_FLAG')
      expect(SmsPolicyCheckerService::THRESHOLDS).to have_key('CRITICAL_FAILURE_THRESHOLDS')
      expect(SmsPolicyCheckerService::THRESHOLDS['CRITICAL_FAILURE_THRESHOLDS']).to be_a(Hash)
    end

    it 'makes CRITICAL_FAILURE_THRESHOLDS constant available and a hash' do
      expect(SmsPolicyCheckerService::CRITICAL_FAILURE_THRESHOLDS).to be_a(Hash)
    end
  end

  describe ".call" do
    subject(:report) { described_class.call(message_body) }

    context "with a clearly compliant message" do
      let(:message_body) { "Hello, hope you are having a great day!" }

      it "returns a :pass result" do
        expect(report[:result]).to eq(:pass)
        expect(report[:reason]).to eq("Compliant")
        expect(report[:confidence]).to be <= (SmsPolicyCheckerService::THRESHOLDS['FINAL_THRESHOLD_FLAG'] || 0.75)
      end

      it "has :full_analysis processing_mode" do
        expect(report[:processing_mode]).to eq(:full_analysis)
      end

      it "has an empty or low-scoring policy_category_scores" do
        expect(report[:policy_category_scores]).to be_a(Hash)
        # Add more specific checks if certain categories are always scored
      end

      it "has minimal or no violation_details" do
        expect(report[:violation_details]).to be_an(Array)
        # Possibly check that it's empty or contains only very low confidence informational items.
      end
    end

    context "with a message triggering a Layer 1 early exit rule" do
      # Assume L1_SHAFT_SEX_EXPLICIT_KEYWORD with "hardcore sex" pattern (1.0 confidence, early_exit_threshold: 1.0)
      # exists in `sms_policy_checker_rules.yml`
      let(:message_body) { "Come watch this hardcore sex movie now!" }

      it "returns a :fail result due to Layer 1 early exit" do
        report = described_class.call(message_body) # Invokes service with initializer-loaded rules
        expect(report[:violation_details].first[:filter_type]).to eq("L1_SHAFT_SEX_EXPLICIT_KEYWORD")
        expect(report[:result]).to eq(:fail)
        expect(report[:reason]).to eq("Early Exit - Violation Category: SHAFT-Sex")
        expect(report[:confidence]).to eq(1.0) # Based on the rule's confidence

      end

      it "includes the Layer 1 violation detail" do
        detail = report[:violation_details].find { |vd| vd[:filter_type] == "L1_SHAFT_SEX_EXPLICIT_KEYWORD" }
        expect(detail).to be_present
        expect(detail[:layer]).to eq(1)
        expect(detail[:policy_category]).to eq("SHAFT-Sex")
        expect(detail[:matched_value]).to include("hardcore sex")
      end

      it "does not proceed to Layer 2 (implicitly, no L2 calls should be made)" do
        skip "Verify Layer 2 calls are skipped"
        # This might involve checking that mock LLM clients were not called,
        # or that `process_layer2_llm_analysis` was effectively skipped.
      end
    end

    context "with a message requiring Layer 2 analysis (e.g., nuanced phishing)" do
      let(:message_body) { "Urgent: Your account needs verification. Click example.com/update to avoid suspension." }

      before do
        # Mock Gemini to return a high phishing score for this specific message context
        # This requires more sophisticated mocking of the mock_gemini_client based on input.
        allow(mock_gemini_client).to receive(:analyze_characteristic) do |prompt_payload|
          # Crude check if prompt is for phishing for this test
          if prompt_payload.to_s.include?("PhishingAndDeceptiveURLs") && prompt_payload.to_s.include?("Urgent: Your account")
            { confidence_score: 0.98, rationale: "Mock Gemini: Strong phishing indicators detected." }.to_json
          else
            { confidence_score: 0.1, rationale: "Mock Gemini: Other characteristic, looks okay." }.to_json
          end
        end
        # Mock SafeBrowse to flag the URL (if your LLM prompt uses it)
        allow(mock_safe_browse_client).to receive(:find_threat_matches).with([ "example.com/update" ])
            .and_return({ "matches" => [ { "threatType" => "SOCIAL_ENGINEERING", "url" => "example.com/update" } ] })
      end

      it "returns a :fail result based on Layer 2" do
        pending "Implementation of Layer 2 and final decision logic needed"
        expect(report[:result]).to eq(:fail)
        # Reason could be "PhishingAndDeceptiveURLs" if it's a critical failure or highest score
        expect(report[:reason]).to eq("PhishingAndDeceptiveURLs") # Assuming it's critical or highest
        expect(report[:confidence]).to be >= (SmsPolicyCheckerService::THRESHOLDS['CRITICAL_FAILURE_THRESHOLDS']["PhishingAndDeceptiveURLs"] || 0.95)
      end

      it "includes Layer 2 violation details for Phishing" do
        pending "Implementation of Layer 2 processing needed"
        detail = report[:violation_details].find { |vd| vd[:filter_type] == "Gemini:PhishingAndDeceptiveURLs" }
        expect(detail).to be_present
        expect(detail[:layer]).to eq(2)
        expect(detail[:individual_confidence]).to eq(0.98)
        expect(detail[:description]).to eq("Mock Gemini: Strong phishing indicators detected.")
      end

      it "provides a rewrite_suggestion (if message failed in :full_analysis)" do
        pending "Implementation of rewrite suggestion logic needed"
        # Assuming the mock_gemini_client.generate_rewrite is called and returns a valid structure
        expect(report[:rewrite_suggestion]).to be_a(Hash)
        expect(report[:rewrite_suggestion][:literal_rewrite]).to eq("Mock rewrite.")
      end
    end

    context "when auxiliary APIs (e.g., Gemini) fail, triggering fallback mode" do
      before do
        # Simulate Gemini API failure
        allow(mock_gemini_client).to receive(:analyze_characteristic).and_raise(StandardError.new("Gemini API unavailable"))
        # Assume a Layer 1 rule might still trigger a fail in fallback
        # e.g., L1_EXCESSIVE_CAPITALIZATION with 0.70 confidence, and fallback threshold is 0.65
      end

      let(:message_body) { "SIGN UP NOW FOR FREE MONEY AND PRIZES CLICK HERE YOU WON BIG" } # Lots of caps

      it "sets processing_mode to :fallback_layer1_only" do
        pending "Implementation of API error handling and fallback mode needed"
        expect(report[:processing_mode]).to eq(:fallback_layer1_only)
      end

      it "bases the result solely on Layer 1 rules and fallback thresholds" do
        pending "Implementation of fallback decision logic needed"
        # Assuming L1_EXCESSIVE_CAPITALIZATION triggers with 0.70 and FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK is e.g. 0.65
        # Or use a L1 rule that is an early_exit for fallback
        expect(report[:result]).to eq(:fail) # Or :pass if L1 passes in fallback
        expect(report[:reason]).to match(/Fallback: Layer 1 Threshold Exceeded - Violation Category: Content-Evasion-Spam|Fallback: Early Exit - Violation Category: \w+/)
        expect(report[:confidence]).to eq(0.70) # From the L1 rule
      end

      it "has a nil rewrite_suggestion" do
        expect(report[:rewrite_suggestion]).to be_nil
      end
    end

    context "Layer 2 relevancy checks" do
      let(:message_body) { "Hello there, just a friendly message." } # No URLs

      before do
        # LLM_CONFIG for PhishingAndDeceptiveURLs has skip_if_no_urls
        # Mock NL client to return no entities if a characteristic depends on it.
        allow(mock_nl_client).to receive(:analyze_entities).and_return({ "entities" => [] })
        allow(mock_safe_browse_client).to receive(:find_threat_matches).and_return({})

        # We need to spy on the Gemini client to ensure it's not called for certain characteristics.
        # This is more complex and might involve more detailed interaction with service_instance internals.
      end

      it "skips LLM call for 'PhishingAndDeceptiveURLs' if no URLs are present" do
        pending "Implementation of relevancy checks and detailed L2 call verification needed"
        # Expectation: The mock_gemini_client.analyze_characteristic should NOT be called
        # with a prompt related to 'PhishingAndDeceptiveURLs'.
        # This requires careful stubbing/spying.
        # For now, check the violation_details for a skip note.
        report = service_instance.call # Call instance method for easier internal inspection/stubbing if needed

        # This assumes your service adds a detail note when skipping.
        skip_detail = report[:violation_details].find { |vd| vd[:description]&.include?("LLM assessment for PhishingAndDeceptiveURLs skipped") }
        expect(skip_detail).to be_present
        expect(skip_detail[:individual_confidence]).to eq(0.0)
      end
    end

    context "rewrite_suggestion logic" do
      # This context would need more specific mocking for the generate_rewrite method of Gemini.
      context "when LLM deems message correctable" do
        let(:message_body) { "This is a failing message that can be fixed." }
        before do
          # Mock service to fail
          allow_any_instance_of(SmsPolicyCheckerService).to receive(:process_layer1_rules).and_return(false) # No L1 halt
          allow_any_instance_of(SmsPolicyCheckerService).to receive(:process_layer2_llm_analysis) do |svc|
            # Simulate a Layer 2 failure
            svc.message_analysis_report[:result] = :fail
            svc.message_analysis_report[:reason] = "SomePolicyViolation"
            svc.message_analysis_report[:confidence] = 0.9
            svc.message_analysis_report[:processing_mode] = :full_analysis
          end
          allow(mock_gemini_client).to receive(:generate_rewrite)
            .and_return({ general_fix_suggestions: "Try this.", literal_rewrite: "Fixed message." }.to_json)
        end
        it "returns a hash with suggestions" do
          pending "Implementation of rewrite generation"
          expect(report[:rewrite_suggestion]).to eq({
            "general_fix_suggestions" => "Try this.", # Note: keys might be symbols depending on JSON parse
            "literal_rewrite" => "Fixed message."
          })
        end
      end

      context "when LLM deems message uncorrectable" do
         let(:message_body) { "This is a very bad message." }
         before do
          allow_any_instance_of(SmsPolicyCheckerService).to receive(:process_layer1_rules).and_return(false)
          allow_any_instance_of(SmsPolicyCheckerService).to receive(:process_layer2_llm_analysis) do |svc|
            svc.message_analysis_report[:result] = :fail
            svc.message_analysis_report[:reason] = "SevereViolation"
            svc.message_analysis_report[:confidence] = 1.0
            svc.message_analysis_report[:processing_mode] = :full_analysis
          end
          allow(mock_gemini_client).to receive(:generate_rewrite)
            .and_return("This message cannot be made compliant due to: Extreme content.")
        end
        it "returns the uncorrectable string" do
          pending "Implementation of rewrite generation"
          expect(report[:rewrite_suggestion]).to eq("This message cannot be made compliant due to: Extreme content.")
        end
      end

      context "when rewrite generation fails or LLM returns nil/unexpected" do
         let(:message_body) { "Another failing message." }
         before do
          allow_any_instance_of(SmsPolicyCheckerService).to receive(:process_layer1_rules).and_return(false)
          allow_any_instance_of(SmsPolicyCheckerService).to receive(:process_layer2_llm_analysis) do |svc|
            svc.message_analysis_report[:result] = :fail
            svc.message_analysis_report[:reason] = "ViolationX"
            svc.message_analysis_report[:confidence] = 0.8
            svc.message_analysis_report[:processing_mode] = :full_analysis
          end
          allow(mock_gemini_client).to receive(:generate_rewrite).and_return(nil) # Or raise error, or return malformed
        end
        it "returns nil for rewrite_suggestion" do
          expect(report[:rewrite_suggestion]).to be_nil
        end
      end
    end

    # TODO: Add more contexts for:
    # - Different Layer 1 rule types (keyword, regex).
    # - Interaction of Layer 1 scores when no early exit, before Layer 2.
    # - Specific Layer 2 characteristics being triggered.
    # - Correct structure of `message_analysis_report` for various pass/fail scenarios.
    # - Testing critical failure conditions from Layer 2 (README Section 6.3.a).
    # - Testing max score fallback logic from Layer 2 (README Section 6.3.b).
  end

  # --- NEW TESTS FOR #process_layer1_rules ---
  describe '#process_layer1_rules' do
    # Helper to run the method and get the report
    let(:run_l1_processing) { service_instance.send(:process_layer1_rules) }
    let(:report) { service_instance.message_analysis_report }

    # Use a minimal set of rules for these specific tests, or rely on your config.
    # For precise testing, defining specific rules here can be better.
    let(:test_layer1_rules) do
      [
        {
          'name' => "L1_KEYWORD_EARLY_EXIT", 'description' => "Test Early Exit", 'type' => "keyword",
          'patterns' => ["emergency exit now"], 'compiled_patterns' => [/\bemergency\ exit\ now\b/i],
          'mapped_policy_category' => "CriticalAlert", 'individual_confidence' => 1.0,
          'is_early_exit_rule' => true, 'early_exit_threshold' => 0.95
        },
        {
          'name' => "L1_KEYWORD_FLAG", 'description' => "Test Flagging Keyword", 'type' => "keyword",
          'patterns' => ["suspicious content"], 'compiled_patterns' => [/\bsuspicious\ content\b/i],
          'mapped_policy_category' => "Suspicious", 'individual_confidence' => 0.7,
          'is_early_exit_rule' => false
        },
        {
          'name' => "L1_REGEX_FORMAT", 'description' => "Test Regex Format", 'type' => "regex",
          'patterns' => ["fmt\\d+"], 'compiled_patterns' => [/fmt\d+/i],
          'mapped_policy_category' => "FormattingIssue", 'individual_confidence' => 0.5,
          'is_early_exit_rule' => false
        },
        {
          'name' => "L1_WEAK_FLAG", 'description' => "Test Weak Flag", 'type' => "keyword",
          'patterns' => ["maybe"], 'compiled_patterns' => [/\bmaybe\b/i],
          'mapped_policy_category' => "Suspicious", 'individual_confidence' => 0.4, # Lower than L1_KEYWORD_FLAG
          'is_early_exit_rule' => false
        }
      ].freeze
    end

    before do
      # Stub the constant for these specific tests if you want isolated rule sets
      stub_const("SmsPolicyCheckerService::LAYER1_RULES", test_layer1_rules)
      # Re-initialize report for each test within this describe block
      service_instance.instance_variable_set(:@message_analysis_report, service_instance.send(:initialize_report))
    end

    context 'when a message matches an early exit keyword rule' do
      let(:message_body) { "Alert: emergency exit now before it's too late!" }

      it 'returns true (processing_halted)' do
        expect(run_l1_processing).to be true
      end

      it 'sets the report result to :fail' do
        run_l1_processing
        expect(report[:result]).to eq(:fail)
      end

      it 'sets the report confidence to the rule\'s confidence' do
        run_l1_processing
        expect(report[:confidence]).to eq(1.0)
      end

      it 'sets the report reason correctly for early exit' do
        run_l1_processing
        expect(report[:reason]).to eq("Early Exit - Violation Category: CriticalAlert")
      end

      it 'adds a violation_detail for the matched rule' do
        run_l1_processing
        detail = report[:violation_details].first
        expect(detail).to include(
          layer: 1,
          filter_type: "L1_KEYWORD_EARLY_EXIT",
          policy_category: "CriticalAlert",
          individual_confidence: 1.0,
          matched_value: "emergency exit now"
        )
      end

      it 'updates policy_category_scores' do
        run_l1_processing
        expect(report[:policy_category_scores]["CriticalAlert"]).to eq(1.0)
      end
    end

    context 'when a message matches a non-early-exit regex rule' do
      let(:message_body) { "Please check item fmt123 for details." }

      it 'returns false (processing_not_halted)' do
        expect(run_l1_processing).to be false
      end

      it 'does not set the report result to :fail yet' do
        run_l1_processing
        expect(report[:result]).to eq(:pass) # Default, as L1 didn't cause early exit
      end

      it 'adds a violation_detail for the matched regex rule' do
        run_l1_processing
        detail = report[:violation_details].first
        expect(detail).to include(
          layer: 1,
          filter_type: "L1_REGEX_FORMAT",
          policy_category: "FormattingIssue",
          individual_confidence: 0.5,
          matched_value: "fmt123"
        )
      end

      it 'updates policy_category_scores' do
        run_l1_processing
        expect(report[:policy_category_scores]["FormattingIssue"]).to eq(0.5)
      end
    end

    context 'when a message matches multiple rules for the same category' do
      let(:message_body) { "This is suspicious content and maybe a problem." } # Matches L1_KEYWORD_FLAG (0.7) and L1_WEAK_FLAG (0.4)

      it 'returns false (processing_not_halted)' do
        expect(run_l1_processing).to be false
      end

      it 'adds violation_details for both matched rules' do
        run_l1_processing
        expect(report[:violation_details].size).to eq(2)
        expect(report[:violation_details].map { |vd| vd[:filter_type] }).to include("L1_KEYWORD_FLAG", "L1_WEAK_FLAG")
      end

      it 'updates policy_category_scores with the MAX confidence for that category' do
        run_l1_processing
        expect(report[:policy_category_scores]["Suspicious"]).to eq(0.7) # Max of 0.7 and 0.4
      end
    end

    context 'when a message matches rules for different categories' do
      let(:message_body) { "Check fmt789, it is suspicious content." }

      it 'returns false (processing_not_halted)' do
        expect(run_l1_processing).to be false
      end

      it 'adds violation_details for both rules' do
        run_l1_processing
        expect(report[:violation_details].size).to eq(2)
      end

      it 'updates policy_category_scores for each category' do
        run_l1_processing
        expect(report[:policy_category_scores]["FormattingIssue"]).to eq(0.5)
        expect(report[:policy_category_scores]["Suspicious"]).to eq(0.7)
      end
    end

    context 'when a message does not match any L1 rules' do
      let(:message_body) { "This is a perfectly fine and compliant message." }
      # Ensure test_layer1_rules won't match this

      it 'returns false (processing_not_halted)' do
        expect(run_l1_processing).to be false
      end

      it 'leaves violation_details empty' do
        run_l1_processing
        expect(report[:violation_details]).to be_empty
      end

      it 'leaves policy_category_scores empty' do
        run_l1_processing
        expect(report[:policy_category_scores]).to be_empty
      end

      it 'leaves report result as :pass and reason as "Compliant"' do
        run_l1_processing
        expect(report[:result]).to eq(:pass)
        expect(report[:reason]).to eq("Compliant")
      end
    end

    context 'when LAYER1_RULES constant is not properly loaded (e.g. nil or not an array)' do
      before do
        stub_const("SmsPolicyCheckerService::LAYER1_RULES", nil) # Simulate load failure
        service_instance.instance_variable_set(:@message_analysis_report, service_instance.send(:initialize_report))
      end

      it 'returns false and logs an error' do
        expect(Rails.logger).to receive(:error).with("[SmsPolicyCheckerService] LAYER1_RULES not loaded or not an array. Skipping Layer 1.")
        expect(run_l1_processing).to be false
      end

      it 'does not add any violation details' do
         run_l1_processing # Call it to trigger the log
         expect(report[:violation_details]).to be_empty
      end
    end
  end # describe '#process_layer1_rules'

  # --- Placeholder for .call tests that will use this L1 logic ---
  describe '.call (integrating L1)' do
    # These tests will be built up in Step 3 of Phase 1
    context "when L1 causes an early exit" do
      let(:message_body) { "Alert: emergency exit now before it's too late!" } # Uses L1_KEYWORD_EARLY_EXIT from test_layer1_rules
      let(:expected_reason) { "Early Exit - Violation Category: CriticalAlert" }

      # before do
      #   stub_const("SmsPolicyCheckerService::LAYER1_RULES", @default_test_layer1_rules || [ # Define or use a shared rule set
      #     {
      #       'name' => "L1_KEYWORD_EARLY_EXIT", 'description' => "Test Early Exit", 'type' => "keyword",
      #       'patterns' => ["emergency exit now"], 'compiled_patterns' => [/\bemergency\ exit\ now\b/i],
      #       'mapped_policy_category' => "CriticalAlert", 'individual_confidence' => 1.0,
      #       'is_early_exit_rule' => true, 'early_exit_threshold' => 0.95
      #     }
      #   ])
      # end

      it "returns a report with :fail, correct reason, and confidence from the early exit rule" do
        # This test will be fully fleshed out when the .call method's orchestration is more complete
        skip "Full .call orchestration for L1 early exit to be tested in Phase 1, Step 3"
        # report = described_class.call(message_body)
        # expect(report[:result]).to eq(:fail)
        # expect(report[:reason]).to eq(expected_reason)
        # expect(report[:confidence]).to eq(1.0)
        # expect(report[:violation_details].first[:filter_type]).to eq("L1_KEYWORD_EARLY_EXIT")
      end
    end
  end

  describe '.call (Layer 1 Only Scenarios)' do
    context 'when message passes all L1 rules' do
      let(:message_body) { "This is a perfectly fine message." } # Does not match test rules
      let(:report) { run_service_call.call(message_body) }

      it 'returns a result of :pass' do
        expect(report[:result]).to eq(:pass)
      end

      it 'returns a reason of "Compliant"' do
        expect(report[:reason]).to eq("Compliant")
      end

      it 'returns a confidence score of 0.0 (or low, from non-triggering rules if any)' do
        expect(report[:confidence]).to eq(0.0) # Since no rules matched
      end

      it 'has an empty violation_details array' do
        expect(report[:violation_details]).to be_empty
      end

      it 'has processing_mode :full_analysis (default for now)' do
        expect(report[:processing_mode]).to eq(:full_analysis)
      end

      it 'has all required keys in the report' do
        expect(report.keys).to match_array(%i[result reason confidence rewrite_suggestion processing_mode policy_category_scores violation_details])
      end
    end

    context 'when message triggers a Layer 1 early exit rule' do
      let(:message_body) { "This message contains EARLYEXITNOW to test the rule." }
      # let(:report) { run_service_call.call(message_body) }

      # it 'returns a result of :fail' do
      #   expect(report[:result]).to eq(:fail)
      # end

      # it 'returns the correct early exit reason' do
      #   expect(report[:reason]).to eq("Early Exit - Violation Category: SystemAlert")
      # end

      # it 'returns the confidence from the early exit rule' do
      #   expect(report[:confidence]).to eq(1.0)
      # end

      # it 'includes the correct violation_detail' do
      #   expect(report[:violation_details].size).to eq(1)
      #   expect(report[:violation_details].first[:filter_type]).to eq("L1_CALL_EARLY_EXIT")
      # end
      let(:rules_for_this_specific_context) do
        [
          {
            'name' => "TEST_EARLY_EXIT_ONLY_RULE",
            'description' => "A very specific early exit rule for this test",
            'type' => "keyword", # Keyword is simpler for this direct test
            'patterns' => ["EARLYEXITNOW"], # Exact match
            'compiled_patterns' => [/\bEARLYEXITNOW\b/i], # Compiled version
            'mapped_policy_category' => "SpecificEarlyExitCat",
            'individual_confidence' => 1.0,
            'is_early_exit_rule' => true,
            'early_exit_threshold' => 0.9
          }
          # NO OTHER RULES for this stub, to ensure isolation
        ]
      end

      before do
        # Stub the constant with these specific rules for examples in THIS context
        stub_const("SmsPolicyCheckerService::LAYER1_RULES", rules_for_this_specific_context)

        # Mock clients
        allow(Google::GeminiClient).to receive(:new).and_return(mock_gemini_client)
        # ... other client mocks
      end

      let(:report) { run_service_call.call(message_body) } # run_service_call.call => DescribedClass.call

      it 'returns a result of :fail' do # Expected to fail if this setup is still not working
        # The debug output from the service will appear BEFORE this expectation runs
        expect(report[:result]).to eq(:fail)
      end

      it 'returns the correct early exit reason' do
        expect(report[:reason]).to eq("Early Exit - Violation Category: SpecificEarlyExitCat")
      end

      it 'returns the confidence from the early exit rule' do
        expect(report[:confidence]).to eq(1.0)
      end

      it 'includes the correct violation_detail' do
        expect(report[:violation_details].size).to eq(1)
        detail = report[:violation_details].first
        expect(detail).to be_present
        expect(detail[:filter_type]).to eq("TEST_EARLY_EXIT_ONLY_RULE")
        expect(detail[:policy_category]).to eq("SpecificEarlyExitCat")
        expect(detail[:matched_value]).to eq("EARLYEXITNOW")
      end
    end

    context 'when message triggers L1 rules but no early exit, and total score exceeds L1 fallback threshold' do
      let(:message_body) { "Warning: major policy concern identified." } # Matches L1_CALL_HIGH_SCORE_NO_EXIT (0.8)
      let(:report) { run_service_call.call(message_body) }
      let(:l1_fallback_threshold) { (SmsPolicyCheckerService::THRESHOLDS['FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK'] || 0.70).to_f }


      # This before block ensures the threshold is set as expected for this test context
      before do
        # Make sure the threshold used by the test is what we expect
        # For example, if default loaded threshold is 0.70, and rule score is 0.8
        unless l1_fallback_threshold == 0.70
            warn "[TEST WARNING] L1 Fallback Threshold is not 0.70 as expected by this test context. It is #{l1_fallback_threshold}."
            warn "              Please adjust 'config/sms_policy_checker_thresholds.yml' or this test's expectation."
        end
        expect(@default_test_layer1_rules_for_call_spec.find { |r| r['name'] == "L1_CALL_HIGH_SCORE_NO_EXIT" } ['individual_confidence']).to be > l1_fallback_threshold
      end

      it 'returns a result of :fail' do
        expect(report[:result]).to eq(:fail)
      end

      it 'returns the correct "Layer 1 Threshold Exceeded" reason' do
        expect(report[:reason]).to eq("Layer 1 Threshold Exceeded - Violation Category: MajorConcern")
      end

      it 'returns the highest L1 confidence score' do
        expect(report[:confidence]).to eq(0.8)
      end

      it 'includes the relevant violation_detail(s)' do
        expect(report[:violation_details].map { |vd| vd[:filter_type] }).to include("L1_CALL_HIGH_SCORE_NO_EXIT")
      end
    end

    context 'when message triggers L1 rules but no early exit, and total score is below L1 fallback threshold' do
      let(:message_body) { "Just a minor note for your attention." } # Matches L1_CALL_LOW_SCORE (0.3)
      let(:report) { run_service_call.call(message_body) }
      let(:l1_fallback_threshold) { (SmsPolicyCheckerService::THRESHOLDS['FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK'] || 0.70).to_f }

      before do
         expect(@default_test_layer1_rules_for_call_spec.find { |r| r['name'] == "L1_CALL_LOW_SCORE" } ['individual_confidence']).to be < l1_fallback_threshold
      end

      it 'returns a result of :pass' do
        expect(report[:result]).to eq(:pass)
      end

      it 'returns a reason of "Compliant"' do
        expect(report[:reason]).to eq("Compliant")
      end

      it 'returns the highest L1 confidence score (which is below threshold)' do
        expect(report[:confidence]).to eq(0.3)
      end

      it 'includes the relevant violation_detail(s)' do
        expect(report[:violation_details].map { |vd| vd[:filter_type] }).to include("L1_CALL_LOW_SCORE")
      end
    end
  end # describe '.call (Layer 1 Only Scenarios)'
end
