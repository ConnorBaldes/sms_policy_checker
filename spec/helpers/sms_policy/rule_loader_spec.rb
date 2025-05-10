# frozen_string_literal: true

require 'rails_helper' # Or 'spec_helper'
# require_relative '../../../app/helpers/sms_policy/rule_loader' # If not autoloaded

RSpec.describe SmsPolicy::RuleLoader do
  # Use FileFixtures helper if created, or define YAML inline / use `let_it_be_loaded`
  include FileFixtures # Assuming this helper is created in spec/support

  describe '.load_rules' do
    context 'with valid YAML content' do
      let(:valid_yaml_content) do
        <<~YAML
          - name: "L1_KEYWORD_TEST"
            description: "Test keyword rule"
            type: "keyword"
            patterns: ["secret word", "another phrase"]
            mapped_policy_category: "TestCategory"
            individual_confidence: 0.9
            is_early_exit_rule: true
            early_exit_threshold: 0.85
          - name: "L1_REGEX_TEST"
            description: "Test regex rule"
            type: "regex"
            patterns: ["^\\d{3}-\\d{3}-\\d{4}$", "pattern_two"]
            mapped_policy_category: "TestDataFormat"
            individual_confidence: 0.7
            is_early_exit_rule: false
        YAML
      end
      let(:loaded_rules) { described_class.load_rules(valid_yaml_content) }

      it 'parses the YAML and returns an array of rule hashes' do
        expect(loaded_rules).to be_an(Array)
        expect(loaded_rules.size).to eq(2)
      end

      it 'correctly compiles keyword patterns into Regexp objects' do
        keyword_rule = loaded_rules.find { |r| r['name'] == "L1_KEYWORD_TEST" }
        expect(keyword_rule).to be_present
        expect(keyword_rule['compiled_patterns']).to be_an(Array)
        expect(keyword_rule['compiled_patterns'].size).to eq(2)

        # Check first keyword pattern
        pattern1 = keyword_rule['compiled_patterns'].first
        expect(pattern1).to be_a(Regexp)
        expect(pattern1.source).to eq("\\bsecret\\ word\\b") # Regexp.escape applied
        expect(pattern1.options & Regexp::IGNORECASE).to be > 0
        expect("some secret word here").to match(pattern1)
        expect("secret wording").not_to match(pattern1) # Whole word
        expect("SECRET WORD").to match(pattern1) # Case insensitive

        # Check second keyword pattern
        pattern2 = keyword_rule['compiled_patterns'].second
        expect(pattern2).to be_a(Regexp)
        expect(pattern2.source).to eq("\\banother\\ phrase\\b")
      end

      it 'correctly compiles regex patterns into Regexp objects' do
        regex_rule = loaded_rules.find { |r| r['name'] == "L1_REGEX_TEST" }
        expect(regex_rule).to be_present
        expect(regex_rule['compiled_patterns']).to be_an(Array)
        expect(regex_rule['compiled_patterns'].size).to eq(2)

        # Check first regex pattern
        pattern1 = regex_rule['compiled_patterns'].first
        expect(pattern1).to be_a(Regexp)
        expect(pattern1.source).to eq("^\\d{3}-\\d{3}-\\d{4}$") # Original regex preserved
        expect(pattern1.options & Regexp::IGNORECASE).to be > 0 # Default ignorecase from loader
        expect("123-456-7890").to match(pattern1)
        expect("abc-def-ghij").not_to match(pattern1)

        # Check second regex pattern
        pattern2 = regex_rule['compiled_patterns'].second
        expect(pattern2).to be_a(Regexp)
        expect(pattern2.source).to eq("pattern_two")
      end

      it 'preserves other rule attributes' do
        keyword_rule = loaded_rules.first
        expect(keyword_rule['name']).to eq("L1_KEYWORD_TEST")
        expect(keyword_rule['description']).to eq("Test keyword rule")
        expect(keyword_rule['mapped_policy_category']).to eq("TestCategory")
        expect(keyword_rule['individual_confidence']).to eq(0.9)
        expect(keyword_rule['is_early_exit_rule']).to be true
        expect(keyword_rule['early_exit_threshold']).to eq(0.85)
      end
    end

    context 'with invalid YAML content' do
      it 'raises an error for malformed YAML' do
        malformed_yaml = "name: Test\n  description: BadIndent"
        expect { described_class.load_rules(malformed_yaml) }
          .to raise_error(StandardError, /Failed to parse Layer 1 rules YAML/)
      end

      it 'raises an error if YAML is not an array of rules' do
        yaml_not_array = "---\nkey: value"
        expect { described_class.load_rules(yaml_not_array) }
          .to raise_error(StandardError, /Invalid YAML or empty ruleset/)
      end
    end

    context 'with invalid rule definitions' do
      it 'raises an error if a required key is missing' do
        yaml_missing_key = <<~YAML
          - name: "L1_INCOMPLETE"
            description: "Missing type"
            # type: "keyword" # Missing type
            patterns: ["test"]
            mapped_policy_category: "Category"
            individual_confidence: 0.5
            is_early_exit_rule: false
        YAML
        expect { described_class.load_rules(yaml_missing_key) }
          .to raise_error(StandardError, /Missing keys: type/)
      end

      it 'raises an error if rule type is invalid' do
        yaml_invalid_type = <<~YAML
          - name: "L1_BAD_TYPE"
            description: "Invalid type"
            type: "unknown_type"
            patterns: ["test"]
            mapped_policy_category: "Category"
            individual_confidence: 0.5
            is_early_exit_rule: false
        YAML
        expect { described_class.load_rules(yaml_invalid_type) }
          .to raise_error(StandardError, /Invalid rule type: 'unknown_type'/)
      end

      it 'raises an error if early_exit_rule is true but threshold is missing' do
        yaml_missing_threshold = <<~YAML
          - name: "L1_MISSING_THRESHOLD"
            description: "Early exit but no threshold"
            type: "keyword"
            patterns: ["test"]
            mapped_policy_category: "Category"
            individual_confidence: 0.9
            is_early_exit_rule: true
            # early_exit_threshold: 0.9 # Missing
        YAML
        expect { described_class.load_rules(yaml_missing_threshold) }
          .to raise_error(StandardError, /is an early_exit_rule but missing 'early_exit_threshold'/)
      end

      it 'raises an error if individual_confidence is not a float between 0.0 and 1.0' do
         yaml_invalid_confidence = <<~YAML
          - name: "L1_BAD_CONFIDENCE"
            description: "Bad confidence value"
            type: "keyword"
            patterns: ["test"]
            mapped_policy_category: "Category"
            individual_confidence: 1.5 # Invalid
            is_early_exit_rule: false
        YAML
        expect { described_class.load_rules(yaml_invalid_confidence) }
          .to raise_error(StandardError, /has invalid 'individual_confidence': 1.5/)
      end
    end

    context 'with empty patterns array' do
      let(:yaml_empty_patterns) do
        <<~YAML
          - name: "L1_NO_PATTERNS"
            description: "Rule with no patterns"
            type: "keyword"
            patterns: [] # Empty
            mapped_policy_category: "TestCategory"
            individual_confidence: 0.9
            is_early_exit_rule: false
        YAML
      end
      it 'correctly handles empty patterns array' do
        rules = described_class.load_rules(yaml_empty_patterns)
        expect(rules.first['compiled_patterns']).to eq([])
      end
    end

    context 'using actual files from config (integration-like)' do
      # This assumes you have the YAML files in your `config/` directory
      # and the FileFixtures helper can access them, or you load them directly.

      # To test with the actual config file:
      # let(:rules_yaml_content) { file_fixture('sms_policy_checker_rules.yml').read }
      # Or, if FileFixtures is not set up for this path:
      let(:rules_yaml_content) { File.read(Rails.root.join('config', 'sms_policy_checker_rules.yml')) }

      it 'loads rules from the project config file without error' do
        # Ensure your actual YAML file is valid before running this
        expect { described_class.load_rules(rules_yaml_content) }.not_to raise_error
      end

      it 'compiles patterns from the project config file correctly' do
        loaded_rules = described_class.load_rules(rules_yaml_content)
        # Add specific checks based on the content of your actual rules file
        # For example, find a specific rule and check its compiled_patterns.
        # This makes the test more robust to changes in the fixture file.
        public_url_shortener_rule = loaded_rules.find { |r| r['name'] == "L1_PUBLIC_URL_SHORTENER" }
        if public_url_shortener_rule
          expect(public_url_shortener_rule['compiled_patterns'].first).to be_a(Regexp)
          expect("http://bit.ly/test123").to match(public_url_shortener_rule['compiled_patterns'].first)
        else
          # Skip or pending if the rule is not in the file, to avoid test brittleness
          # pending "L1_PUBLIC_URL_SHORTENER rule not found in fixture for detailed check."
        end
      end
    end
  end
end
