# frozen_string_literal: true

require 'yaml'
require 'regexp-examples' # May not be needed if regexes are directly provided

module SmsPolicy
  # == SmsPolicy::RuleLoader
  #
  # Helper module/class responsible for loading and pre-processing Layer 1 rules
  # from a YAML configuration file.
  #
  # It converts keyword patterns into robust Regexp objects and compiles
  # user-defined regex patterns.
  #
  # @see file:README.md#4.2 Implementation Details (Layer 1)
  # @see file:README.md#4.2 Note on Runtime Processing
  #
  module RuleLoader
    # Loads and pre-processes Layer 1 rules from a YAML string or file.
    #
    # @param yaml_content [String] The YAML content defining the rules.
    # @return [Array<Hash>] An array of rule hashes, where each rule has
    #   its `patterns` replaced with `compiled_patterns` (an array of `Regexp` objects).
    # @raise [StandardError] if YAML parsing fails or rule structure is invalid.
    def self.load_rules(yaml_content)
      raw_rules = YAML.safe_load(yaml_content, permitted_classes: [Symbol]) # Add other classes if needed
      raise "Invalid YAML or empty ruleset" unless raw_rules.is_a?(Array)

      raw_rules.map do |rule_def|
        validate_rule_definition!(rule_def) # Ensure essential keys exist

        compiled_patterns = (rule_def['patterns'] || []).map do |pattern_str|
          case rule_def['type']&.downcase
          when 'keyword'
            # Convert keyword to a case-insensitive, whole-word matching regex
            # Escapes special characters in the keyword itself.
            # /\bkeyword\b/i
            Regexp.new("\\b#{Regexp.escape(pattern_str)}\\b", Regexp::IGNORECASE)
          when 'regex'
            # Compile user-provided regex string.
            # Assumes case-insensitivity by default as per README,
            # but users can use inline modifiers.
            Regexp.new(pattern_str, Regexp::IGNORECASE) # Or just Regexp.new(pattern_str) if no default flags
          else
            raise "Invalid rule type: '#{rule_def['type']}' for rule '#{rule_def['name']}'. Must be 'keyword' or 'regex'."
          end
        end.compact

        rule_def.merge('compiled_patterns' => compiled_patterns)
      end
    rescue Psych::SyntaxError => e
      raise "Failed to parse Layer 1 rules YAML: #{e.message}"
    end

    private

    # Validates the structure of a single rule definition.
    #
    # @param rule_def [Hash] The rule definition hash.
    # @raise [StandardError] if the rule definition is missing required keys.
    def self.validate_rule_definition!(rule_def)
      required_keys = %w[name description type patterns mapped_policy_category individual_confidence is_early_exit_rule]
      missing_keys = required_keys.reject { |key| rule_def.key?(key) }

      unless missing_keys.empty?
        raise "Invalid rule definition for '#{rule_def['name'] || 'Unnamed rule'}'. Missing keys: #{missing_keys.join(', ')}"
      end

      if rule_def['is_early_exit_rule'] && !rule_def.key?('early_exit_threshold')
        raise "Rule '#{rule_def['name']}' is an early_exit_rule but missing 'early_exit_threshold'."
      end

      unless rule_def['individual_confidence'].is_a?(Numeric) &&
             rule_def['individual_confidence'] >= 0.0 &&
             rule_def['individual_confidence'] <= 1.0
        raise "Rule '#{rule_def['name']}' has invalid 'individual_confidence': #{rule_def['individual_confidence']}. Must be float 0.0-1.0."
      end
    end
  end
end
