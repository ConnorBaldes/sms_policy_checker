# frozen_string_literal: true

require "yaml"

module SmsPolicy
  # == SmsPolicy::RuleLoader
  #
  # Helper module responsible for loading and pre-processing Layer 1 rules
  # from a YAML configuration file or string.
  #
  # It converts keyword patterns into robust Regexp objects and compiles
  # user-defined regex patterns. It also validates the structure and basic
  # integrity of the rule definitions.
  #
  # @see file:README.md#4.2 Implementation Details (Layer 1)
  # @see file:README.md#4.2 Note on Runtime Processing
  #
  module RuleLoader
    # Loads and pre-processes Layer 1 rules from a YAML string.
    #
    # @param yaml_content [String] The YAML content defining the rules.
    # @return [Array<Hash>] An array of rule hashes, where each rule has
    #   its `patterns` (if any) replaced with `compiled_patterns`
    #   (an array of `Regexp` objects).
    # @raise [StandardError] if YAML parsing fails, the ruleset is invalid,
    #   or any rule definition is malformed or invalid.
    def self.load_rules(yaml_content)
      raw_rules = YAML.safe_load(yaml_content, permitted_classes: [Symbol]) # Add other permitted classes if ever needed
      raise "Invalid YAML or empty ruleset provided" unless raw_rules.is_a?(Array) && raw_rules.any?

      raw_rules.map do |rule_def|
        validate_rule_definition!(rule_def) # Ensure essential keys and values are valid

        compiled_patterns = (rule_def["patterns"] || []).map do |pattern_str|
          _compile_single_pattern(pattern_str, rule_def["type"], rule_def["name"])
        end.compact # compact might be redundant if _compile_single_pattern always raises on error or returns Regexp

        rule_def.merge("compiled_patterns" => compiled_patterns)
      end
    rescue Psych::SyntaxError => e
      raise "Failed to parse Layer 1 rules YAML: #{e.message}"
    # Catching StandardError here could mask errors from _compile_single_pattern or validate_rule_definition!
    # It's better to let them propagate if they are not Psych::SyntaxError.
    end

    private

    # Compiles a single pattern string into a Regexp object based on the rule type.
    #
    # @private
    # @param pattern_str [String, Object] The pattern string to compile. Expected to be a string.
    # @param type_str [String, nil] The type of the rule ("keyword" or "regex").
    # @param rule_name [String] The name of the rule (for error context).
    # @return [Regexp] The compiled regular expression.
    # @raise [StandardError] if the pattern string is empty/blank or if the rule type is invalid.
    def self._compile_single_pattern(pattern_str, type_str, rule_name)
      if pattern_str.to_s.strip.empty?
        raise "Pattern string cannot be empty or blank for rule '#{rule_name}' (type: '#{type_str}')."
      end

      clean_pattern_str = pattern_str.to_s # Ensure it's a string if it wasn't already

      case type_str&.downcase
      when "keyword"
        # Convert keyword to a case-insensitive, whole-word matching regex.
        # Escapes special characters in the keyword itself.
        # Example: "find me" -> /\bfind me\b/i
        Regexp.new("\\b#{Regexp.escape(clean_pattern_str)}\\b", Regexp::IGNORECASE)
      when "regex"
        # Compile user-provided regex string.
        # Assumes case-insensitivity by default as per common policy requirements,
        # but users can use inline modifiers like (?-i:) within their regex string
        # if case-sensitivity is needed for a specific pattern.
        Regexp.new(clean_pattern_str, Regexp::IGNORECASE)
      else
        raise "Invalid rule type: '#{type_str}' for rule '#{rule_name}'. Must be 'keyword' or 'regex'."
      end
    end

    # Validates the structure and essential values of a single rule definition.
    #
    # @private
    # @param rule_def [Hash] The rule definition hash to validate.
    # @raise [StandardError] if the rule definition is not a Hash, is missing required keys,
    #   or has invalid values for certain keys (e.g., `individual_confidence`).
    def self.validate_rule_definition!(rule_def)
      unless rule_def.is_a?(Hash)
        raise "Invalid rule definition: Expected a Hash, got #{rule_def.class} for rule content: #{rule_def.inspect.truncate(100)}"
      end

      rule_name_for_error = rule_def["name"] || 'Unnamed rule'

      required_keys = %w[name description type patterns mapped_policy_category individual_confidence is_early_exit_rule]
      missing_keys = required_keys.reject { |key| rule_def.key?(key) }

      unless missing_keys.empty?
        raise "Invalid rule definition for '#{rule_name_for_error}'. Missing keys: #{missing_keys.join(', ')}"
      end

      unless rule_def["name"].is_a?(String) && !rule_def["name"].strip.empty?
        raise "Rule 'name' must be a non-blank string. Found: '#{rule_def["name"]}' for rule identified as '#{rule_name_for_error}'."
      end

      if rule_def["is_early_exit_rule"] == true && !rule_def.key?("early_exit_threshold")
        raise "Rule '#{rule_name_for_error}' is an early_exit_rule but missing 'early_exit_threshold'."
      end

      confidence = rule_def["individual_confidence"]
      unless confidence.is_a?(Numeric) && confidence >= 0.0 && confidence <= 1.0
        raise "Rule '#{rule_name_for_error}' has invalid 'individual_confidence': #{confidence.inspect}. Must be a number between 0.0 and 1.0 inclusive."
      end

      if rule_def.key?("early_exit_threshold")
        threshold = rule_def["early_exit_threshold"]
        unless threshold.is_a?(Numeric) && threshold >= 0.0 && threshold <= 1.0
          raise "Rule '#{rule_name_for_error}' has invalid 'early_exit_threshold': #{threshold.inspect}. Must be a number between 0.0 and 1.0 inclusive."
        end
      end

      unless rule_def["patterns"].is_a?(Array)
        raise "Rule '#{rule_name_for_error}' must have 'patterns' as an array. Found: #{rule_def["patterns"].class}"
      end
    end
  end
end