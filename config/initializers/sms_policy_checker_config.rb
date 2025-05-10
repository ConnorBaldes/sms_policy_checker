# frozen_string_literal: true

# Loads configurations for the SmsPolicyCheckerService at application boot.
# This makes them available globally, e.g., via constants or a config object.

require_relative '../../app/helpers/sms_policy/rule_loader' # Ensure RuleLoader is available

module SmsPolicyCheckerConfig
  CONFIG_BASE_PATH = Rails.root.join('config')

  def self.load_config_file(filename)
    path = CONFIG_BASE_PATH.join(filename)
    raise "Configuration file not found: #{path}" unless File.exist?(path)
    YAML.safe_load(File.read(path), permitted_classes: [Symbol, Regexp], aliases: true)
  end

  # Load Layer 1 Rules and pre-compile them
  begin
    raw_rules_yaml = File.read(CONFIG_BASE_PATH.join('sms_policy_checker_rules.yml'))
    LAYER1_RULES = SmsPolicy::RuleLoader.load_rules(raw_rules_yaml).freeze
    Rails.logger.info "SmsPolicyChecker: Successfully loaded #{LAYER1_RULES.count} Layer 1 rules."
  rescue StandardError => e
    Rails.logger.error "SmsPolicyChecker: FAILED to load Layer 1 rules: #{e.message}"
    # Consider raising the error to halt boot if rules are critical, or set LAYER1_RULES to empty array
    LAYER1_RULES = [].freeze # Fallback to empty rules if loading fails
    # raise e # Uncomment to make application boot fail if rules are essential
  end

  # Load LLM Configuration
  begin
    LLM_CONFIG = load_config_file('sms_policy_checker_llm_config.yml').freeze
    # Perform basic validation if characteristics exist
    if LLM_CONFIG.nil? || !LLM_CONFIG.key?('characteristics') || !LLM_CONFIG['characteristics'].is_a?(Array)
        raise "LLM configuration is invalid or missing 'characteristics' array."
    end
    Rails.logger.info "SmsPolicyChecker: Successfully loaded LLM configuration for #{LLM_CONFIG['characteristics'].count} characteristics."
  rescue StandardError => e
    Rails.logger.error "SmsPolicyChecker: FAILED to load LLM config: #{e.message}"
    LLM_CONFIG = { 'characteristics' => [] }.freeze # Fallback
    # raise e
  end

  # Load Thresholds
  begin
    THRESHOLDS = load_config_file('sms_policy_checker_thresholds.yml').freeze
    # Validate essential thresholds
    required_thresholds = ['FINAL_THRESHOLD_FLAG', 'FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK', 'CRITICAL_FAILURE_THRESHOLDS']
    missing_thresholds = required_thresholds.reject { |key| THRESHOLDS.key?(key) }
    unless missing_thresholds.empty?
      raise "Thresholds configuration is missing essential keys: #{missing_thresholds.join(', ')}"
    end
    Rails.logger.info "SmsPolicyChecker: Successfully loaded thresholds."
  rescue StandardError => e
    Rails.logger.error "SmsPolicyChecker: FAILED to load thresholds: #{e.message}"
    # Provide default safe thresholds or raise error
    THRESHOLDS = {
      'FINAL_THRESHOLD_FLAG' => 0.99, # Very high, effectively disabling if load fails
      'FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK' => 0.99,
      'CRITICAL_FAILURE_THRESHOLDS' => {}
    }.freeze
    # raise e
  end

  # Make these available to the SmsPolicyCheckerService class,
  # e.g., by assigning them to constants within that class or a shared module.
  # This is one way; dependency injection or a dedicated config object are alternatives.
  SmsPolicyCheckerService.const_set('LAYER1_RULES', LAYER1_RULES) if defined?(SmsPolicyCheckerService)
  SmsPolicyCheckerService.const_set('LLM_CONFIG', LLM_CONFIG) if defined?(SmsPolicyCheckerService)
  SmsPolicyCheckerService.const_set('THRESHOLDS', THRESHOLDS) if defined?(SmsPolicyCheckerService)
  if defined?(SmsPolicyCheckerService) && THRESHOLDS.key?('CRITICAL_FAILURE_THRESHOLDS')
    SmsPolicyCheckerService.const_set('CRITICAL_FAILURE_THRESHOLDS', THRESHOLDS['CRITICAL_FAILURE_THRESHOLDS'])
  elsif defined?(SmsPolicyCheckerService)
     SmsPolicyCheckerService.const_set('CRITICAL_FAILURE_THRESHOLDS', {}) # Default empty
  end


end

# Ensure constants are set on SmsPolicyCheckerService if it's already loaded
# Or rely on Rails auto-loading order.
# A more robust way might be a singleton Config object that the service accesses.
