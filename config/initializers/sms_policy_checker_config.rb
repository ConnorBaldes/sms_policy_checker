# frozen_string_literal: true

# Loads configurations for the SmsPolicyCheckerService at application boot.
begin
  # Ensure RuleLoader is loaded first as it's used to define LAYER1_RULES
  require_dependency Rails.root.join("app/helpers/sms_policy/rule_loader.rb").to_s
  Rails.logger.info "[SmsPolicyCheckerConfig] Explicitly loaded SmsPolicy::RuleLoader."
rescue LoadError => e
  Rails.logger.error "[SmsPolicyCheckerConfig] Failed to explicitly load SmsPolicy::RuleLoader: #{e.message}. Layer 1 rules may not load correctly."
end

begin
  require_dependency Rails.root.join("app/services/sms_policy_checker_service.rb").to_s
  Rails.logger.info "[SmsPolicyCheckerConfig] Explicitly loaded SmsPolicyCheckerService."
rescue LoadError => e
  Rails.logger.error "[SmsPolicyCheckerConfig] Failed to explicitly load SmsPolicyCheckerService: #{e.message}. Configuration constants might not be set on it."
end

# Define a module to namespace configuration loading logic, though not strictly necessary
# for a simple initializer, it can help organize if it grows.
module SmsPolicyCheckerApp
  module ConfigLoader
    CONFIG_BASE_PATH = Rails.root.join("config")

    def self.load_yaml_file(filename)
      path = CONFIG_BASE_PATH.join(filename)
      unless File.exist?(path)
        Rails.logger.error "[SmsPolicyCheckerConfig] Configuration file not found: #{path}"
        return nil # Or raise an error if the file is critical
      end
      YAML.safe_load(File.read(path), permitted_classes: [ Symbol, Regexp ], aliases: true)
    end

    # --- Load Layer 1 Rules ---
    begin
      rules_yaml_content = File.read(CONFIG_BASE_PATH.join("sms_policy_checker_rules.yml"))
      # Ensure SmsPolicy::RuleLoader is loaded before trying to use it.
      # If app/helpers isn"t in autoload_paths during initializers, you might need an explicit require.
      # For now, assuming Rails autoloading paths are configured to include app/helpers early enough,
      # or that SmsPolicy::RuleLoader has been explicitly required.
      if defined?(SmsPolicy::RuleLoader)
        LAYER1_RULES = SmsPolicy::RuleLoader.load_rules(rules_yaml_content).freeze
        Rails.logger.info "[SmsPolicyCheckerConfig DEBUG Initializer] Loaded LAYER1_RULES (names): #{LAYER1_RULES.map { |r| r['name'] }.inspect if LAYER1_RULES.is_a?(Array)}"
        Rails.logger.info "[SmsPolicyCheckerConfig DEBUG Initializer] First rule details: #{LAYER1_RULES.first.inspect if LAYER1_RULES.is_a?(Array) && !LAYER1_RULES.empty?}"
        Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded and compiled #{LAYER1_RULES.count} Layer 1 rules."
      else
        Rails.logger.error "[SmsPolicyCheckerConfig] SmsPolicy::RuleLoader not defined. Cannot load Layer 1 rules."
        LAYER1_RULES = [].freeze
      end
    rescue Errno::ENOENT # File not found
      Rails.logger.error "[SmsPolicyCheckerConfig] FAILED to load Layer 1 rules: sms_policy_checker_rules.yml not found."
      LAYER1_RULES = [].freeze
    rescue StandardError => e
      Rails.logger.error "[SmsPolicyCheckerConfig] FAILED to load Layer 1 rules: #{e.class} - #{e.message}\n#{e.backtrace.first(5).join("\n")}"
      LAYER1_RULES = [].freeze # Fallback to empty rules
      # Consider raising the error to halt boot if rules are critical:
      # raise "Critical Error: Could not load sms_policy_checker_rules.yml - #{e.message}"
    end

    # --- Load LLM Configuration ---
    begin
      LLM_CONFIG = load_yaml_file("sms_policy_checker_llm_config.yml")&.freeze || { "characteristics" => [] }.freeze
      if LLM_CONFIG["characteristics"].empty? && File.exist?(CONFIG_BASE_PATH.join("sms_policy_checker_llm_config.yml"))
         Rails.logger.warn "[SmsPolicyCheckerConfig] LLM configuration loaded, but 'characteristics' array is empty or file was problematic."
      elsif !LLM_CONFIG["characteristics"].empty?
        Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded LLM configuration for #{LLM_CONFIG["characteristics"].count} characteristics."
      else
        Rails.logger.warn "[SmsPolicyCheckerConfig] sms_policy_checker_llm_config.yml not found or empty. Using default empty LLM config."
      end
    rescue StandardError => e
      Rails.logger.error "[SmsPolicyCheckerConfig] FAILED to load LLM config: #{e.class} - #{e.message}"
      LLM_CONFIG = { "characteristics" => [] }.freeze # Fallback
    end

    # --- Load Thresholds ---
    begin
      THRESHOLDS = load_yaml_file("sms_policy_checker_thresholds.yml")&.freeze || {}.freeze
      required_threshold_keys = [ "FINAL_THRESHOLD_FLAG", "FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK", "CRITICAL_FAILURE_THRESHOLDS" ]
      missing_thresholds = required_threshold_keys.reject { |key| THRESHOLDS.key?(key) }

      if THRESHOLDS.empty? && File.exist?(CONFIG_BASE_PATH.join("sms_policy_checker_thresholds.yml"))
        Rails.logger.warn "[SmsPolicyCheckerConfig] Thresholds configuration loaded but seems empty or file was problematic."
      elsif !missing_thresholds.empty?
        Rails.logger.warn "[SmsPolicyCheckerConfig] Thresholds configuration is missing essential keys: #{missing_thresholds.join(", ")}. Using defaults for missing keys."
        # Provide safe defaults if keys are missing
        default_thresholds = {
          "FINAL_THRESHOLD_FLAG" => 0.99,
          "FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK" => 0.99,
          "CRITICAL_FAILURE_THRESHOLDS" => {}
        }
        THRESHOLDS = default_thresholds.merge(THRESHOLDS) # Merge loaded with defaults, loaded takes precedence
      elsif !THRESHOLDS.empty?
        Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded thresholds."
      else
         Rails.logger.warn "[SmsPolicyCheckerConfig] sms_policy_checker_thresholds.yml not found or empty. Using default empty thresholds."
         THRESHOLDS = { # Ensure critical_failure_thresholds is at least an empty hash
          "FINAL_THRESHOLD_FLAG" => 0.99,
          "FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK" => 0.99,
          "CRITICAL_FAILURE_THRESHOLDS" => {}
        }.freeze
      end
    rescue StandardError => e
      Rails.logger.error "[SmsPolicyCheckerConfig] FAILED to load thresholds: #{e.class} - #{e.message}"
      THRESHOLDS = {
          "FINAL_THRESHOLD_FLAG" => 0.99,
          "FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK" => 0.99,
          "CRITICAL_FAILURE_THRESHOLDS" => {}
        }.freeze # Fallback
    end

    # Make configurations available as constants within SmsPolicyCheckerService
    # This requires SmsPolicyCheckerService class to be loaded.
    # Rails autoloading should handle this. If not, ensure `app/services` is in `$LOAD_PATH`
    # and `SmsPolicyCheckerService` is loaded before this initializer, or use a different mechanism.
    if defined?(SmsPolicyCheckerService)
      SmsPolicyCheckerService.const_set("LAYER1_RULES", LAYER1_RULES)
      SmsPolicyCheckerService.const_set("LLM_CONFIG", LLM_CONFIG)
      SmsPolicyCheckerService.const_set("THRESHOLDS", THRESHOLDS)
      # Derived constant for convenience, ensuring CRITICAL_FAILURE_THRESHOLDS is always a hash
      critical_thresholds = THRESHOLDS.is_a?(Hash) ? THRESHOLDS.fetch("CRITICAL_FAILURE_THRESHOLDS", {}) : {}
      SmsPolicyCheckerService.const_set("CRITICAL_FAILURE_THRESHOLDS", critical_thresholds)

      Rails.logger.info "[SmsPolicyCheckerConfig] Configurations set as constants on SmsPolicyCheckerService."
    else
      Rails.logger.error "[SmsPolicyCheckerConfig] SmsPolicyCheckerService class not defined. Cannot set configuration constants on it."
      # You might store them in a global AppConfig module instead if the service class isn"t available yet.
      # Example:
      # module AppConfig; end
      # AppConfig.const_set("SMS_POLICY_LAYER1_RULES", LAYER1_RULES)
      # ... and then SmsPolicyCheckerService would reference AppConfig::SMS_POLICY_LAYER1_RULES
    end
  end
end
