# config/initializers/sms_policy_checker_config.rb
# frozen_string_literal: true

# This initializer loads configurations for the SmsPolicyCheckerService at application boot.
# It aims to fail fast if critical configurations are missing or malformed.

begin
  # --- 1. Load Essential Dependencies ---
  # These are critical. If they don't load, the application cannot proceed.
  begin
    require_dependency Rails.root.join("app/helpers/sms_policy/rule_loader.rb").to_s
    Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded SmsPolicy::RuleLoader."
  rescue LoadError => e
    error_message = "[SmsPolicyCheckerConfig CRITICAL] Failed to load SmsPolicy::RuleLoader: #{e.message}. Layer 1 rules cannot be processed."
    Rails.logger.fatal error_message
    raise LoadError, error_message # Halt boot
  end

  begin
    require_dependency Rails.root.join("app/services/sms_policy_checker_service.rb").to_s
    Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded SmsPolicyCheckerService."
  rescue LoadError => e
    error_message = "[SmsPolicyCheckerConfig CRITICAL] Failed to load SmsPolicyCheckerService: #{e.message}. Configuration constants cannot be set."
    Rails.logger.fatal error_message
    raise LoadError, error_message # Halt boot
  end

  # --- 2. Define Configuration Loading Logic ---
  module SmsPolicyCheckerApp
    module ConfigLoader
      CONFIG_BASE_PATH = Rails.root.join("config")

      # Loads a YAML file.
      # Returns nil if the file does not exist.
      # Raises a critical error if the file exists but is malformed.
      def self.load_yaml_file(filename)
        path = CONFIG_BASE_PATH.join(filename)
        return nil unless File.exist?(path)

        begin
          # Using permitted_classes: [] for strict loading of only core Ruby types.
          # Add other classes like Time, Date explicitly if they are ever used in these YAMLs.
          # aliases: true allows use of YAML anchors/aliases.
          YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
        rescue Psych::SyntaxError => e
          critical_message = "[SmsPolicyCheckerConfig CRITICAL] Failed to parse YAML configuration file #{path}: #{e.message}"
          Rails.logger.fatal critical_message
          raise StandardError, critical_message # Halt boot for malformed YAML
        end
      end

      # --- Load Layer 1 Rules (Critical) ---
      begin
        rules_file_path = CONFIG_BASE_PATH.join("sms_policy_checker_rules.yml")
        unless File.exist?(rules_file_path)
          critical_message = "[SmsPolicyCheckerConfig CRITICAL] Layer 1 rules file not found: #{rules_file_path}"
          Rails.logger.fatal critical_message
          raise Errno::ENOENT, critical_message # Halt boot
        end
        rules_yaml_content = File.read(rules_file_path)
        # SmsPolicy::RuleLoader.load_rules will raise on internal parsing or validation errors.
        LAYER1_RULES_TEMP = SmsPolicy::RuleLoader.load_rules(rules_yaml_content).freeze

        Rails.logger.debug "[SmsPolicyCheckerConfig] Loaded LAYER1_RULES (names): #{LAYER1_RULES_TEMP.map { |r| r['name'] }.inspect if LAYER1_RULES_TEMP.is_a?(Array)}"
        Rails.logger.debug "[SmsPolicyCheckerConfig] First L1 rule details: #{LAYER1_RULES_TEMP.first.inspect if LAYER1_RULES_TEMP.is_a?(Array) && !LAYER1_RULES_TEMP.empty?}"
        Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded and compiled #{LAYER1_RULES_TEMP.count} Layer 1 rules."
      rescue StandardError => e # Catches errors from File.read or SmsPolicy::RuleLoader.load_rules
        critical_message = "[SmsPolicyCheckerConfig CRITICAL] Failed to load Layer 1 rules from #{rules_file_path}: #{e.class} - #{e.message}\nBacktrace: #{e.backtrace.first(5).join("\n")}"
        Rails.logger.fatal critical_message
        raise StandardError, critical_message # Halt boot
      end

      # --- Load LLM Configuration (File optional, but malformed file is critical) ---
      LLM_CONFIG_FROM_FILE = load_yaml_file("sms_policy_checker_llm_config.yml") # Raises on parse error
      LLM_CONFIG_TEMP = (LLM_CONFIG_FROM_FILE || { "characteristics" => [] }).freeze # Default if file not found

      if LLM_CONFIG_FROM_FILE.nil?
        Rails.logger.warn "[SmsPolicyCheckerConfig] sms_policy_checker_llm_config.yml not found. Using default empty LLM configuration."
      elsif LLM_CONFIG_TEMP["characteristics"].empty?
        Rails.logger.warn "[SmsPolicyCheckerConfig] LLM configuration loaded, but 'characteristics' array is empty."
      else
        Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded LLM configuration for #{LLM_CONFIG_TEMP["characteristics"].count} characteristics."
      end

      # --- Load Thresholds (File optional, but malformed file is critical) ---
      DEFAULT_THRESHOLDS = {
        "FINAL_THRESHOLD_FLAG" => 0.99, # Default if not specified in YAML
        "FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK" => 0.99, # Default if not specified
        "CRITICAL_FAILURE_THRESHOLDS" => {} # Default to empty hash
      }.freeze

      thresholds_from_file = load_yaml_file("sms_policy_checker_thresholds.yml") # Raises on parse error

      # Start with defaults, then deep_merge loaded values. Loaded values take precedence.
      # Ensures all keys in DEFAULT_THRESHOLDS are present.
      THRESHOLDS_TEMP = DEFAULT_THRESHOLDS.deep_merge(thresholds_from_file || {}).freeze

      # Ensure CRITICAL_FAILURE_THRESHOLDS is a hash, even if YAML tried to make it something else.
      unless THRESHOLDS_TEMP["CRITICAL_FAILURE_THRESHOLDS"].is_a?(Hash)
        Rails.logger.warn "[SmsPolicyCheckerConfig] CRITICAL_FAILURE_THRESHOLDS in thresholds file was not a Hash. Overriding with empty Hash. Check config file."
        # Re-create THRESHOLDS_TEMP with CRITICAL_FAILURE_THRESHOLDS as a Hash
        # This is a bit clunky; ideally, schema validation would catch this earlier if complex.
        # For now, directly ensure it's a hash.
        modifiable_thresholds = THRESHOLDS_TEMP.dup # Unfreeze for modification
        modifiable_thresholds["CRITICAL_FAILURE_THRESHOLDS"] = {} # Force it to be a hash
        THRESHOLDS_TEMP = modifiable_thresholds.freeze
      end

      if thresholds_from_file.nil?
        Rails.logger.warn "[SmsPolicyCheckerConfig] sms_policy_checker_thresholds.yml not found. Using default threshold values."
      else
        Rails.logger.info "[SmsPolicyCheckerConfig] Successfully loaded and merged thresholds."
        # Log if any of the main threshold keys were defaulted
        DEFAULT_THRESHOLDS.each_key do |key|
          unless thresholds_from_file.key?(key)
            Rails.logger.warn "[SmsPolicyCheckerConfig] Threshold key '#{key}' was not found in yml, using default: #{DEFAULT_THRESHOLDS[key]}"
          end
        end
      end
      Rails.logger.debug "[SmsPolicyCheckerConfig] Final Thresholds: #{THRESHOLDS_TEMP.inspect}"


      # --- 3. Assign Configurations to SmsPolicyCheckerService Constants ---
      # This step is critical. If SmsPolicyCheckerService isn't defined, we can't proceed.
      unless defined?(SmsPolicyCheckerService)
        critical_message = "[SmsPolicyCheckerConfig CRITICAL] SmsPolicyCheckerService class not defined when attempting to set configuration constants. This should have been caught by require_dependency."
        Rails.logger.fatal critical_message
        raise NameError, critical_message # Halt boot
      end

      SmsPolicyCheckerService.const_set("LAYER1_RULES", LAYER1_RULES_TEMP)
      SmsPolicyCheckerService.const_set("LLM_CONFIG", LLM_CONFIG_TEMP)
      SmsPolicyCheckerService.const_set("THRESHOLDS", THRESHOLDS_TEMP)
      # CRITICAL_FAILURE_THRESHOLDS is derived from THRESHOLDS inside SmsPolicyCheckerService or taken directly if defined:
      # It's already ensured to be a Hash within THRESHOLDS_TEMP by the logic above.
      SmsPolicyCheckerService.const_set("CRITICAL_FAILURE_THRESHOLDS", THRESHOLDS_TEMP.fetch("CRITICAL_FAILURE_THRESHOLDS", {}))

      Rails.logger.info "[SmsPolicyCheckerConfig] All configurations successfully loaded and set on SmsPolicyCheckerService."

    rescue StandardError => e
      # Catch any unexpected error during the ConfigLoader module's execution.
      critical_message = "[SmsPolicyCheckerConfig CRITICAL] An unexpected error occurred during configuration loading: #{e.class} - #{e.message}\nBacktrace: #{e.backtrace.first(10).join("\n")}"
      Rails.logger.fatal critical_message
      raise StandardError, critical_message # Halt boot
    end
  end

# Catch any exception during the entire initializer file execution, though specific critical errors should be raised explicitly.
rescue StandardError => e
  Rails.logger.fatal "[SmsPolicyCheckerConfig CRITICAL] Unrecoverable error during SmsPolicyCheckerConfig initialization: #{e.message}"
  # Depending on Rails version and load order, raising here might not always be caught by Rails' boot process
  # in a way that prevents server start, but it will log loudly.
  # For critical safety, the explicit raises within the module are more reliable for halting.
  raise
end