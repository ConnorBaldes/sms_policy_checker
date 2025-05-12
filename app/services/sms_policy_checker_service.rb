# app/services/sms_policy_checker_service.rb
# frozen_string_literal: true

require "yaml"
require "json"
require "uri"
# Ensure client classes are loaded (initializer should handle this generally)
# require_dependency Rails.root.join("app/clients/google/safe_browse_client.rb").to_s
# require_dependency Rails.root.join("app/clients/google/nl_client.rb").to_s
# require_dependency Rails.root.join("app/clients/google/gemini_client.rb").to_s

# == SmsPolicyCheckerService
#
# Service class responsible for analyzing SMS message content against a set of predefined
# policies and generating a compliance report. It operates in two main layers:
#
# Layer 1: Performs checks based on compiled regular expression rules. This layer
#          can trigger an "early exit" if a high-confidence violation is found.
# Layer 2: Utilizes Google's Generative AI (Gemini), Natural Language API, and
#          Safe Browse API to perform more nuanced analysis of the message against
#          various policy characteristics. This layer is only processed if Layer 1
#          does not trigger an early exit and if no critical API errors occur.
#
# The service can operate in a `:fallback_layer1_only` mode if critical errors
# occur during Layer 2 API interactions, ensuring that a result (based solely on
# Layer 1) is still provided.
#
# The final report includes a pass/fail result, a reason, a confidence score,
# details of any violations found, policy category scores, and potentially a
# rewrite suggestion if the message fails in full analysis mode.
#
# @example
#   report = SmsPolicyCheckerService.call("Check out this amazing offer: http://example.com/promo")
#   puts report[:result] # => :pass or :fail
#   puts report[:reason]
#   puts report[:violation_details]
#
class SmsPolicyCheckerService
  attr_reader :message_body, :pre_fetched_api_signals
  attr_accessor :message_analysis_report

  # Initializes a new instance of the SmsPolicyCheckerService.
  #
  # @param message_body [String] The SMS message content to be analyzed.
  def initialize(message_body)
    @message_body = message_body.to_s # Ensure it's a string
    @message_analysis_report = initialize_report
    @pre_fetched_api_signals = {}
    # Note: Client instances (SafeBrowse, NlClient, GeminiClient) are created on-demand in methods.
    # Consider memoized accessors if performance profiling indicates instantiation is a bottleneck
    # or if a single client instance needs to be shared across multiple method calls within
    # a single `SmsPolicyCheckerService` instance's lifecycle.
  end

  # Class-level convenience method to instantiate and call the service.
  #
  # @param message_body [String] The SMS message content to be analyzed.
  # @return [Hash] The analysis report. See {#call} for details on the report structure.
  # @see #call
  def self.call(message_body)
    new(message_body).call
  end

  # Executes the full SMS policy checking process.
  # This involves Layer 1 (regex-based) checks and, if applicable,
  # Layer 2 (LLM-based) analysis. It handles fallback logic if API
  # errors occur during Layer 2.
  #
  # @return [Hash] An analysis report with the following structure:
  #   - `:result` [Symbol] The overall outcome (`:pass` or `:fail`).
  #   - `:reason` [String] A human-readable reason for the result, often the
  #     name of the policy category that led to a failure or "Compliant".
  #   - `:confidence` [Float] A score (0.0 to 1.0+) indicating the confidence
  #     of the most significant finding. Higher values indicate stronger signals.
  #   - `:rewrite_suggestion` [String, Hash, nil] If the message failed and was
  #     processed in `:full_analysis` mode, this may contain a rewrite suggestion
  #     from the LLM. Can be a string if uncorrectable, or a hash with
  #     `general_fix_suggestions` and `literal_rewrite` if correctable.
  #   - `:processing_mode` [Symbol] Indicates the mode of processing
  #     (`:full_analysis` or `:fallback_layer1_only`).
  #   - `:policy_category_scores` [Hash<String, Float>] A hash where keys are
  #     policy category names (or characteristic names from Layer 2) and values
  #     are the highest confidence scores observed for that category.
  #   - `:violation_details` [Array<Hash>] A list of all specific rule matches
  #     or LLM characteristic evaluations, each with:
  #     - `:layer` [Integer] 1 or 2.
  #     - `:filter_type` [String] Name of the L1 rule or "Gemini:[CharacteristicName]" or "API_FALLBACK:[ErrorType]".
  #     - `:description` [String] Description of the rule or rationale from LLM.
  #     - `:matched_value` [String] The specific text that matched an L1 rule (or "N/A" for L2/fallback).
  #     - `:individual_confidence` [Float] Confidence of this specific detail.
  #     - `:policy_category` [String] The policy category this detail maps to.
  def call
    Rails.logger.info "[SmsPolicyCheckerService CALL] Started. Message snippet: '#{@message_body.truncate(100)}'"
    layer1_halted = process_layer1_rules
    Rails.logger.debug "[SmsPolicyCheckerService CALL] L1 processing done. Halted: #{layer1_halted}. Report L1 result: #{@message_analysis_report[:result]}"

    critical_l2_policy_failure_occurred = false
    unless layer1_halted
      if @message_analysis_report[:processing_mode] == :full_analysis
        Rails.logger.debug "[SmsPolicyCheckerService CALL] Entering L2 processing."
        l2_processing_outcome = process_layer2_llm_analysis # This now gathers API signals internally
        Rails.logger.info "[SmsPolicyCheckerService CALL] L2 processing outcome: #{l2_processing_outcome}."
        critical_l2_policy_failure_occurred = (l2_processing_outcome == :critical_policy_failure)
      else
        Rails.logger.info "[SmsPolicyCheckerService CALL] Skipping L2 because mode is: #{@message_analysis_report[:processing_mode]}"
      end
    end

    determine_final_result_if_not_concluded(layer1_halted, critical_l2_policy_failure_occurred)
    add_rewrite_suggestion_if_applicable

    Rails.logger.info "[SmsPolicyCheckerService CALL] Final report: result: #{@message_analysis_report[:result]}, reason: '#{@message_analysis_report[:reason]}', confidence: #{@message_analysis_report[:confidence].round(3)}, mode: #{@message_analysis_report[:processing_mode]}"
    @message_analysis_report
  end

  private

  # Initializes the structure for the analysis report.
  #
  # @private
  # @return [Hash] A hash with default values for the analysis report.
  #   See {#call} return value for the keys initialized here.
  def initialize_report
    {
      result: :pass, reason: "Compliant", confidence: 0.0,
      rewrite_suggestion: nil, processing_mode: :full_analysis,
      policy_category_scores: {}, violation_details: []
    }
  end

  # Processes the message against Layer 1 rules (typically regex-based).
  # It populates violation details and policy category scores in the
  # `@message_analysis_report`. If an "early exit" rule is met with
  # sufficient confidence, it sets the report to fail and halts further Layer 1
  # processing.
  #
  # @private
  # @return [Boolean] `true` if processing was halted due to an early exit rule,
  #   `false` otherwise.
  # @note Relies on `SmsPolicyCheckerService::LAYER1_RULES` constant being loaded
  #   and correctly formatted.
  def process_layer1_rules
    unless defined?(SmsPolicyCheckerService::LAYER1_RULES) && SmsPolicyCheckerService::LAYER1_RULES.is_a?(Array)
      Rails.logger.error "[SmsPolicyCheckerService L1] CRITICAL: LAYER1_RULES not loaded or not an array. Skipping Layer 1."
      return false # No rules to process, so not halted by a rule.
    end

    processing_halted = false
    SmsPolicyCheckerService::LAYER1_RULES.each do |rule|
      # Config integrity check: ensure compiled_patterns is an array
      unless rule["compiled_patterns"].is_a?(Array)
        Rails.logger.warn "[SmsPolicyCheckerService L1] Skipping rule '#{rule['name']}' due to missing or invalid 'compiled_patterns'."
        next
      end

      rule["compiled_patterns"].each do |pattern|
        # Config integrity check: ensure pattern is a Regexp
        unless pattern.is_a?(Regexp)
          Rails.logger.warn "[SmsPolicyCheckerService L1] Skipping invalid pattern in rule '#{rule['name']}' (not a Regexp)."
          next
        end

        # Assignment in condition is intentional for efficiency (matching can be frequent)
        if (match_data = pattern.match(@message_body))
          add_l1_violation_detail(rule, match_data[0])
          if rule["is_early_exit_rule"] && rule["individual_confidence"].to_f >= rule["early_exit_threshold"].to_f
            set_early_exit_failure(rule)
            processing_halted = true
            break # Stop processing patterns for this rule
          end
          break # Stop processing patterns for this rule as one has matched
        end
      end
      break if processing_halted # Stop processing further rules if halted
    end
    processing_halted
  end

  # Adds a violation detail entry to the report for a Layer 1 rule match.
  # Also updates the maximum score for the associated policy category.
  #
  # @private
  # @param rule [Hash] The Layer 1 rule configuration hash that was matched.
  #   Expected keys: "name", "description", "individual_confidence", "mapped_policy_category".
  # @param matched_value [String] The portion of the message body that matched the rule's pattern.
  # @return [void]
  def add_l1_violation_detail(rule, matched_value)
    category = rule["mapped_policy_category"].to_s
    current_score = rule["individual_confidence"].to_f
    detail = {
      layer: 1, filter_type: rule["name"].to_s, description: rule["description"].to_s,
      matched_value: matched_value, individual_confidence: current_score,
      policy_category: category
    }
    @message_analysis_report[:violation_details] << detail
    existing_score = @message_analysis_report[:policy_category_scores][category].to_f
    @message_analysis_report[:policy_category_scores][category] = [existing_score, current_score].max
  end

  # Updates the analysis report to reflect an early exit failure based on a Layer 1 rule.
  # Sets the result to `:fail`, updates confidence, and sets the reason.
  #
  # @private
  # @param rule [Hash] The Layer 1 rule configuration hash that triggered the early exit.
  #   Expected keys: "name", "individual_confidence", "mapped_policy_category".
  # @return [void]
  def set_early_exit_failure(rule)
    category = rule["mapped_policy_category"].to_s
    current_score = rule["individual_confidence"].to_f
    @message_analysis_report[:result] = :fail
    @message_analysis_report[:confidence] = current_score
    @message_analysis_report[:reason] = if @message_analysis_report[:processing_mode] == :fallback_layer1_only
                                          "Fallback: Early Exit - Violation Category: #{category}"
                                        else
                                          "Early Exit - Violation Category: #{category}"
                                        end

    Rails.logger.info "[SmsPolicyCheckerService L1] Early Exit triggered by rule '#{rule['name']}'. Reason: #{@message_analysis_report[:reason]}. Confidence: #{current_score}"
  end

  # Extracts all HTTP and HTTPS URLs from the message body.
  #
  # @private
  # @return [Array<String>] An array of unique URLs found in the message.
  #   Returns an empty array if no URLs are found.
  #   Logs an error and returns an empty array if `URI.extract` raises an exception
  #   or if `message_body` is not suitable for extraction.
  def extract_urls_from_message_body
    Rails.logger.debug "[SmsPolicyCheckerService EXTRACT_URLS] For: '#{@message_body.truncate(50)}'"
    urls = []
    # URI.extract can be slow or error-prone with very large/malformed strings.
    # Ensure message_body is a string and not excessively long if performance issues arise.
    return urls unless @message_body.is_a?(String) && @message_body.length < 10_000 # Arbitrary sanity length limit

    begin
      urls = URI.extract(@message_body, ["http", "https"]).uniq
    rescue StandardError => e
      Rails.logger.error "[SmsPolicyCheckerService EXTRACT_URLS] Error during URI.extract: #{e.message} for message: '#{@message_body.truncate(50)}'"
      urls = [] # Ensure urls is an empty array on error
    end
    Rails.logger.debug "[SmsPolicyCheckerService EXTRACT_URLS] Found: #{urls.inspect}"
    urls
  end

  # Collects signals from auxiliary APIs (Safe Browse, Natural Language API for entities and moderation).
  # The results, or error information if calls fail, are stored in `@pre_fetched_api_signals`.
  # If any client instantiation or call fails catastrophically (raises an exception),
  # an error hash is stored for that signal.
  #
  # @private
  # @return [void] Modifies `@pre_fetched_api_signals` in place.
  # @note This method makes network calls to external services.
  def gather_auxiliary_api_signals
    Rails.logger.debug "[SmsPolicyCheckerService GATHER_SIGNALS] Starting."
    @pre_fetched_api_signals = {} # Reset pre_fetched_api_signals
    @pre_fetched_api_signals[:url_list] = extract_urls_from_message_body
    @pre_fetched_api_signals[:urls_present] = @pre_fetched_api_signals[:url_list].any?

    fetch_safebrowse_signals
    fetch_nl_entities_signals
    fetch_nl_moderation_signals

    Rails.logger.debug "[SmsPolicyCheckerService GATHER_SIGNALS] Finished. Signals: #{@pre_fetched_api_signals.inspect}"
  end

  # Fetches signals from Google Safe Browse API.
  # Stores results or error information in `@pre_fetched_api_signals[:safe_browse_result]`.
  # @private
  # @return [void]
  def fetch_safebrowse_signals
    if @pre_fetched_api_signals[:urls_present]
      begin
        sb_client = Google::SafeBrowseClient.new
        response = sb_client.find_threat_matches(@pre_fetched_api_signals[:url_list])
        if response&.dig("error")
          error_message = response['error'].is_a?(Hash) ? response['error']['message'] : response['error'].to_s
          Rails.logger.warn "[SmsPolicyCheckerService GATHER_SIGNALS] SafeBrowseClient#find_threat_matches API Error: #{error_message}"
          @pre_fetched_api_signals[:safe_browse_result] = { "matches" => [], "error" => "[Google::SafeBrowseClient#find_threat_matches] API Error: #{error_message.truncate(150)}" }
        else
          @pre_fetched_api_signals[:safe_browse_result] = response || { "matches": [] }
          Rails.logger.info "[SmsPolicyCheckerService GATHER_SIGNALS] SafeBrowse check done. Matches found: #{@pre_fetched_api_signals[:safe_browse_result]['matches']&.any? || false}"
        end
      rescue StandardError => e
        Rails.logger.error "[SmsPolicyCheckerService GATHER_SIGNALS] Google::SafeBrowseClient#find_threat_matches Invocation Error: #{e.class} - #{e.message}"
        @pre_fetched_api_signals[:safe_browse_result] = { "matches" => [], "error" => "[Google::SafeBrowseClient#find_threat_matches] Invocation Error: #{e.message.truncate(100)}" }
      end
    else
      @pre_fetched_api_signals[:safe_browse_result] = { "matches": [] }
    end
  end

  # Fetches entity analysis signals from Google Natural Language API.
  # Stores results or error information in `@pre_fetched_api_signals[:nl_api_result]`.
  # @private
  # @return [void]
  def fetch_nl_entities_signals
    begin
      nl_client = Google::NlClient.new
      response = nl_client.analyze_entities(@message_body)
      if response&.dig("error")
        error_message = response['error'].is_a?(Hash) ? response['error']['message'] : response['error'].to_s
        Rails.logger.warn "[SmsPolicyCheckerService GATHER_SIGNALS] NlClient#analyze_entities API Error: #{error_message}"
        @pre_fetched_api_signals[:nl_api_result] = { "entities" => [], "error" => "[Google::NlClient#analyze_entities] API Error: #{error_message.truncate(150)}", "languageCode" => "und", "languageSupported" => false }
      else
        @pre_fetched_api_signals[:nl_api_result] = response || { "entities" => [], "languageCode" => "und", "languageSupported" => false }
        Rails.logger.info "[SmsPolicyCheckerService GATHER_SIGNALS] NL Entities check done. Entities found: #{@pre_fetched_api_signals[:nl_api_result]['entities']&.any? || false}"
      end
    rescue StandardError => e
      Rails.logger.error "[SmsPolicyCheckerService GATHER_SIGNALS] Google::NlClient#analyze_entities Invocation Error: #{e.class} - #{e.message}"
      @pre_fetched_api_signals[:nl_api_result] = { "entities" => [], "error" => "[Google::NlClient#analyze_entities] Invocation Error: #{e.message.truncate(100)}", "languageCode" => "und", "languageSupported" => false }
    end
  end

  # Fetches text moderation signals from Google Natural Language API.
  # Stores results or error information in `@pre_fetched_api_signals[:moderation_result]`.
  # @private
  # @return [void]
  def fetch_nl_moderation_signals
    begin
      nl_client = Google::NlClient.new # New instance, could be memoized if NlClient is shareable
      response = nl_client.moderate_text(@message_body)
      if response&.dig("error")
        error_message = response['error'].is_a?(Hash) ? response['error']['message'] : response['error'].to_s
        Rails.logger.warn "[SmsPolicyCheckerService GATHER_SIGNALS] NlClient#moderate_text API Error: #{error_message}"
        @pre_fetched_api_signals[:moderation_result] = { "moderationCategories" => [], "error" => "[Google::NlClient#moderate_text] API Error: #{error_message.truncate(150)}" }
      else
        @pre_fetched_api_signals[:moderation_result] = response || { "moderationCategories" => [] }
        Rails.logger.info "[SmsPolicyCheckerService GATHER_SIGNALS] NL ModerateText check done. Categories found: #{@pre_fetched_api_signals[:moderation_result]['moderationCategories']&.any? || false}"
      end
    rescue StandardError => e
      Rails.logger.error "[SmsPolicyCheckerService GATHER_SIGNALS] Google::NlClient#moderate_text Invocation Error: #{e.class} - #{e.message}"
      @pre_fetched_api_signals[:moderation_result] = { "moderationCategories" => [], "error" => "[Google::NlClient#moderate_text] Invocation Error: #{e.message.truncate(100)}" }
    end
  end

  # Constructs the prompt to be sent to the Gemini LLM for a specific policy characteristic.
  # It uses a template from the characteristic's configuration and populates placeholders
  # with the message body and summaries of pre-fetched API signals.
  #
  # @private
  # @param characteristic_config [Hash] The configuration for the LLM characteristic.
  #   Expected keys: "prompt_template", "name", "knowledge_source_context".
  # @param pre_fetched_signals [Hash] A hash containing data gathered by {#gather_auxiliary_api_signals}.
  #   Expected keys: `:urls_present`, `:safe_browse_result`, `:nl_api_result`, `:moderation_result`.
  # @return [String] The fully constructed prompt text.
  def build_gemini_prompt(characteristic_config, pre_fetched_signals)
    template = characteristic_config["prompt_template"].to_s
    placeholders = {
      message_body: @message_body, # Already ensured to be a string
      characteristic_name: characteristic_config["name"].to_s,
      policy_context_snippet: characteristic_config["knowledge_source_context"].to_s,
      safe_browse_results: summarize_safe_browse_for_prompt(pre_fetched_signals),
      nl_entities: summarize_nl_entities_for_prompt(pre_fetched_signals),
      moderation_signals: summarize_nl_moderation_for_prompt(pre_fetched_signals),
      perspective_scores: "Perspective API not used; see Text Moderation signals." # Static placeholder
    }

    prompt = template
    placeholders.each do |key, value|
      prompt = prompt.gsub(/%\{#{key}\}/, value.to_s) # Ensure value is string
    end

    # This log can be very verbose. Keep at DEBUG or remove if not frequently needed.
    # Rails.logger.debug "[SmsPolicyCheckerService PROMPT for '#{characteristic_config['name']}'] (first 200 chars):\n#{prompt.truncate(200)}"
    prompt
  end

  # Generates a summary string for Safe Browse results to be used in prompts.
  # @private
  # @param signals [Hash] The pre_fetched_api_signals hash.
  # @return [String] A textual summary of Safe Browse results.
  def summarize_safe_browse_for_prompt(signals)
    return "N/A (No URLs in message)" unless signals[:urls_present]

    sb_res = signals[:safe_browse_result]
    if sb_res&.dig("error")
      "Safe Browse data unavailable: #{sb_res['error']}"
    elsif sb_res&.dig("matches")&.any?
      "Flagged by Safe Browse: " + sb_res["matches"].map { |m| "#{m['threatType']} for #{m.dig('threat', 'url')}" }.join("; ")
    else
      "No threats found by Safe Browse for present URLs."
    end
  end

  # Generates a summary string for Natural Language Entities results to be used in prompts.
  # @private
  # @param signals [Hash] The pre_fetched_api_signals hash.
  # @return [String] A textual summary of NL Entities results.
  def summarize_nl_entities_for_prompt(signals)
    nl_data = signals[:nl_api_result]
    return "N/A (NL API data missing)" unless nl_data

    if nl_data["error"]
      "NL Entity API data unavailable: #{nl_data["error"]}"
    elsif nl_data["entities"].is_a?(Array) && nl_data["entities"].any?
      "Detected Entities: " + nl_data["entities"].first(5).map { |e| "#{e['name']} (Type: #{e['type']})" }.join("; ")
    else
      "No notable entities detected by NL API."
    end
  end

  # Generates a summary string for Text Moderation results to be used in prompts.
  # @private
  # @param signals [Hash] The pre_fetched_api_signals hash.
  # @return [String] A textual summary of Text Moderation results.
  def summarize_nl_moderation_for_prompt(signals)
    mod_data = signals[:moderation_result]
    return "N/A (Moderation API data missing)" unless mod_data

    if mod_data["error"]
      "Text Moderation API data unavailable: #{mod_data["error"]}"
    elsif mod_data["moderationCategories"].is_a?(Array) && mod_data["moderationCategories"].any?
      # Filter for categories with confidence >= 0.5 (or adjust as needed)
      flagged_cats = mod_data["moderationCategories"].select { |cat| cat["confidence"].to_f >= 0.5 }
      if flagged_cats.any?
        "Text Moderation signals: " + flagged_cats.map do |cat|
          cat_name = cat["name"].to_s.split("/").last # Get the last part of the category path
          severity_info = cat["severity"] ? " (Severity: #{cat["severity"].to_f.round(2)})" : ""
          "#{cat_name} (Confidence: #{cat["confidence"].to_f.round(2)}#{severity_info})"
        end.join("; ")
      else
        "No significant moderation categories flagged by NL API (threshold 0.5)."
      end
    else
      "No moderation categories reported by NL API."
    end
  end

  # Manages the Layer 2 analysis using the Gemini LLM for various policy characteristics.
  # It first gathers auxiliary API signals. Then, for each relevant characteristic,
  # it builds a prompt, calls the Gemini client, and processes the response.
  # If critical API errors occur (e.g., Gemini call failure or malformed response),
  # it triggers a fallback to Layer 1 only processing.
  # If a characteristic evaluation meets a critical failure threshold, processing stops
  # and a critical policy failure is recorded.
  #
  # @private
  # @return [Symbol]
  #   - `:ok` if L2 processing completed without critical LLM failures or API errors forcing fallback.
  #   - `:api_error_triggered_fallback` if an API error caused a switch to `:fallback_layer1_only` mode.
  #   - `:critical_policy_failure` if an LLM evaluation exceeded a critical threshold for a characteristic.
  # @note Relies on `SmsPolicyCheckerService::LLM_CONFIG` and
  #   `SmsPolicyCheckerService::CRITICAL_FAILURE_THRESHOLDS` constants.
  def process_layer2_llm_analysis
    Rails.logger.debug "[SmsPolicyCheckerService L2_PROCESS] Starting Layer 2 analysis."
    gather_auxiliary_api_signals # Gather fresh signals for L2

    # If API signal gathering itself led to a fallback scenario (e.g., via a yet-to-be-implemented global error handler)
    return :api_error_triggered_fallback if @message_analysis_report[:processing_mode] == :fallback_layer1_only

    all_characteristics = SmsPolicyCheckerService::LLM_CONFIG&.fetch("characteristics", [])
    unless all_characteristics.is_a?(Array) && all_characteristics.any?
      Rails.logger.warn "[SmsPolicyCheckerService L2_PROCESS] No LLM characteristics configured or LLM_CONFIG is invalid. Skipping L2."
      return :ok # No characteristics to process.
    end

    # Defines the specific set of policy characteristics to be evaluated by the LLM.
    # These characteristics are based on the defined scope of policy coverage for this service.
    characteristics_to_process_names = [
      "MisleadingSenderIdentity",
      "FalseOrInaccurateContent",
      "HatefulContent",
      "ServiceInterferenceOrFilterEvasion",
      "SHAFT_Sex_AdultContent",
      "SHAFT_Alcohol_ProhibitedPromotion",
      "SHAFT_Firearms_IllegalPromotion",
      "SHAFT_Tobacco_ProhibitedPromotion",
      "ProhibitedSubstances_CannabisCBDKratom",
      "RegulatedPharmaceuticals_PrescriptionOffers",
      "FraudulentOrMaliciousContent",
      "HighRiskFinancialServices",
      "ProhibitedAffiliateMarketing",
      "RestrictedDebtCollection",
      "GetRichQuickSchemes",
      "GamblingPromotions",
      "PhishingAndDeceptiveURLs",
      "ProhibitedPublicURLShorteners",
      "AdvancedContentEvasionTactics"
    ]
    characteristics_to_evaluate = all_characteristics.select { |c| characteristics_to_process_names.include?(c["name"]) }

    if characteristics_to_evaluate.empty?
      Rails.logger.info "[SmsPolicyCheckerService L2_PROCESS] No applicable characteristics found for evaluation after filtering."
      return :ok
    end

    Rails.logger.info "[SmsPolicyCheckerService L2_PROCESS] Will evaluate #{characteristics_to_evaluate.count} L2 characteristics."
    gemini_client = Google::GeminiClient.new # Consider memoization

    characteristics_to_evaluate.each do |char_config|
      # Check for fallback mode at the start of each characteristic processing
      if @message_analysis_report[:processing_mode] == :fallback_layer1_only
        Rails.logger.warn "[SmsPolicyCheckerService L2_PROCESS] Fallback triggered mid-loop. Stopping further L2 characteristic processing."
        return :api_error_triggered_fallback # Exit L2 processing loop
      end

      outcome = process_single_characteristic(char_config, gemini_client)
      # If a single characteristic processing leads to fallback or critical failure, propagate that outcome.
      return outcome if outcome == :api_error_triggered_fallback || outcome == :critical_policy_failure
    end

    :ok # All relevant characteristics processed without triggering early exit from L2.
  end

  # Processes a single LLM characteristic: determines relevancy, calls Gemini, and handles response.
  # @private
  # @param char_config [Hash] Configuration for the characteristic.
  # @param gemini_client [Google::GeminiClient] Instance of the Gemini client.
  # @return [Symbol] `:ok`, `:api_error_triggered_fallback`, or `:critical_policy_failure`.
  def process_single_characteristic(char_config, gemini_client)
    characteristic_name = char_config["name"].to_s
    unless determine_characteristic_relevancy(char_config)
      Rails.logger.info "[SmsPolicyCheckerService L2_PROCESS] Skipped (relevancy): '#{characteristic_name}'"
      return :ok # Not relevant, but not an error state for L2 processing itself.
    end

    Rails.logger.info "[SmsPolicyCheckerService L2_PROCESS] Processing relevant characteristic: '#{characteristic_name}'"
    prompt_text = build_gemini_prompt(char_config, @pre_fetched_api_signals)
    gemini_response = gemini_client.analyze_characteristic(prompt_text)

    if gemini_response&.dig("error")
      error_details = gemini_response['error'].is_a?(Hash) ? gemini_response['error']['message'] : gemini_response['error'].to_s
      Rails.logger.error "[SmsPolicyCheckerService L2_GEMINI_ERROR] for '#{characteristic_name}': #{error_details}"
      handle_api_errors_and_fallback(:gemini_call_failed, characteristic_name: characteristic_name, error_message: error_details)
      return :api_error_triggered_fallback
    elsif !(gemini_response && gemini_response.key?("confidence_score") && gemini_response.key?("rationale"))
      Rails.logger.error "[SmsPolicyCheckerService L2_GEMINI_ERROR] Malformed response for '#{characteristic_name}': #{gemini_response.inspect.truncate(500)}"
      handle_api_errors_and_fallback(:gemini_response_malformed, characteristic_name: characteristic_name, response: gemini_response.inspect.truncate(500))
      return :api_error_triggered_fallback
    end

    Rails.logger.info "[SmsPolicyCheckerService L2_GEMINI_SUCCESS] for '#{characteristic_name}'. Score: #{gemini_response['confidence_score']}"
    llm_confidence = gemini_response["confidence_score"].to_f
    llm_rationale = gemini_response["rationale"].to_s
    add_l2_violation_detail(characteristic_name, llm_rationale, llm_confidence)

    critical_threshold_value = SmsPolicyCheckerService::CRITICAL_FAILURE_THRESHOLDS&.dig(characteristic_name)
    if critical_threshold_value && llm_confidence >= critical_threshold_value.to_f
      set_critical_l2_failure(characteristic_name, llm_confidence)
      return :critical_policy_failure
    end
    :ok # Processed successfully
  end


  # Adds a detail entry to the report for a Layer 2 LLM characteristic evaluation.
  # Also updates the maximum score for that characteristic in policy_category_scores.
  #
  # @private
  # @param characteristic_name [String] The name of the policy characteristic evaluated.
  # @param rationale [String] The rationale provided by the LLM for its assessment.
  # @param confidence [Float] The confidence score (0.0-1.0+) provided by the LLM.
  # @return [void]
  def add_l2_violation_detail(characteristic_name, rationale, confidence)
    detail = {
      layer: 2, filter_type: "Gemini:#{characteristic_name}",
      description: rationale, matched_value: "N/A", # Matched value is not applicable for L2 in the same way as L1
      individual_confidence: confidence, policy_category: characteristic_name
    }
    @message_analysis_report[:violation_details] << detail
    existing_score = @message_analysis_report[:policy_category_scores][characteristic_name].to_f
    @message_analysis_report[:policy_category_scores][characteristic_name] = [existing_score, confidence].max
    Rails.logger.debug "[SmsPolicyCheckerService L2_SCORES] Updated score for '#{characteristic_name}' to: #{@message_analysis_report[:policy_category_scores][characteristic_name]}"
  end

  # Updates the analysis report to reflect a critical failure based on a Layer 2
  # LLM characteristic evaluation that met or exceeded its critical threshold.
  # Sets the result to `:fail`, updates overall confidence, and sets the reason
  # to the characteristic name.
  #
  # @private
  # @param characteristic_name [String] The name of the characteristic that caused the critical failure.
  # @param confidence [Float] The confidence score from the LLM for this characteristic.
  # @return [void]
  def set_critical_l2_failure(characteristic_name, confidence)
    Rails.logger.warn "[SmsPolicyCheckerService L2_CRITICAL] Critical failure for '#{characteristic_name}'. Score: #{confidence}"
    @message_analysis_report[:result] = :fail
    @message_analysis_report[:confidence] = confidence.to_f
    @message_analysis_report[:reason] = characteristic_name # For critical L2, the characteristic is the direct reason
  end

  # Determines if a given LLM characteristic is relevant for the current message
  # based on "relevancy_skip_conditions" in its configuration.
  # For example, a characteristic related to URL safety might be skipped if no URLs
  # are present in the message.
  #
  # @private
  # @param char_config [Hash] The configuration hash for the characteristic.
  #   May contain a "relevancy_skip_conditions" array.
  # @return [Boolean] `true` if the characteristic is deemed relevant for processing,
  #   `false` if it should be skipped.
  def determine_characteristic_relevancy(char_config)
    is_relevant = true # Default to relevant
    skip_conditions = char_config.fetch("relevancy_skip_conditions", [])
    return true unless skip_conditions.is_a?(Array) && skip_conditions.any? # No conditions, so relevant

    skip_conditions.each do |condition|
      condition_type = condition["type"]
      case condition_type
      when "skip_if_no_urls"
        is_relevant = false if !@pre_fetched_api_signals[:urls_present] # Invert logic: skip if no URLs means relevant only if URLs ARE present
        Rails.logger.debug "[SmsPolicyCheckerService RELEVANCY] For '#{char_config['name']}': condition 'skip_if_no_urls', urls_present: #{@pre_fetched_api_signals[:urls_present]}. Now relevant: #{is_relevant}"
      when "skip_if_no_specific_entities"
        nl_data = @pre_fetched_api_signals[:nl_api_result]
        # Only proceed if NL call was successful and entities data is available
        if nl_data && (nl_data["error"].nil? || nl_data["error"].empty?) && nl_data["entities"].is_a?(Array)
          required_entity_type = condition["entity_type"].to_s.upcase
          found_entities = nl_data["entities"].select { |e| e["type"].to_s.upcase == required_entity_type }
          is_relevant = false if found_entities.empty? # Skip if no such entities found
          Rails.logger.debug "[SmsPolicyCheckerService RELEVANCY] For '#{char_config['name']}': entity_type '#{required_entity_type}', found: #{found_entities.any?}. Now relevant: #{is_relevant}"
        else
          # If NL data is unavailable, we cannot satisfy a "skip_if_no_specific_entities" condition based on absence.
          # Defaulting to relevant might be risky if the entity is crucial for the characteristic.
          # However, if we skip, we might miss violations.
          # Current behavior: assume relevant if dependent data is missing, as the characteristic might have other signals.
          Rails.logger.debug "[SmsPolicyCheckerService RELEVANCY] For '#{char_config['name']}': Cannot evaluate 'skip_if_no_specific_entities' due to NL API data issue. Defaulting to relevant."
        end
      else
        Rails.logger.warn "[SmsPolicyCheckerService RELEVANCY] Unknown skip_condition type: '#{condition_type}' for '#{char_config['name']}'"
      end
      break unless is_relevant # If any condition makes it irrelevant, stop checking others
    end
    is_relevant
  end

  # Determines the final result and reason if not already concluded by L1 early exit or L2 critical failure.
  # @private
  # @param layer1_halted [Boolean] Whether Layer 1 processing was halted.
  # @param critical_l2_failure_occurred [Boolean] Whether a critical L2 policy failure occurred.
  # @return [void] Modifies `@message_analysis_report` in place.
  def determine_final_result_if_not_concluded(layer1_halted, critical_l2_failure_occurred)
    # If L1 halted or L2 had a critical failure, the result, reason, and confidence are already set.
    if layer1_halted
      Rails.logger.info "[SmsPolicyCheckerService FINAL_RESULT] L1 halted, result already determined: #{@message_analysis_report[:reason]}"
      return
    elsif critical_l2_failure_occurred
      Rails.logger.info "[SmsPolicyCheckerService FINAL_RESULT] Critical L2 failure, result already determined: #{@message_analysis_report[:reason]}"
      return
    end

    Rails.logger.debug "[SmsPolicyCheckerService FINAL_RESULT] Determining final result based on aggregated scores. Mode: #{@message_analysis_report[:processing_mode]}"
    determine_final_result_and_reason
  end


  # Calculates the final `:result` (:pass or :fail), `:reason`, and `:confidence`
  # for the overall analysis report based on aggregated scores. This is called if no
  # early exit (L1) or critical L2 failure has already determined the outcome.
  # It uses the highest score from `@message_analysis_report[:policy_category_scores]`
  # and compares it against configured thresholds.
  #
  # @private
  # @return [void] Modifies `@message_analysis_report` in place.
  # @note Relies on `SmsPolicyCheckerService::THRESHOLDS` constants.
  #   It's expected that these constants are loaded with appropriate numeric values
  #   (potentially with defaults) by an initializer.
  def determine_final_result_and_reason
    max_observed_score = 0.0
    leading_category_for_fail = nil

    (@message_analysis_report[:policy_category_scores] || {}).each do |category, score|
      score_f = score.to_f
      if score_f > max_observed_score
        max_observed_score = score_f
        leading_category_for_fail = category
      end
    end
    @message_analysis_report[:confidence] = max_observed_score

    # Assumes THRESHOLDS are loaded by initializer and are Floats.
    # The initializer should provide defaults if keys are missing from config files.
    final_threshold_key = if @message_analysis_report[:processing_mode] == :fallback_layer1_only
                            "FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK"
                          else
                            "FINAL_THRESHOLD_FLAG"
                          end
    threshold_to_use = SmsPolicyCheckerService::THRESHOLDS[final_threshold_key].to_f

    if max_observed_score >= threshold_to_use && leading_category_for_fail
      @message_analysis_report[:result] = :fail
      @message_analysis_report[:reason] = if @message_analysis_report[:processing_mode] == :fallback_layer1_only
                                            "Fallback: Layer 1 Threshold Exceeded - Violation Category: #{leading_category_for_fail}"
                                          else
                                            leading_category_for_fail # The category itself is the reason
                                          end
    else
      # If result is not already :fail (e.g. from an L1 early exit not caught by the `determine_final_result_if_not_concluded` guard, though unlikely)
      # or if it's still the initial :pass state.
      if @message_analysis_report[:result] != :fail
        @message_analysis_report[:result] = :pass
        @message_analysis_report[:reason] = if @message_analysis_report[:processing_mode] == :fallback_layer1_only
                                              "Fallback: Compliant."
                                            else
                                              "Compliant"
                                            end
        # Confidence remains max_observed_score, which might be low for a pass, which is fine.
      end
    end
    Rails.logger.info "[SmsPolicyCheckerService FINAL_RESULT] Based on threshold '#{threshold_to_use}': Result: #{@message_analysis_report[:result]}, Reason: #{@message_analysis_report[:reason]}, Score: #{max_observed_score.round(3)}"
  end

  # Adds a rewrite suggestion to the report if the message failed in full analysis mode.
  # @private
  # @return [void] Modifies `@message_analysis_report[:rewrite_suggestion]`
  def add_rewrite_suggestion_if_applicable
    if @message_analysis_report[:result] == :fail && @message_analysis_report[:processing_mode] == :full_analysis
      Rails.logger.info "[SmsPolicyCheckerService REWRITE] Message failed in full_analysis, attempting rewrite suggestion."
      @message_analysis_report[:rewrite_suggestion] = generate_rewrite_suggestion
      Rails.logger.debug "[SmsPolicyCheckerService REWRITE] Rewrite suggestion result: #{@message_analysis_report[:rewrite_suggestion].inspect.truncate(200)}"
    else
      @message_analysis_report[:rewrite_suggestion] = nil
    end
  end

  # Manages the transition to `:fallback_layer1_only` processing mode when a
  # significant API error occurs during Layer 2. It updates the report's
  # processing mode and adds a specific violation detail indicating the fallback.
  #
  # @private
  # @param error_type [Symbol] A symbol identifying the type of API error
  #   (e.g., `:gemini_call_failed`, `:gemini_response_malformed`).
  # @param options [Hash] Additional context about the error.
  # @option options [String] :characteristic_name The name of the characteristic being processed when the error occurred.
  # @option options [String] :error_message The specific error message from the client or system.
  # @option options [String] :response (optional) The raw response that was malformed.
  # @return [void] Modifies `@message_analysis_report` in place.
  def handle_api_errors_and_fallback(error_type, options = {})
    # Prevent multiple fallbacks or fallback if already in that mode
    return if @message_analysis_report[:processing_mode] == :fallback_layer1_only

    Rails.logger.warn "[SmsPolicyCheckerService FALLBACK] API Error triggering fallback. Type: #{error_type}, Options: #{options.inspect}"
    @message_analysis_report[:processing_mode] = :fallback_layer1_only
    @message_analysis_report[:rewrite_suggestion] = nil # No rewrites in fallback mode

    char_name_info = options[:characteristic_name] ? " for characteristic '#{options[:characteristic_name]}'" : " during general L2 processing"
    error_detail_msg = options[:error_message] || "L2 API processing encountered an issue."

    description = "Switched to Layer 1 fallback mode due to API error: #{error_type}#{char_name_info}. Detail: #{error_detail_msg}".strip
    api_failure_detail = {
      layer: 2, # Error occurred in context of Layer 2
      filter_type: "API_FALLBACK:#{error_type}",
      description: description.truncate(300), # Ensure description is not excessively long
      matched_value: "N/A",
      individual_confidence: 0.0, # No confidence score for an API error itself
      policy_category: "API_Error"
    }
    @message_analysis_report[:violation_details] << api_failure_detail
    Rails.logger.warn "[SmsPolicyCheckerService FALLBACK] Switched to :fallback_layer1_only mode. Report will be based on L1 scores and L1 final threshold."
    # Note: The final result and reason will be re-evaluated based on L1 scores by determine_final_result_and_reason
    # if this fallback happens before that stage. If it happens mid-determine_final_result, that method will use the L1 fallback threshold.
  end

  # Attempts to generate a rewrite suggestion for a failing message using the Gemini LLM.
  # This is only called if the message analysis resulted in a `:fail` and was processed
  # in `:full_analysis` mode.
  #
  # @private
  # @return [String, Hash, nil]
  #   - A [String] message if the LLM deems the content uncorrectable (e.g., "This message cannot be made compliant due to:...").
  #   - A [Hash] with keys `"general_fix_suggestions"` (String) and `"literal_rewrite"` (String)
  #     if the LLM provides a structured suggestion.
  #   - `nil` if a rewrite is not applicable, if necessary data is missing, if the Gemini client
  #     returns an error, or if an unexpected exception occurs during the process.
  # @note Makes a network call to the Gemini client.
  def generate_rewrite_suggestion
    Rails.logger.debug "[SmsPolicyCheckerService REWRITE] Generating rewrite suggestion."
    unless @message_body && @message_analysis_report[:reason] && @message_analysis_report[:confidence]
      Rails.logger.warn "[SmsPolicyCheckerService REWRITE] Missing necessary data (message, reason, or confidence) for rewrite."
      return nil
    end

    gemini_client = Google::GeminiClient.new # Consider memoization
    rewrite_response = gemini_client.generate_rewrite(
      @message_body,
      @message_analysis_report[:reason], # The primary failing category/characteristic
      @message_analysis_report[:confidence]
    )

    # Check for specific structured responses from GeminiClient for rewrites
    if rewrite_response.is_a?(String) && rewrite_response.start_with?("This message cannot be made compliant due to:")
      Rails.logger.info "[SmsPolicyCheckerService REWRITE] LLM deemed message uncorrectable: #{rewrite_response.truncate(100)}"
      rewrite_response # Return the string explaining why it's uncorrectable
    elsif rewrite_response.is_a?(Hash) && rewrite_response["literal_rewrite"].present? # Assuming "literal_rewrite" is key
      Rails.logger.info "[SmsPolicyCheckerService REWRITE] LLM provided correctable suggestions."
      rewrite_response # Return the hash with suggestions
    elsif rewrite_response.is_a?(Hash) && rewrite_response["error"]
      error_details = rewrite_response['details'] || rewrite_response['error']
      Rails.logger.error "[SmsPolicyCheckerService REWRITE] GeminiClient error during rewrite generation: #{rewrite_response['error']}. Details: #{error_details.to_s.truncate(200)}"
      nil # Error from client
    else
      Rails.logger.warn "[SmsPolicyCheckerService REWRITE] LLM returned an unexpected format for rewrite: #{rewrite_response.inspect.truncate(300)}"
      nil # Unexpected format
    end
  rescue StandardError => e # Catches exceptions from GeminiClient instantiation or other unexpected errors
    Rails.logger.error "[SmsPolicyCheckerService REWRITE] Exception during generate_rewrite_suggestion: #{e.class} - #{e.message}. Backtrace: #{e.backtrace.first(3).join(' | ')}"
    nil
  end
end