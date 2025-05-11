# frozen_string_literal: true

require "yaml" # For potential direct YAML loading if not using an initializer
require "json" # For parsing LLM responses
require "uri"
# Load helper modules and client wrappers
# These would typically be auto-loaded by Rails
# require_relative '../helpers/sms_policy/rule_loader'
# require_relative '../clients/google/gemini_client'
# require_relative '../clients/google/safe_browse_client'
# require_relative '../clients/google/perspective_client'
# require_relative '../clients/google/nl_client'

# == SmsPolicyCheckerService
#
# Service to analyze SMS message content for policy violations before sending via Twilio.
# It uses a multi-layered approach:
# 1. Layer 1: Fast, rule-based pre-filters (keywords, regex).
# 2. Layer 2: Advanced LLM-powered analysis (Google Gemini and other Google Cloud APIs).
#
# The service aims to reduce message blocking by identifying potential issues related
# to phishing, SHAFT, misleading sender information, and other carrier policies.
#
# @see file:README.md#2 Core Service Object: SmsPolicyCheckerService
#
class SmsPolicyCheckerService
  # --- Constants ---
  # Configurations would ideally be loaded via an initializer and stored in constants
  # or a configuration object. For this skeleton, we'll assume they are accessible.
  # Example:
  # LAYER1_RULES = SmsPolicy::RuleLoader.load_rules(File.read(Rails.root.join('config', 'sms_policy_checker_rules.yml')))
  # LLM_CONFIG = YAML.load_file(Rails.root.join('config', 'sms_policy_checker_llm_config.yml'))
  # THRESHOLDS = YAML.load_file(Rails.root.join('config', 'sms_policy_checker_thresholds.yml'))
  # FINAL_THRESHOLD_FLAG = THRESHOLDS['FINAL_THRESHOLD_FLAG']
  # CRITICAL_FAILURE_THRESHOLDS = THRESHOLDS['CRITICAL_FAILURE_THRESHOLDS'] # Assuming this structure

  # @!attribute [r] message_body
  #   @return [String] The raw SMS message content being analyzed.
  attr_reader :message_body

  # @!attribute [rw] message_analysis_report
  #   @return [Hash] The structured report detailing the analysis outcome.
  #   @see file:README.md#2.2 Output Structure: message_analysis_report
  attr_accessor :message_analysis_report

  # @!attribute [r] pre_fetched_api_signals
  #   @return [Hash] Stores results from initial API calls (e.g., SafeBrowse, Perspective, NL)
  #                 to be used as input for Layer 2 LLM analysis and relevancy checks.
  attr_reader :pre_fetched_api_signals

  # Initializes a new instance of the service for a single message.
  #
  # @param message_body [String] The raw text content of the SMS message.
  def initialize(message_body)
    @message_body = message_body
    @message_analysis_report = initialize_report
    @pre_fetched_api_signals = {} # To store results from SafeBrowse, Perspective, NL APIs
    # TODO: Initialize API clients (ideally injected or singletons)
    # @gemini_client = Google::GeminiClient.new
    # @safe_browse_client = Google::SafeBrowseClient.new
    # @perspective_client = Google::PerspectiveClient.new
    # @nl_client = Google::NlClient.new
  end

  # Primary class method to invoke the service.
  #
  # @param message_body [String] The raw text content of the SMS message.
  # @return [Hash] A structured `message_analysis_report`.
  # @see file:README.md#2.1 Interface
  def self.call(message_body)
    new(message_body).call
  end

  # Instance method to perform the analysis.
  #
  # @return [Hash] The populated `message_analysis_report`.
  def call
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Method call started. Message: '#{@message_body}'"
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Initial report state: #{@message_analysis_report.inspect}"

    layer1_halted = process_layer1_rules
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] After process_layer1_rules. layer1_halted: #{layer1_halted}"
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Report state after L1: #{@message_analysis_report.inspect}"

    critical_l2_failure_occurred = false

    unless layer1_halted
      Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Layer 1 NOT halted. Current processing_mode: #{@message_analysis_report[:processing_mode]}"
      if @message_analysis_report[:processing_mode] == :full_analysis
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Entering process_layer2_llm_analysis block."
        critical_l2_failure_occurred = process_layer2_llm_analysis # This will now return true if a critical failure occurred
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Exited process_layer2_llm_analysis block. Critical L2 failure: #{critical_l2_failure_occurred}"
      else
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] SKIPPING process_layer2_llm_analysis due to processing_mode: #{@message_analysis_report[:processing_mode]}"
      end

      # Only call determine_final_result_and_reason if no L1 halt AND no critical L2 failure from the L2 processing step
      unless critical_l2_failure_occurred
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] No critical L2 failure from process_layer2_llm_analysis. Calling determine_final_result_and_reason."
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Report state before final determination: #{@message_analysis_report.inspect}"
        determine_final_result_and_reason
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] After calling determine_final_result_and_reason."
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Report state after final determination: #{@message_analysis_report.inspect}"
      else
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Critical L2 failure occurred and set report. Skipping final determination."
      end
    else
      Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Layer 1 HALTED. Skipping L2 and final determination."
    end

    Rails.logger.debug "[SmsPolicyCheckerService DEBUG CALL] Returning final report: #{@message_analysis_report.inspect}"
    # TODO: Implement rewrite suggestion (Step X)
    # if @message_analysis_report[:result] == :fail && @message_analysis_report[:processing_mode] == :full_analysis
    #   @message_analysis_report[:rewrite_suggestion] = generate_rewrite_suggestion
    # end
    @message_analysis_report
  end


  private

  # Initializes the basic structure of the `message_analysis_report`.
  #
  # @return [Hash] The initialized report.
  # @see file:README.md#6.1 Initialization
  def initialize_report
    {
      result: :pass, # Default, can change
      reason: "Compliant", # Default, can change
      confidence: 0.0,
      rewrite_suggestion: nil,
      processing_mode: :full_analysis, # Default, changes on API errors
      policy_category_scores: {},
      violation_details: []
    }
  end

  # Processes Layer 1 rules against the message body.
  # Updates `message_analysis_report` with findings and determines if an early exit is triggered.
  #
  # @return [Boolean] `true` if processing was halted due to an early exit, `false` otherwise.
  # @see file:README.md#4.4 Layer 1 Processing Logic Algorithm
  def process_layer1_rules
    unless defined?(SmsPolicyCheckerService::LAYER1_RULES) && SmsPolicyCheckerService::LAYER1_RULES.is_a?(Array)
      Rails.logger.error "[SmsPolicyCheckerService] LAYER1_RULES not loaded or not an array. Skipping Layer 1."
      return false
    end
    processing_halted = false
    SmsPolicyCheckerService::LAYER1_RULES.each do |rule|
      next unless rule["compiled_patterns"].is_a?(Array)
      found_match_for_this_rule = false
      matched_text_for_this_rule = nil
      rule["compiled_patterns"].each do |compiled_regex_pattern|
        next unless compiled_regex_pattern.is_a?(Regexp)
        match_data = compiled_regex_pattern.match(message_body)
        if match_data
          found_match_for_this_rule = true
          matched_text_for_this_rule = match_data[0]
          break
        end
      end

      if found_match_for_this_rule
        violation_detail = {
          layer: 1, filter_type: rule["name"], description: rule["description"],
          matched_value: matched_text_for_this_rule,
          individual_confidence: rule["individual_confidence"].to_f,
          policy_category: rule["mapped_policy_category"]
        }
        @message_analysis_report[:violation_details] << violation_detail
        category = rule["mapped_policy_category"]
        current_score = rule["individual_confidence"].to_f
        existing_score = @message_analysis_report[:policy_category_scores][category].to_f
        @message_analysis_report[:policy_category_scores][category] = [ existing_score, current_score ].max

        if rule["is_early_exit_rule"] && current_score >= rule["early_exit_threshold"].to_f
          @message_analysis_report[:result] = :fail
          @message_analysis_report[:confidence] = current_score
          @message_analysis_report[:reason] = if @message_analysis_report[:processing_mode] == :fallback_layer1_only
                                                "Fallback: Early Exit - Violation Category: #{category}"
          else
                                                "Early Exit - Violation Category: #{category}"
          end
          processing_halted = true
          break
        end
      end
    end
    processing_halted
  end

  def gather_auxiliary_api_signals
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] Starting to gather signals."
    @pre_fetched_api_signals ||= {}
    @pre_fetched_api_signals[:url_list] = extract_urls_from_message_body
    @pre_fetched_api_signals[:urls_present] = @pre_fetched_api_signals[:url_list].is_a?(Array) && @pre_fetched_api_signals[:url_list].any?
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] URLs Present: #{@pre_fetched_api_signals[:urls_present]}, List: #{@pre_fetched_api_signals[:url_list].inspect}"

    if @pre_fetched_api_signals[:urls_present]
      Rails.logger.debug "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] URLs found, attempting SafeBrowse call."
      begin
        safe_browse_client = Google::SafeBrowseClient.new # Consider instantiating clients once if appropriate
        sb_result = safe_browse_client.find_threat_matches(@pre_fetched_api_signals[:url_list])
        Rails.logger.debug "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] Raw SafeBrowse result: #{sb_result.inspect}"
        if sb_result&.dig("error")
          Rails.logger.warn "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] SafeBrowseClient returned an error: #{sb_result['error']}"
          @pre_fetched_api_signals[:safe_browse_result] = { "matches" => [], "error" => sb_result["error"] }
        else
          @pre_fetched_api_signals[:safe_browse_result] = sb_result || { "matches" => [] }
        end
      rescue StandardError => e
        Rails.logger.error "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] Failed to call SafeBrowseClient: #{e.class} - #{e.message}"
        @pre_fetched_api_signals[:safe_browse_result] = { "matches" => [], "error" => "SafeBrowseClient call failed: #{e.message}" }
      end
      Rails.logger.debug "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] Final SafeBrowse signal: #{@pre_fetched_api_signals[:safe_browse_result].inspect}"
    else
      Rails.logger.debug "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] No URLs found, skipping SafeBrowse call."
      @pre_fetched_api_signals[:safe_browse_result] = { "matches" => [] }
    end

    @pre_fetched_api_signals[:nl_api_result] = { "entities" => [], "error" => "NL Client not yet implemented" }
    @pre_fetched_api_signals[:perspective_result] = { "attributeScores" => {}, "error" => "Perspective Client not yet implemented" }
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG GATHER_SIGNALS] Finished gathering signals. Pre-fetched signals: #{@pre_fetched_api_signals.inspect}"
  end

  def extract_urls_from_message_body
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG EXTRACT_URLS] Called for message: '#{@message_body}'"
    urls = []
    begin
      if @message_body.is_a?(String)
        urls = URI.extract(@message_body, [ "http", "https" ]).uniq # Keep it to http/https for now
      else
        Rails.logger.warn "[SmsPolicyCheckerService DEBUG EXTRACT_URLS] @message_body is not a string: #{@message_body.inspect}"
      end
    rescue StandardError => e
      Rails.logger.error "[SmsPolicyCheckerService DEBUG EXTRACT_URLS] Error during URI.extract: #{e.message}"
    end
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG EXTRACT_URLS] Extracted URLs: #{urls.inspect}"
    urls
  end

  def process_layer2_llm_analysis
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG L2_PROCESS] Starting Layer 2 LLM Analysis."
    gather_auxiliary_api_signals

    all_characteristics = SmsPolicyCheckerService::LLM_CONFIG.fetch("characteristics", [])
    unless all_characteristics.is_a?(Array) && all_characteristics.any?
      Rails.logger.error "[SmsPolicyCheckerService DEBUG L2_PROCESS] LLM_CONFIG['characteristics'] not a non-empty array or missing. Skipping L2."
      return false # No critical L2 failure
    end

    # --- DEVELOPMENT SPEEDUP: Limit characteristics processed ---
    # For now, let's define a list of characteristics to actually process to avoid excessive API calls
    # You can expand this list or use `all_characteristics` for full processing.
    # Ensure these names match names in your llm_config.yml
    dev_characteristics_to_process_names = [
      "PhishingAndDeceptiveURLs",
      "HatefulContent",
      "SHAFT_Sex_AdultContent"
      # "MisleadingSenderIdentity",
      # "FraudulentOrMaliciousContent"
    ] # Limit to e.g. 2-5
    characteristics_to_evaluate = all_characteristics.select { |c| dev_characteristics_to_process_names.include?(c["name"]) }
    if characteristics_to_evaluate.empty? && all_characteristics.any?
        Rails.logger.warn "[SmsPolicyCheckerService DEBUG L2_PROCESS] No characteristics matched the dev processing list. Processing first available if any."
        characteristics_to_evaluate = [ all_characteristics.first ].compact # Process at least one if available
    end
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG L2_PROCESS] Will evaluate #{characteristics_to_evaluate.count} L2 characteristics (dev limit)."
    # --- END DEVELOPMENT SPEEDUP ---

    gemini_client = Google::GeminiClient.new # Instantiate once

    characteristics_to_evaluate.each do |char_config| # Use the subset for now
      characteristic_name = char_config["name"]
      Rails.logger.debug "[SmsPolicyCheckerService DEBUG L2_PROCESS] Determining relevancy for: '#{characteristic_name}'"
      is_relevant = determine_characteristic_relevancy(char_config)

      if is_relevant
        Rails.logger.info "[SmsPolicyCheckerService L2_PROCESS_RELEVANCY] Characteristic '#{characteristic_name}' IS relevant."
        prompt_text = build_gemini_prompt(char_config, @pre_fetched_api_signals)
        gemini_response = gemini_client.analyze_characteristic(prompt_text) # This now makes a real API call
        Rails.logger.info "[SmsPolicyCheckerService L2_PROCESS_GEMINI] Gemini response for '#{characteristic_name}': #{gemini_response.inspect}"

        llm_confidence = 0.0
        llm_rationale = "LLM analysis not performed or error."

        if gemini_response && gemini_response["error"].nil?
          llm_confidence = gemini_response["confidence_score"].to_f rescue 0.0
          llm_rationale = gemini_response["rationale"].to_s
        elsif gemini_response && gemini_response["error"]
          llm_rationale = "LLM Error for '#{characteristic_name}': #{gemini_response['error']}"
          if gemini_response["block_reason"]
            llm_rationale += " (Block Reason: #{gemini_response['block_reason']})"
            # Example: if a prompt is blocked for safety, you might assign a high confidence to certain violation categories.
            # if characteristic_name == "HatefulContent" && gemini_response["block_reason"].to_s.include?("HATE") # Or other safety categories
            #   llm_confidence = 0.99 # Example of specific handling for blocked prompts
            # end
          end
        end

        violation_detail = {
          layer: 2, filter_type: "Gemini:#{characteristic_name}",
          description: llm_rationale, matched_value: "N/A", # Consider extracting key snippets from message if LLM provides them
          individual_confidence: llm_confidence, policy_category: characteristic_name
        }
        @message_analysis_report[:violation_details] << violation_detail

        existing_score = @message_analysis_report[:policy_category_scores][characteristic_name].to_f
        new_l2_score = [ existing_score, llm_confidence ].max # Take max if L1 also scored this category
        @message_analysis_report[:policy_category_scores][characteristic_name] = new_l2_score
        Rails.logger.debug "[SmsPolicyCheckerService L2_PROCESS_SCORES] Updated score for '#{characteristic_name}' to: #{new_l2_score}"

        # --- Implement Critical Failure Check (README Section 6.3.a) ---
        # Check for CRITICAL L2 FAILURE for this characteristic immediately after getting its score
        critical_threshold = SmsPolicyCheckerService::CRITICAL_FAILURE_THRESHOLDS[characteristic_name].to_f rescue nil
        if critical_threshold && new_l2_score >= critical_threshold
          Rails.logger.warn "[SmsPolicyCheckerService L2_CRITICAL] Critical L2 failure for '#{characteristic_name}'. Score: #{new_l2_score}, Threshold: #{critical_threshold}"
          @message_analysis_report[:result] = :fail
          @message_analysis_report[:confidence] = new_l2_score
          @message_analysis_report[:reason] = characteristic_name # Set reason to the L2 characteristic name
          return true # Signal to .call that a critical failure occurred, stop further L2 processing & final determination
        end
      else
        Rails.logger.info "[SmsPolicyCheckerService L2_PROCESS_RELEVANCY] Characteristic '#{characteristic_name}' is SKIPPED."
      end
    end
    Rails.logger.debug "[SmsPolicyCheckerService DEBUG L2_PROCESS] Finished iterating L2 characteristics evaluation."
    false # No critical L2 failure occurred during the loop
  end

  def determine_characteristic_relevancy(char_config)
    is_relevant = true
    skip_conditions = char_config.fetch("relevancy_skip_conditions", [])
    skip_conditions.each do |condition|
      condition_type = condition["type"]
      case condition_type
      when "skip_if_no_urls"
        is_relevant = false unless @pre_fetched_api_signals[:urls_present]
      when "skip_if_no_specific_entities"
        nl_call_succeeded = @pre_fetched_api_signals[:nl_api_result] && !@pre_fetched_api_signals.dig(:nl_api_result, "error")
        if nl_call_succeeded
          # This logic needs actual entities from NL client to work fully
          # required_entity_type = condition['entity_type']
          # found_entities = @pre_fetched_api_signals.dig(:nl_api_result, "entities")&.select { |e| e["type"] == required_entity_type } || []
          # is_relevant = false if found_entities.empty?
          Rails.logger.debug "[SmsPolicyCheckerService] Relevancy: 'skip_if_no_specific_entities' evaluated but NL entities not fully processed yet."
        else
          Rails.logger.debug "[SmsPolicyCheckerService] Relevancy: Cannot evaluate 'skip_if_no_specific_entities' for '#{char_config['name']}' as NL data is unavailable/failed."
        end
      else
        Rails.logger.warn "[SmsPolicyCheckerService] Unknown relevancy_skip_condition type: '#{condition_type}' for characteristic '#{char_config['name']}'"
      end
      break unless is_relevant
    end
    is_relevant
  end

  # Determines the final result (:pass or :fail) and reason based on scores
  # if not already determined by an early exit or critical L2 failure.
  # Implements logic from README Section 6.3.b (Max Score Fallback).
  #
  # @see file:README.md#6.3.b Max Score Fallback
  def determine_final_result_and_reason
    # This method is now only called if NO L1 early exit AND NO critical L2 failure occurred.

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

    # Use THRESHOLDS - ensure they are loaded (initializer should handle this)
    threshold_to_use = if @message_analysis_report[:processing_mode] == :fallback_layer1_only
                         (SmsPolicyCheckerService::THRESHOLDS["FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK"].to_f rescue 0.75)
    else # :full_analysis
                         (SmsPolicyCheckerService::THRESHOLDS["FINAL_THRESHOLD_FLAG"].to_f rescue 0.75)
    end

    if max_observed_score >= threshold_to_use && leading_category_for_fail
      @message_analysis_report[:result] = :fail
      if @message_analysis_report[:processing_mode] == :fallback_layer1_only
        @message_analysis_report[:reason] = "Fallback: Layer 1 Threshold Exceeded - Violation Category: #{leading_category_for_fail}"
      else # :full_analysis, and NOT a critical L2 failure, but combined L1/L2 scores hit FINAL_THRESHOLD_FLAG
        @message_analysis_report[:reason] = leading_category_for_fail
      end
    else
      if @message_analysis_report[:result] != :fail # Don't override if already failed by other means
        @message_analysis_report[:result] = :pass
        @message_analysis_report[:reason] = if @message_analysis_report[:processing_mode] == :fallback_layer1_only
                                              "Fallback: Compliant."
        else
                                              "Compliant"
        end
      end
    end
  end

  # Handles API errors, potentially switching the service to fallback mode.
  #
  # @param error_type [Symbol] A symbol indicating the type of API error (e.g., :gemini_unavailable, :perspective_failed).
  # @param options [Hash] Additional options, e.g., { characteristic_name: '...' }
  # @see file:README.md#6.4 Error Handling during API calls
  # @see file:README.md#7 Fallback Mode: API Unavailability
  def handle_api_errors_and_fallback(error_type, options = {})
    # TODO: Implement error logging and fallback logic based on README Section 6.4 and 7.
    # This could involve:
    # 1. Logging the error with details (error_type, characteristic if applicable).
    # 2. If the error is critical or repeated (e.g., Gemini totally unavailable):
    #    a. Set `@message_analysis_report[:processing_mode] = :fallback_layer1_only`.
    #    b. Ensure `rewrite_suggestion` becomes nil.
    #    c. Stop further Layer 2 processing for the current message.
    #    d. The final decision will then be based ONLY on Layer 1 findings.
    #       (The `determine_final_result_and_reason` method needs to respect this mode).
    #
    # For this skeleton, we'll assume a simple switch to fallback:
    puts "API Error Occurred: #{error_type}, options: #{options}. Switching to fallback if applicable."
    # A more robust implementation would track error counts or specific error types
    # to decide when to switch to :fallback_layer1_only.
    # For now, let's assume any significant L2 API error triggers fallback for the current call.
    if [ :gemini_unavailable, :perspective_unavailable, :nl_unavailable, :safe_browse_unavailable ].include?(error_type)
      @message_analysis_report[:processing_mode] = :fallback_layer1_only
      @message_analysis_report[:rewrite_suggestion] = nil # No rewrites in fallback
      puts "Switched to :fallback_layer1_only mode due to API error."
      # If Layer 1 already completed, we might need to re-evaluate its result based on fallback rules.
      # This implies `determine_final_result_and_reason` is called after fallback is set.
    end
  end

  # Generates a rewrite suggestion using the LLM if the message failed in full_analysis mode.
  #
  # @return [Hash, String, nil] The rewrite suggestion as per README Section 6.5.
  #   - Hash: { general_fix_suggestions: String, literal_rewrite: String } if correctable.
  #   - String: "This message cannot be made compliant due to: [reason]" if uncorrectable.
  #   - nil: If LLM fails to provide a suggestion or not applicable.
  # @see file:README.md#6.5 Message Rewrite Suggestion
  def generate_rewrite_suggestion
    # TODO: Implement rewrite suggestion logic based on README Section 6.5
    # This involves:
    # 1. Constructing a prompt for Gemini:
    #    - Inputs: original `message_body`, `message_analysis_report[:reason]`, `[:confidence]`.
    #    - Instructions for correctable vs. uncorrectable, and desired output structure (JSON hash or string).
    # 2. Calling Gemini API (e.g., @gemini_client.generate_rewrite(prompt)).
    # 3. Parsing the response:
    #    - If "uncorrectable" string, return it.
    #    - Else, try to parse as JSON for the Hash.
    #    - If any issues (API error, parsing error, unexpected format), return nil.
    #
    # Example:
    # prompt = build_rewrite_prompt(
    #   message_body,
    #   @message_analysis_report[:reason],
    #   @message_analysis_report[:confidence]
    # )
    # begin
    #   raw_suggestion = @gemini_client.call(prompt) # Assuming client handles call
    #   if raw_suggestion.start_with?("This message cannot be made compliant due to:")
    #     return raw_suggestion
    #   else
    #     # Attempt to parse as JSON for { general_fix_suggestions, literal_rewrite }
    #     suggestion_hash = JSON.parse(raw_suggestion)
    #     if suggestion_hash.is_a?(Hash) && suggestion_hash.key?('general_fix_suggestions') && suggestion_hash.key?('literal_rewrite')
    #        return suggestion_hash
    #     end
    #   end
    # rescue JSON::ParserError, StandardError => e # Catch API or parsing errors
    #   # Log error
    #   puts "Error generating rewrite suggestion: #{e.message}"
    # end
    Rails.logger.warn "[SmsPolicyCheckerService] TODO: Implement generate_rewrite_suggestion"
    nil # Default if anything goes wrong or not applicable
  end

  # --- Helper methods for internal logic, e.g. ---
  #
  # def extract_urls_from_message
  #   # URI.extract(message_body, ['http', 'https']) - needs require 'uri'
  #   # Or a more robust regex from README Section 4.3, Rule L1_PHISHING_URGENCY_KEYWORDS_WITH_LINK
  #   message_body.scan(/https?:\/\/[^\s]+/)
  # end
  #
  # def is_characteristic_relevant?(characteristic_config, signals)
  #   # Implement logic from README Section 5.5.1.a.ii
  #   # Default to true. Check skip_conditions against signals.
  #   # e.g., if characteristic_config['relevancy_skip_conditions'] includes {type: 'skip_if_no_urls'}
  #   #   return false if !signals[:urls_present]
  #   true
  # end
  #
  def build_gemini_prompt(characteristic_config, pre_fetched_signals)
    template = characteristic_config["prompt_template"].to_s
    prompt = template.gsub(/%\{message_body\}/, @message_body.to_s.gsub("'", "\\\\'")) # More robust escaping needed if message_body can have complex chars for a string literal in a prompt
                     .gsub(/%\{characteristic_name\}/, characteristic_config["name"].to_s)
                     .gsub(/%\{policy_context_snippet\}/, characteristic_config["knowledge_source_context"].to_s.gsub("'", "\\\\'"))

    safe_browse_summary = "N/A" # Default
    if pre_fetched_signals[:urls_present]
        sb_res = pre_fetched_signals[:safe_browse_result]
        if sb_res && sb_res["matches"]&.any?
            safe_browse_summary = "Flagged by Safe Browse: " + sb_res["matches"].map { |m| "#{m['threatType']} for #{m.dig('threat', 'url')}" }.join("; ")
        elsif sb_res && sb_res["error"]
            safe_browse_summary = "Safe Browse API call resulted in error: #{sb_res["error"]}"
        else # No error, no matches, and URLs were present
            safe_browse_summary = "No threats found by Safe Browse for present URLs."
        end
    end
    prompt = prompt.gsub(/%\{safe_browse_results\}/, safe_browse_summary)

    # Basic placeholders for NL and Perspective, to be refined when clients are implemented
    nl_summary = pre_fetched_signals.dig(:nl_api_result, "error") || "NL data not processed."
    if pre_fetched_signals.dig(:nl_api_result, "entities")&.any?
        nl_summary = "Detected entities: " + pre_fetched_signals[:nl_api_result]["entities"].map { |e| e["name"] }.join(", ")
    end
    prompt = prompt.gsub(/%\{nl_entities\}/, nl_summary)

    perspective_summary = pre_fetched_signals.dig(:perspective_result, "error") || "Perspective data not processed."
    if pre_fetched_signals.dig(:perspective_result, "attributeScores")&.any?
        perspective_summary = "Perspective scores: " + pre_fetched_signals[:perspective_result]["attributeScores"].map { |k, v| "#{k}: #{v.dig('summaryScore', 'value')&.round(2)}" }.join(", ")
    end
    prompt = prompt.gsub(/%\{perspective_scores\}/, perspective_summary)

    Rails.logger.debug "[SmsPolicyCheckerService DEBUG PROMPT] Built Gemini prompt for '#{characteristic_config['name']}':\n#{prompt}"
    prompt
  end

  #
  # def build_rewrite_prompt(message_body, reason, confidence)
  #   # Implement logic from README Section 6.5
  #   "Placeholder rewrite prompt for: #{message_body}, failed due to #{reason}"
  # end
end
