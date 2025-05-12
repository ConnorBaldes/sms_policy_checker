# SMS Policy Checker

A Ruby on Rails service to analyze SMS messages for policy compliance using a hybrid AI (LLM + rules) approach to mitigate carrier filtering and provide actionable feedback.

## Description

The `SmsPolicyCheckerService` is designed to proactively analyze SMS message content *before* transmission (e.g., via Twilio). Its primary goal is to identify potential policy violations that could lead to carrier filtering (often manifesting as Twilio error 30007) or other deliverability issues. By providing structured, detailed feedback on messages, this service helps users understand and rectify problematic content, thereby improving message deliverability and compliance with communication policies related to phishing, SHAFT (Sex, Hate, Alcohol, Firearms, Tobacco), misleading sender information, and more.

Built as a Ruby on Rails service object, it accepts an SMS message body as input and returns a comprehensive analysis report. The architecture leverages a multi-layered filtering strategy, combining rapid, deterministic rule-based checks (Layer 1) with sophisticated, context-aware Large Language Model (LLM) analysis (Layer 2) powered by Google's Gemini API and supported by Google Cloud's Natural Language and Safe Browse APIs.

## Key Features

* **Multi-Layered Analysis:** Combines fast, regex/keyword-based Layer 1 filtering with deep, contextual LLM-powered Layer 2 analysis.
* **Comprehensive Policy Coverage:** Addresses a wide range of policies including SHAFT, phishing, misleading content, and more, based on 19 configurable characteristics for LLM analysis.
* **Structured Feedback:** Returns a detailed hash report including pass/fail status, reason, confidence scores, violation details, and policy category scores.
* **Rewrite Suggestions:** Offers LLM-generated suggestions to make non-compliant messages compliant (when applicable).
* **Fallback Mechanism:** Provides baseline screening using Layer 1 rules if external APIs (Layer 2) are unavailable.
* **Configurable:** Rules, LLM prompts, and decision thresholds are managed via external YAML files for easier updates.
* **Robust Error Handling:** Clients and services include detailed error handling and logging.
* **Well-Documented:** Thorough YARD documentation for all Ruby components.
* **Live Integration Tests:** RSpec suite designed to test the service with live API calls, ensuring real-world behavior.

## Architecture Overview

The service employs a sequential, two-layer filtering approach for efficiency and depth of analysis:

1.  **Layer 1 (Rule-Based Pre-filters):** The message is first processed by a series of fast, locally executable rules defined in `config/sms_policy_checker_rules.yml`. If a high-confidence, severe violation is detected by a rule designated as an "early exit" rule, processing may stop, and Layer 2 can be skipped. This layer is implemented via `SmsPolicy::RuleLoader` and processed within `SmsPolicyCheckerService`.

2.  **Layer 2 (Advanced LLM-Powered Analysis):** If the message passes Layer 1 without an early exit, it proceeds to Layer 2. This layer utilizes:
    * **Google Gemini API (`Google::GeminiClient`):** For nuanced assessment against 19 configurable policy characteristics.
    * **Google Natural Language API (`Google::NlClient`):** For entity extraction and text moderation to provide signals to Gemini.
    * **Google Safe Browse API (`Google::SafeBrowseClient`):** For checking URL safety, providing signals to Gemini.
    LLM characteristic definitions and prompts are managed in `config/sms_policy_checker_llm_config.yml`.

This sequential model ensures that obvious violations are caught quickly by Layer 1, reserving the more resource-intensive LLM analysis for messages requiring deeper contextual understanding. The entire process is orchestrated by `SmsPolicyCheckerService`, with configurations loaded by `config/initializers/sms_policy_checker_config.rb`.

## Project Directory Structure
```bash
sms_policy_checker/
├── app/
│   ├── services/
│   │   └── sms_policy_checker_service.rb  # Main service object
│   ├── helpers/
│   │   └── sms_policy/
│   │       └── rule_loader.rb             # Helper for loading Layer 1 rules
│   └── clients/                           # API client wrappers
│       └── google/
│           ├── gemini_client.rb
│           ├── safe_browse_client.rb
│           └── nl_client.rb
├── config/
│   ├── initializers/
│   │   └── sms_policy_checker_config.rb   # To load YAML configs on boot
│   ├── sms_policy_checker_rules.yml       # Layer 1 rules
│   ├── sms_policy_checker_llm_config.yml  # Layer 2 LLM characteristics and prompts
│   └── sms_policy_checker_thresholds.yml  # Various decision thresholds
├── spec/
│   ├── services/
│   │   └── sms_policy_checker_service_spec.rb # RSpec tests for the service
│   ├── rails_helper.rb
│   └── spec_helper.rb
├── Gemfile
├── Rakefile
└── README.md
```

## Installation

### Prerequisites
* Ruby (e.g., 3.x.x - ensure compatibility with Rails ~> 7.1)
* Bundler (e.g., 2.x.x)
* SQLite3 (or your chosen database for a Rails environment if different)

### Steps
1.  Clone the repository:
```bash
    git clone <your-repository-url>
    cd sms_policy_checker_app
```
2.  Install dependencies:
```bash
    bundle install
```

## Configuration

The service relies on an environment variable for API access and several YAML files for its operational logic. These are loaded by `config/initializers/sms_policy_checker_config.rb` at application boot.

### API Key

* A **Google Cloud API Key** is required for accessing Google Safe Browse, Natural Language, and Generative Language (Gemini) APIs.
* This key must be provided via the environment variable: `GOOGLE_API_KEY`.
* Ensure the key has the necessary APIs enabled in your Google Cloud project.
* For local development and testing, you can use a `.env` file (e.g., `.env`, `.env.development`, `.env.test`) managed by the `dotenv-rails` gem. Add your API key to this file:
    ```env
    # Example for .env or .env.test
    GOOGLE_API_KEY="your_actual_google_api_key"
    ```
    - `.env*` are in `.gitignore` as to not accidentally add them to public Repo.

### YAML Configuration Files

1.  **`config/sms_policy_checker_rules.yml`**:
    * Defines Layer 1 rules (keywords and regular expressions).
    * Each rule specifies attributes like `name`, `description`, `type` (`keyword` or `regex`), `patterns`, `mapped_policy_category`, `individual_confidence`, `is_early_exit_rule`, and `early_exit_threshold`.
    * **Critical:** The application will fail to boot if this file is missing or contains fatal structural/validation errors.

2.  **`config/sms_policy_checker_llm_config.yml`**:
    * Defines Layer 2 "characteristics" analyzed by the Gemini LLM.
    * Each characteristic includes a `name`, `description`, `knowledge_source_context` (policy snippets for the LLM), optional `relevancy_skip_conditions`, and a `prompt_template`.
    * Placeholders in `prompt_template` (e.g., `%{message_body}`) are populated at runtime.
    * **Note:** If this file is missing, the service operates with empty L2 characteristics (logging a warning). If present but malformed (YAML syntax error), the application fails to boot.

3.  **`config/sms_policy_checker_thresholds.yml`**:
    * Defines numerical thresholds for decision-making:
        * `FINAL_THRESHOLD_FLAG`: General failure threshold for full analysis mode.
        * `FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK`: Failure threshold for Layer 1 fallback mode.
        * `CRITICAL_FAILURE_THRESHOLDS`: A hash mapping L2 characteristic names to scores that trigger immediate critical failure.
    * **Note:** If this file is missing, defaults are used (defined in the initializer, logging a warning). If present but malformed (YAML syntax error), the application fails to boot.

## Usage

The primary way to use the service is by calling its class method `call`.

```ruby
# Example usage within a Rails application:

message_to_check = "Hello, click this link now for your prize: [http://short.ly/promo123](http://short.ly/promo123)"
analysis_report = SmsPolicyCheckerService.call(message_to_check)

puts "Analysis Result: #{analysis_report[:result]}"
puts "Reason: #{analysis_report[:reason]}"
puts "Confidence: #{analysis_report[:confidence]}"
puts "Processing Mode: #{analysis_report[:processing_mode]}"

if analysis_report[:rewrite_suggestion]
  puts "Rewrite Suggestion: #{analysis_report[:rewrite_suggestion].inspect}"
end

puts "Policy Category Scores:"
analysis_report[:policy_category_scores].each do |category, score|
  puts "  #{category}: #{score}"
end

puts "Violation Details:"
analysis_report[:violation_details].each do |detail|
  puts "  Layer: #{detail[:layer]}, Type: #{detail[:filter_type]}, Confidence: #{detail[:individual_confidence]}"
  puts "    Description: #{detail[:description]}"
  puts "    Matched: #{detail[:matched_value]}" if detail[:matched_value]
end
```
The service is designed for single message processing. For high-volume screening, it should be invoked by an external orchestration layer (e.g., background jobs) for parallel processing.

## Service Output Details (API)

The `SmsPolicyCheckerService.call` method returns a comprehensive Ruby `Hash` (the `message_analysis_report`).

**Output Structure:** `message_analysis_report`
- `result` (`Symbol`): Overall outcome. Either `:pass` or `:fail`.
- `reason` (`String`): A human-readable explanation for the outcome. Examples:
    - If Layer 2 failure: `"PhishingAndDeceptiveURLs"`
    - If Layer 1 Early Exit: `"Early Exit - Violation Category: [mapped_policy_category]"`
    - If Fallback L1 Early Exit: `"Fallback: Early Exit - Violation Category: [mapped_policy_category]"`
    - If Fallback L1 Threshold Failure: `"Fallback: Layer 1 Threshold Exceeded - Violation Category: [category]"`
    - If Pass: `"Compliant"` or `"Fallback: Compliant."`
- `confidence` (`Float`): Score (0.0-1.0+) representing confidence in the violation if `:fail`, or the highest score observed if `:pass` (will be below the flagging threshold).
- `rewrite_suggestion` (`Hash` | `String` | `nil`):
    - `Hash`: If LLM deems correctable: `{ "general_fix_suggestions": String, "literal_rewrite": String }`.
    - `String`: If LLM deems uncorrectable: `"This message cannot be made compliant due to: [reason]"`.
    - nil: If no suggestion is applicable/generated, or in fallback mode.
- `processing_mode` (`Symbol`): `:full_analysis` or `:fallback_layer1_only`.
- `policy_category_scores` (`Hash`): Scores for all assessed policy categories (e.g., `{"PhishingAndDeceptiveURLs" => 0.98, "SHAFT_Sex_AdultContent" => 0.15}`).
- `violation_details` (`Array<Hash>`): List of all individual findings. Each detail hash includes:
    - `layer` (`Integer`): `1` or `2`.
    - `filter_type` (`String`): Rule name (e.g., `"L1_PUBLIC_URL_SHORTENER_SEVERE"`) or LLM analysis type (e.g., `"Gemini:PhishingAndDeceptiveURLs"`, `"API_FALLBACK:gemini_call_failed"`).
    - `description` (`String`): Description of the finding or LLM rationale.
    - `matched_value` (`String` | `"N/A"`): Specific text/URL matched by L1, or "N/A" for L2/fallback.
    - `individual_confidence` (`Float`): Confidence of this specific finding.
    - `policy_category` (`String`): Policy category this finding pertains to.

<details>
<summary><strong>Example `message_analysis_report` (Failure with Rewrite)</strong></summary>

```ruby
# This is a Ruby Hash representation
{
  result: :fail,
  reason: "PhishingAndDeceptiveURLs", # Assuming this was the highest scoring L2 category above threshold
  confidence: 0.98, # The score for "PhishingAndDeceptiveURLs"
  rewrite_suggestion: {
    "general_fix_suggestions" => "Avoid using link shorteners and ensure all links lead to trusted, clearly identifiable domains. State the purpose of the link clearly.",
    "literal_rewrite" => "Please review your account details by logging into our official website at [yourcompany.com/account](https://yourcompany.com/account). For help, call 1-800-555-1234."
  },
  processing_mode: :full_analysis,
  policy_category_scores: {
    "ProhibitedPublicURLShorteners" => 1.0, # From Layer 1
    "PhishingAndDeceptiveURLs" => 0.98    # From Layer 2
    # ... other L2 categories might have scores here too
  },
  violation_details: [
    {
      layer: 1,
      filter_type: "L1_PUBLIC_URL_SHORTENER_SEVERE",
      description: "Detects the use of common, free public URL shorteners, strong phishing/spam indicator.",
      matched_value: "bit.ly/example",
      individual_confidence: 1.0,
      policy_category: "ProhibitedPublicURLShorteners"
    },
    {
      layer: 2,
      filter_type: "Gemini:PhishingAndDeceptiveURLs",
      description: "The message uses urgent language ('urgent action required') combined with a public URL shortener. SafeBrowse also flagged the effective destination of the shortener for SOCIAL_ENGINEERING.",
      matched_value: "N/A", # Or could be message snippet if applicable
      individual_confidence: 0.98,
      policy_category: "PhishingAndDeceptiveURLs"
    }
    # ... other details if any
  ]
}
```
</details>

<details>
<summary><strong>Example `message_analysis_report` (Pass in Fallback)</strong></summary>

```ruby
# This is a Ruby Hash representation
{
  result: :pass,
  reason: "Fallback: Compliant.",
  confidence: 0.65, # Highest L1 score, below fallback threshold
  rewrite_suggestion: nil,
  processing_mode: :fallback_layer1_only,
  policy_category_scores: {
    "AdvancedContentEvasionTactics" => 0.65
  },
  violation_details: [
    {
      layer: 1,
      filter_type: "L1_EXCESSIVE_CAPITALIZATION_MODERATE", # Example rule name
      description: "Detects excessive use of uppercase letters, a spam indicator.",
      matched_value: "URGENT ATTENTION NEEDED CLICK NOW",
      individual_confidence: 0.65,
      policy_category: "AdvancedContentEvasionTactics" # Example mapping
    },
    { # Example of an API_FALLBACK detail when fallback is triggered
      layer: 2,
      filter_type: "API_FALLBACK:gemini_call_failed", # Or other error type
      description: "Switched to Layer 1 fallback mode due to API error: gemini_call_failed for characteristic 'MisleadingSenderIdentity'. Detail: Gemini API Error (Status: 500)",
      matched_value: "N/A",
      individual_confidence: 0.0,
      policy_category: "API_Error"
    }
  ]
}
```
</details>

## Detailed Design and Processing Logic
This section outlines the internal workings of the `SmsPolicyCheckerService`.
<details>
<summary><strong>Layer 1: Rule-Based Pre-filters</strong></summary>

**Purpose**
- **Rapid Detection:** Quickly flag common, unambiguous violations using predefined keywords and regex.
- **Cost & Latency Optimization:** Reduce calls to more expensive LLM services.
- **Standalone Fallback:** Provide baseline screening if Layer 2 APIs are unavailable.

**Implementation Details**
- **Configuration:** Rules are in `config/sms_policy_checker_rules.yml`.
- **Rule Definition Structure (YAML):**
    - `name` (String): Unique ID (e.g., "L1_SHAFT_SEX_EXPLICIT_KEYWORD").
    - `description` (String): Explanation.
    - `type` (String): "keyword" or "regex".
    - `patterns` (Array of Strings): Keywords or regex patterns.
        - "keyword" type patterns are compiled into case-insensitive, whole-word matching regex (e.g., "Alert!" becomes `/\bAlert!\b/i`).
        - "regex" type patterns are compiled as Regexp objects, typically with case-insensitivity by default.
- `mapped_policy_category` (String): Internal policy category (e.g., "SHAFT_Sex_AdultContent").
- `individual_confidence` (Float): Score (0.0-1.0) for a match.
- `is_early_exit_rule` (Boolean): If true, a high-confidence match stops processing and skips Layer 2.
- `early_exit_threshold` (Float): Confidence needed for an early exit rule to trigger.
- **Runtime Processing:** Patterns are pre-compiled into `Regexp` objects at application boot by `SmsPolicy::RuleLoader` for efficient matching.
</details>

<details>
<summary><strong>Illustrative Layer 1 Rule Examples (Conceptual)</strong></summary>

(Note: Actual patterns are in `sms_policy_checker_rules.yml`. These are simplified examples of rule intent.)

1. Rule: `L1_SHAFT_SEX_EXTREME_EXPLICIT_SEVERE`
    - Type: `keyword`, Confidence: `1.0`, Early Exit: `true` (threshold `1.0`)
    - Detects unambiguous, severe explicit sexual terms (e.g., "child porn").

2. Rule: `L1_PUBLIC_URL_SHORTENER_SEVERE`
    - Type: `regex`, Confidence: `1.0`, Early Exit: `true` (threshold `1.0`)
    - Detects common public URL shorteners (e.g., bit.ly, tinyurl.com).
3. Rule: `L1_PHISHING_IMMEDIATE_ACTION_WITH_LINK_HIGH_CONF` (Example Name)
    - Type: `keyword` (or `regex` combining keyword and URL presence)
    - Description: Detects urgency phrases with links (e.g., "account suspended click here").
    - Confidence: `0.85`, Early Exit: `false`.
4. Rule: `L1_EXCESSIVE_CAPITALIZATION_MODERATE`
    - Type: `regex`, Confidence: `0.70`, Early Exit: `false`.
    - Detects high ratio of uppercase letters.

(Refer to `config/sms_policy_checker_rules.yml` for the complete and active set of L1 rules.)
</details>

<details>
<summary><strong>Layer 1 Processing Algorithm</strong></summary>

1. Initialize `violation_details` and `policy_category_scores` in the main message_analysis_report.
2. Set `processing_halted = false`.
3. For each loaded Layer 1 `rule` (with its pre-compiled `Regexp` objects in `compiled_patterns`):
    - a. Iterate through each `compiled_regex_pattern` in the rule.
    - b. If `compiled_regex_pattern` matches the `message_body`:
        - i. Record the finding (layer 1, rule name, description, matched text, rule's `individual_confidence`, rule's `mapped_policy_category`) in `violation_details`.
        - ii. Update `policy_category_scores` with the `individual_confidence`, taking the max if the category already has a score.
        - iii. If `rule['is_early_exit_rule']` is `true` AND `rule['individual_confidence'] >= rule['early_exit_threshold']`:
            - 1. Set `message_analysis_report.result = :fail`.
            - 2. Set `message_analysis_report.confidence = rule['individual_confidence']`.
            - 3. Set `message_analysis_report.reason = "Early Exit - Violation Category: #{rule['mapped_policy_category']}"`.
            - 4. Set `processing_halted = true`.
            - 5. Break from all L1 rule processing.
        - iv. Break from processing more patterns for the current rule (one match is enough).
    - c. If `processing_halted` is `true`, break from the L1 rule loop.

4. If `processing_halted` is `true`, Layer 2 analysis is skipped.
</details>

<details>
<summary><strong>Layer 2: Advanced LLM-Powered Analysis (Google Cloud Ecosystem)</strong></summary>

**Purpose**
To perform deep, contextual analysis for messages not flagged by L1 early-exit rules, identifying nuanced violations against 19 policy characteristics.

**Defined Layer 2 Policy Characteristics**
The service assesses against characteristics like:
- `MisleadingSenderIdentity`
- `FalseOrInaccurateContent`
- `HatefulContent`
- `ServiceInterferenceOrFilterEvasion`
- `SHAFT_Sex_AdultContent`
- `SHAFT_Alcohol_ProhibitedPromotion`
- `SHAFT_Firearms_IllegalPromotion`
- `SHAFT_Tobacco_ProhibitedPromotion`
- `ProhibitedSubstances_CannabisCBDKratom`
- `RegulatedPharmaceuticals_PrescriptionOffers`
- `FraudulentOrMaliciousContent`
- `HighRiskFinancialServices`
- `ProhibitedAffiliateMarketing`
- `RestrictedDebtCollection`
- `GetRichQuickSchemes`
- `GamblingPromotions`
- `PhishingAndDeceptiveURLs`
- `ProhibitedPublicURLShorteners`
- `AdvancedContentEvasionTactics`

(Note: Categories requiring external message metadata like consent status are currently out of scope.)

**Trigger Condition**
Layer 2 executes if Layer 1 does not trigger an early exit.

**Core Engine: Google Gemini API**(`Google::GeminiClient`)
- For each relevant policy characteristic, Gemini is prompted to assess the message against that specific characteristic, considering the message text, curated policy context, and signals from auxiliary APIs.
- Prompts instruct Gemini to return a JSON object with `confidence_score` (0.0-1.0) and `rationale` (text). This is enforced by `responseSchema` in the API call.

**Auxiliary APIs & Integration**
Signals from these APIs are gathered by `SmsPolicyCheckerService` and fed into Gemini prompts:
- Google Safe Browse API (`Google::SafeBrowseClient`): URL threat information.
- Google Natural Language API (`Google::NlClient`): Entity extraction and text moderation scores. (Note: The original design mentioned Perspective API, but the implementation uses Cloud Natural Language API's `moderateText` feature, which provides similar signals.)

These signals also inform relevancy checks for characteristics (e.g., skipping URL-based checks if no URLs are present). If an auxiliary API fails, it's noted in the prompt, and characteristics dependent on its data for relevancy checks default to being relevant.
</details>

<details>
<summary><strong>Layer 2 Processing Algorithm</strong></summary>

1, Gather Auxiliary API Signals: Call Safe Browse (for URLs), NL API (entities, moderation) for the `message_body`. Store these results. If any of these crucial API calls fail in a way that triggers the `handle_api_errors_and_fallback` mechanism in `SmsPolicyCheckerService`, `processing_mode` is set to `:fallback_layer1_only`, and further L2 processing for characteristics is aborted.

2. For each configured Layer 2 policy `characteristic` (from `sms_policy_checker_llm_config.yml`):
    - a. Determine Relevancy: Based on relevancy_skip_conditions in the characteristic's config and pre-fetched auxiliary signals (e.g., skip "PhishingAndDeceptiveURLs" if no URLs are in the message). If a characteristic is deemed not relevant, its assessment is skipped, and its score remains 0 or it's noted in violation details.
    - b. If relevant:
        - i. **Construct Prompt:** Build a specific prompt for Gemini using the characteristic's `prompt_template`, `knowledge_source_context`, the `message_body`, and formatted summaries of the auxiliary API signals.
        - ii. **Call Gemini API:** Send the prompt to Gemini, requesting a JSON response adhering to the schema: `{ "confidence_score": Number, "rationale": String }`.
        - iii. **Handle API Errors:** If the Gemini call fails (and triggers fallback via `handle_api_errors_and_fallback`), set `processing_mode = :fallback_layer1_only` and break from L2 characteristic processing.
        - iv. **Parse Response:** Extract `confidence_score` and `rationale` from Gemini's JSON response.
        - v. **Record Finding:** Add a `violation_detail` (layer 2, type "Gemini:[CharacteristicName]", Gemini's rationale, Gemini's score, the characteristic name as `policy_category`).
        - vi. **Update Scores:** Update `policy_category_scores` for this characteristic with Gemini's score (taking the max if already present, though for L2 each characteristic is distinct).
        - vii. **Critical L2 Check:** If the `confidence_score` for this characteristic meets or exceeds its threshold defined in `CRITICAL_FAILURE_THRESHOLDS` (from `sms_policy_checker_thresholds.yml`):
            - 1. Set `message_analysis_report.result = :fail`.
            - 2. Set `message_analysis_report.confidence = [Gemini's score]`.
            - 3. Set `message_analysis_report.reason = [CharacteristicName]`.
            - 4. Break from processing further L2 characteristics (critical failure found).

3. If a critical L2 failure occurred, proceed to overall algorithm step 5 (Rewrite).
</details>

<details>
<summary><strong>Final Decision Logic & Overall Algorithm (Simplified)</strong></summary>

1. **Initialize Report:** Defaults to `result: :pass`, `processing_mode: :full_analysis`.
2. **Run Layer 1:**
    - If L1 early exit occurs: `result`, `reason`, `confidence` are set. Skip to step 4 (Rewrite).
3. **Run Layer 2 (if no L1 early exit and not already in fallback):**
    - Process each relevant characteristic.
    - If `handle_api_errors_and_fallback` is triggered during L2 setup or a Gemini call:
        - `processing_mode` becomes `:fallback_layer1_only`.
        - L2 characteristic loop is exited.
        - The final result will be determined based only on L1 scores as per Fallback Mode logic (see below). Skip to step 4 (Rewrite, which will be skipped in fallback).
- If a critical L2 failure occurs (characteristic score >= its critical threshold):
    - `result`, `reason`, `confidence` are set. Skip to step 4 (Rewrite).
- **If L2 completes without critical failures or API-triggered fallback:**
    - Calculate `max_observed_score` from all `policy_category_scores` (L1 non-early-exit + L2).
    - Set `report.confidence = max_observed_score`.
    - If `max_observed_score >= FINAL_THRESHOLD_FLAG` (from `thresholds.yml`):
        - `report.result = :fail`, `report.reason = [category_with_max_score]`.
    - Else:
        - `report.result = :pass`, `report.reason = "Compliant"`.
4. **Message Rewrite Suggestion:**
- Attempted if `report.result == :fail` AND `report.processing_mode == :full_analysis`.
- Calls Gemini with a specific prompt to get a fix or an "uncorrectable" assessment.
- Populates `report.rewrite_suggestion` with Hash, String, or `nil`.

5. Return `message_analysis_report`.
</details>

<details>
<summary><strong>Fallback Mode: API Unavailability</strong></summary>

- **Trigger:** Persistent failures in essential Layer 2 API calls (Gemini, or auxiliary APIs if their failure prevents L2 from proceeding meaningfully). The `handle_api_errors_and_fallback` method in `SmsPolicyCheckerService` manages this transition.

- Behavior:
    1. `message_analysis_report.processing_mode` is set to `:fallback_layer1_only`.
    2. Layer 2 processing for characteristics stops.
    3. `rewrite_suggestion` will be `nil`.
    4. Final decision is based solely on Layer 1 findings:
        - **L1 Early Exit (already handled):** If an L1 early exit rule triggered before the API failure, its outcome stands, but the reason string will include "Fallback:" prefix if the fallback mode was set prior to the L1 reason being finalized. (The `SmsPolicyCheckerService` logic ensures reason strings reflect the mode).
        - **L1 Threshold Assessment (if no L1 early exit):**
            - Let `max_l1_score` be the highest score from L1 `violation_details`.
            - If `max_l1_score >= FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK` (from `thresholds.yml`):
                - `result = :fail`, `confidence = max_l1_score`.
                - `reason = "Fallback: Layer 1 Threshold Exceeded - Violation Category: [category_of_max_l1_rule]"`.
            - Else:
                - `result = :pass`, `confidence = max_l1_score`.
                - `reason = "Fallback: Compliant."`.
- `violation_details` and `policy_category_scores` will only contain Layer 1 findings and any `API_FALLBACK:...` details.
</details>

<details>
<summary><strong>Efficiency & Scalability Considerations</strong></summary>

- **Single Message Processing:** The service interface (`call` method) processes one message at a time to maintain simplicity and testability.
- **Layer 1 Pre-filtering:** Optimizes by quickly handling clear violations locally.
- **External Parallel Processing:** High-volume screening (e.g., 10k+ messages) is intended to be managed by the calling application, for example, by using background job systems like Sidekiq to run `SmsPolicyCheckerService.call` for individual messages in parallel worker processes.
</details>

## Running Tests
The project uses RSpec for testing. The main test suite (`spec/services/sms_policy_checker_service_spec.rb`) focuses on **live integration tests** with Google APIs.

**Prerequisites for Live Tests:**
1. `GOOGLE_API_KEY` **Environment Variable:** Must be set with a valid Google Cloud API key that has Safe Browse, Natural Language, and Generative Language (Gemini) APIs enabled. Live tests will be skipped if this key is not set or is a placeholder value.
2. **Configuration Files:** All YAML configuration files (`sms_policy_checker_rules.yml`, `sms_policy_checker_llm_config.yml`, `sms_policy_checker_thresholds.yml`) must be present and correctly structured in the `config/` directory.
3. **Internet Connection:** Required for all API calls.
4. **Awareness of Costs/Rate Limits:** Live API calls will incur costs on your Google Cloud account and are subject to rate limits. Run judiciously.

**Commands:**
- Run all RSpec tests:
```bash
    bundle exec rspec
 ```
- Run only the service specs:
```bash
    bundle exec rspec spec/services/sms_policy_checker_service_spec.rb
```

### Maintainer(s)
- [Connor Baldes](https://github.com/ConnorBaldes)
