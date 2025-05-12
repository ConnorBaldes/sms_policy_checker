# SMS Policy Checker

A Ruby on Rails service to analyze SMS messages for policy compliance using a hybrid AI (LLM + rules) approach to mitigate carrier filtering and provide actionable feedback.

## Description

The `SmsPolicyCheckerService` is designed to proactively analyze SMS message content *before* transmission (e.g., via Twilio). Its primary goal is to identify potential policy violations that could lead to carrier filtering (often manifesting as Twilio error 30007) or other deliverability issues. By providing structured, detailed feedback on messages, this service helps users understand and rectify problematic content, thereby improving message deliverability and compliance with communication policies related to phishing, SHAFT (Sex, Hate, Alcohol, Firearms, Tobacco), misleading sender information, and more.

Built as a Ruby on Rails service object, it accepts an SMS message body as input and returns a comprehensive analysis report. The architecture leverages a multi-layered filtering strategy, combining rapid, deterministic rule-based checks (Layer 1) with sophisticated, context-aware Large Language Model (LLM) analysis (Layer 2) powered by Google's Gemini API and supported by Google Cloud's Natural Language and Safe Browse APIs.

## Table of Contents

* [Key Features](#key-features)
* [Architecture Overview](#architecture-overview)
* [Project Directory Structure](#project-directory-structure)
* [Installation](#installation)
* [Configuration](#configuration)
    * [API Key](#api-key)
    * [YAML Configuration Files](#yaml-configuration-files)
* [Usage](#usage)
* [Service Output Details (API)](#service-output-details-api)
    * [Output Structure: `message_analysis_report`](#output-structure-message_analysis_report)
    * [Example Report (Failure)](#example-report-failure)
    * [Example Report (Pass in Fallback)](#example-report-pass-in-fallback)
* [Detailed Design and Processing Logic](#detailed-design-and-processing-logic)
    * [Layer 1: Rule-Based Pre-filters](#layer-1-rule-based-pre-filters)
    * [Layer 2: Advanced LLM-Powered Analysis](#layer-2-advanced-llm-powered-analysis)
    * [Final Decision Logic & Overall Algorithm](#final-decision-logic--overall-algorithm)
    * [Fallback Mode: API Unavailability](#fallback-mode-api-unavailability)
    * [Efficiency & Scalability Considerations](#efficiency--scalability-considerations)
* [Running Tests](#running-tests)
* [Maintainer(s)](#maintainers)
* [Contributing](#contributing)
* [License](#license)

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
- result (Symbol): Overall outcome. Either :pass or :fail.
- reason (String): A human-readable explanation for the outcome. Examples:
    - If Layer 2 failure: "PhishingAndDeceptiveURLs"
    - If Layer 1 Early Exit: "Early Exit - Violation Category: [mapped_policy_category]"
    - If Fallback L1 Early Exit: "Fallback: Early Exit - Violation Category: [mapped_policy_category]"
    - If Fallback L1 Threshold Failure: "Fallback: Layer 1 Threshold Exceeded - Violation Category: [category]"
    - If Pass: "Compliant" or "Fallback: Compliant."
- confidence (Float): Score (0.0-1.0+) representing confidence in the violation if :fail, or the highest score observed if :pass (will be below the flagging threshold).
- rewrite_suggestion (Hash | String | nil):
    - Hash: If LLM deems correctable: { "general_fix_suggestions": String, "literal_rewrite": String }.
    - String: If LLM deems uncorrectable: "This message cannot be made compliant due to: [reason]".
    - nil: If no suggestion is applicable/generated, or in fallback mode.
- processing_mode (Symbol): :full_analysis or :fallback_layer1_only.
- policy_category_scores (Hash): Scores for all assessed policy categories (e.g., {"PhishingAndDeceptiveURLs" => 0.98, "SHAFT_Sex_AdultContent" => 0.15}).
- violation_details (Array<Hash>): List of all individual findings. Each detail hash includes:
    - layer (Integer): 1 or 2.
    - filter_type (String): Rule name (e.g., "L1_PUBLIC_URL_SHORTENER_SEVERE") or LLM analysis type (e.g., "Gemini:PhishingAndDeceptiveURLs", "API_FALLBACK:gemini_call_failed").
    - description (String): Description of the finding or LLM rationale.
    - matched_value (String | "N/A"): Specific text/URL matched by L1, or "N/A" for L2/fallback.
    - individual_confidence (Float): Confidence of this specific finding.
    - policy_category (String): Policy category this finding pertains to.

<details>
<summary><strong>Example message_analysis_report (Failure with Rewrite)</strong></summary>

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



