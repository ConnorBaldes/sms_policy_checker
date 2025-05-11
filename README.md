# SMS Message Policy Checker: Design and Implementation Details



# Trial Project: SMS Message Policy Checker

## Project Directory
```bash
sms_policy_checker_app/
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
│           ├── perspective_client.rb
│           └── nl_client.rb
├── config/
│   ├── initializers/
│   │   └── sms_policy_checker_config.rb   # To load YAML configs on boot
│   ├── sms_policy_checker_rules.yml       # Layer 1 rules
│   ├── sms_policy_checker_llm_config.yml  # Layer 2 LLM characteristics and prompts
│   └── sms_policy_checker_thresholds.yml  # Various decision thresholds
└── README.md
```

## 1. Project Goal & Overview

The primary goal of the `SmsPolicyCheckerService` is to analyze SMS message content *before* it is sent via Twilio, identify potential policy violations that could lead to carrier filtering (specifically Twilio error 30007), and provide structured feedback. This service aims to reduce message blocking by flagging problematic content related to phishing, SHAFT (Sex, Hate, Alcohol, Firearms, Tobacco), misleading sender information, and other carrier or Twilio policy violations.

The service is designed as a Ruby on Rails service object, accepting a message body as input and returning a detailed, structured analysis result. It incorporates a multi-layered filtering approach, leveraging both rapid rule-based checks and advanced Large Language Model (LLM) capabilities through Google's Gemini API and associated Google Cloud services.

## 2. Core Service Object: `SmsPolicyCheckerService`

### 2.1. Interface

* **Class:** `SmsPolicyCheckerService`
* **Location:** `app/services/sms_policy_checker_service.rb`
* **Primary Method:** A class method `call` for easy invocation.
    * **Input:** `message_body` (String): The raw text content of the SMS message to be analyzed.
    * **Output:** A `Hash` representing a structured `message_analysis_report`.

### 2.2. Output Structure: `message_analysis_report`

The service returns a comprehensive hash with the following keys:

* `result` (Symbol): Overall outcome. Either `:pass` or `:fail`.
* `reason` (String): A human-readable explanation for the outcome.
    * If `:fail`: Describes the primary policy category or rule that caused the failure. Examples:
        * For Layer 2 failures (in `:full_analysis` mode): "Phishing & Deceptive URLs"
        * For Layer 1 Early Exits (when `processing_mode` is `:full_analysis` because Layer 2 was intentionally skipped): "Early Exit - Violation Category: [mapped_policy_category]"
        * For Layer 1 Early Exits (when `processing_mode` is `:fallback_layer1_only`): "Fallback: Early Exit - Violation Category: [mapped_policy_category]"
        * For Layer 1 Threshold Failures (when `processing_mode` is `:fallback_layer1_only`): "Fallback: Layer 1 Threshold Exceeded - Violation Category: [mapped_policy_category_of_max_l1_score_rule]"
    * If `:pass`: Indicates compliance. Examples:
        * When `processing_mode` is `:full_analysis`: "Compliant"
        * When `processing_mode` is `:fallback_layer1_only`: "Fallback: Compliant."
* `confidence` (Float): A score between 0.0 and 1.0 representing the service's confidence in the *violation* (if `result: :fail`) or the highest score of any checked policy if it passed (if `result: :pass`, this score will be below the flagging threshold). A score of `0.0` generally indicates full confidence of no violation found by the checks performed.
* `rewrite_suggestion` (Hash | String, Optional): If the message failed and `processing_mode` is `:full_analysis`, the LLM will attempt to provide a suggestion. The content of this field will be:
    * A **Hash** if the LLM deems the message correctable, containing:
        * `general_fix_suggestions` (String): General advice from the LLM on how to avoid the identified violation.
        * `literal_rewrite` (String): The LLM's actual suggested rewritten text for the message.
    * A **String** (e.g., "This message cannot be made compliant due to: [LLM-provided reason]") if the LLM determines the original message is uncorrectable.
    * `nil` if the LLM provides neither the Hash suggestion nor the "uncorrectable" string assessment (e.g., due to an inability to generate the suggestion, an API error during the rewrite attempt, or if the LLM's output is not in the expected format). It will also be `nil` if `processing_mode` is `:fallback_layer1_only`.
* `processing_mode` (Symbol): Indicates how the analysis was performed.
    * `:full_analysis`: Both Layer 1 and Layer 2 (LLM analysis) were completed.
    * `:fallback_layer1_only`: Due to API unavailability, only Layer 1 rule-based checks were performed.
* `policy_category_scores` (Hash): A hash where keys are internal `policy_category` strings (e.g., "Phishing," "SHAFT-Hate") and values are the final confidence scores (0.0-1.0) for each category assessed for the message. This shows the score for *all* categories that had findings, not just the primary reason for failure.
    * Example: `{"Phishing": 0.95, "SHAFT-Sex": 0.2, "Content-Evasion-Spam": 0.65}`
* `violation_details` (Array of Hashes): A comprehensive list of all individual findings (both from Layer 1 rules and Layer 2 LLM analysis) that contributed to the analysis, regardless of whether they directly caused a failure. Each hash contains:
    * `layer` (Integer): 1 or 2.
    * `filter_type` (String): The specific rule name (e.g., "L1_PUBLIC_URL_SHORTENER") or LLM analysis type (e.g., "Gemini:Phishing," "Perspective:TOXICITY").
    * `description` (String): A human-readable description of the finding (e.g., "Matched public URL shortener bit.ly," Gemini's rationale for a Phishing assessment, "Perspective API TOXICITY score exceeded moderate threshold").
    * `matched_value` (String, Optional): The specific text snippet or URL that triggered the rule or was focused on by the LLM.
    * `individual_confidence` (Float): The confidence score assigned by that specific rule or LLM analysis for this particular finding.
    * `policy_category` (String): The internal policy category this finding pertains to.

**Example `message_analysis_report` (Failure):**

```json
{
  "result": ":fail",
  "reason": "Phishing & Deceptive URLs",
  "confidence": 0.98,
  "rewrite_suggestion": "To update your account, please visit our official website [example.com/support](https://example.com/support) or call us directly. Do not click unverified links.",
  "processing_mode": ":full_analysis",
  "policy_category_scores": {
    "Phishing": 0.98,
    "Prohibited-URL-Shortener": 0.90,
    "SHAFT-Sex": 0.15
  },
  "violation_details": [
    {
      "layer": 1,
      "filter_type": "L1_PUBLIC_URL_SHORTENER",
      "description": "Detected public URL shortener: t.ly/example",
      "matched_value": "t.ly/example",
      "individual_confidence": 0.90,
      "policy_category": "Prohibited-URL-Shortener"
    },
    {
      "layer": 2,
      "filter_type": "Gemini:Phishing",
      "description": "The message uses urgent language typical of phishing ('urgent action required') combined with an unverified shortened URL that redirects to a suspicious domain. Google Safe Browse also flagged the destination URL for SOCIAL_ENGINEERING.",
      "matched_value": "urgent action required, visit t.ly/example",
      "individual_confidence": 0.98,
      "policy_category": "Phishing"
    }
    // ... other details if any
  ]
}
```
**Example message_analysis_report (Pass in Fallback):**

```json
{
  "result": ":pass",
  "reason": "Fallback: Compliant.",
  "confidence": 0.70,
  "rewrite_suggestion": null,
  "processing_mode": ":fallback_layer1_only",
  "policy_category_scores": {
    "Content-Evasion-Spam": 0.70
  },
  "violation_details": [
    {
      "layer": 1,
      "filter_type": "L1_EXCESSIVE_CAPITALIZATION",
      "description": "Message contains a high ratio of uppercase characters.",
      "matched_value": "URGENT ATTENTION NEEDED CLICK NOW",
      "individual_confidence": 0.70,
      "policy_category": "Content-Evasion-Spam"
    }
  ]
}
```

### 2.3 Processing Model

The service object is designed for **Single Message Processing**. The `call` method accepts one `message_body` and returns one `message_analysis_report`.
**Why:** This simplifies the internal logic of the service object, making it easier to develop, test, and maintain. High-volume screening (10k+ messages) is intended to be handled by an external orchestration layer (e.g., multiple Sidekiq background job workers, each invoking the service for a single message), allowing for parallel processing and scalability.


## 3. Overall Architectural Design: A Two-Layer Sequential Filtering Approach
The service employs a sequential, two-layer filtering process for efficiency and depth of analysis:

1. Layer 1 (Rule-Based Pre-filters): The message is first processed by a series of fast, locally executable rules. If a high-confidence, severe violation is detected and designated as an "early exit" rule, processing stops, and Layer 2 is skipped.

2. Layer 2 (Advanced LLM-Powered Analysis): If the message passes Layer 1 (i.e., no early exit), it proceeds to Layer 2 for more nuanced analysis using Google's Gemini API and other supporting Google Cloud APIs.

**Why:** This sequential model ensures that obvious, common violations are caught quickly and cheaply by Layer 1, reserving the more resource-intensive LLM analysis of Layer 2 for messages requiring deeper contextual understanding. This optimizes for both performance and cost.


## 4. Layer 1: Rule-Based Pre-filters

### 4.1. Purpose
- Rapid Detection: To quickly identify and flag common, unambiguous policy violations using predefined keywords and regular expressions.
- Cost & Latency Optimization: To reduce unnecessary calls to the more expensive LLM services by handling clear cases locally.
- Standalone Fallback Capability: To provide a baseline level of message screening if Layer 2 (external APIs) becomes unavailable.

### 4.2. Implementation Details
- **Configuration:** All Layer 1 rules are defined in YAML configuration files (e.g., `config/sms_policy_checker_rules.yml`). This allows rules to be updated via configuration changes and deployment, without modifying service code.

- **Rule Definition Structure (in YAML):** Each rule entry in the YAML file will have the following attributes:
    - `name` (String): A unique identifier for the rule (e.g., "L1_SHAFT_SEX_EXPLICIT_KEYWORD").
    - `description` (String): A brief explanation of what the rule checks for.
    - `type` (String): Specifies how the `patterns` are to be interpreted. Either `"keyword"` or `"regex"`.
    - `patterns` (Array of Strings): A list of pattern strings.
        - If `type` is `"keyword"`: Each string is treated as a literal keyword or phrase. The system will compile it into a case-insensitive, whole-word matching regular expression (e.g., a keyword "Alert!" becomes an internal regex like `/\bAlert!\b/i` after escaping any special characters in "Alert!").
        - If `type` is `"regex"`: Each string is treated as a regular expression pattern. The system will compile it into a `Regexp` object, typically assuming case-insensitivity by default (users can use inline modifiers like `(?i)` or `(?-i)` within the pattern string for specific case sensitivity control if needed).
        - ***Note on Runtime Processing:*** During application initialization, the `patterns` defined in the YAML for each rule are processed based on their `type`. Keyword strings are converted into robust, case-insensitive, whole-word matching regular expressions, and regex strings are compiled directly. The resulting Ruby `Regexp` objects are stored as part of the service's internal representation of each rule (e.g., in a `compiled_patterns` attribute for each rule object/hash). These pre-compiled `Regexp` objects are then exclusively used for efficient matching during the Layer 1 processing of each message, ensuring pattern matching is as fast as possible.
    - `mapped_policy_category` (String): The internal policy category this rule corresponds to (e.g., "SHAFT-Sex," "Phishing-Attempt-Basic").
    - `individual_confidence` (Float): A score (0.0-1.0) representing the confidence that a match to this rule indicates a true violation of the mapped policy category.
    - `is_early_exit_rule` (Boolean): true if a high-confidence match to this rule should cause immediate message failure and skip Layer 2; false otherwise.
    - `early_exit_threshold` (Float): If is_early_exit_rule is true, this is the individual_confidence score the rule must meet or exceed to trigger an early exit (e.g., 0.95 or 1.0).

### 4.3. Specific Layer 1 Rules (Illustrative Examples)
The following are example rules for Layer 1. (Note: Actual keyword lists and regex patterns will be more comprehensive and maintained in the YAML configuration).

1. **Rule:** `L1_SHAFT_SEX_EXPLICIT_KEYWORD`
    * **Description:** Detects unambiguously explicit sexual terms.
    * **Type:** `keyword`
    * **Example Patterns:** `["xxx", "hardcore sex", ...]` (carefully curated list)
    * **Mapped Policy Category:** `SHAFT-Sex`
    * **Individual Confidence:** `1.0`
    * **Early Exit Rule:** `true`
    * **Early Exit Threshold:** `1.0`
    * **Fallback Relevance:** Critical for blocking clear explicit content.

2. **Rule:** `L1_SHAFT_HATE_EXTREME_KEYWORD`
    * **Description:** Detects undeniable hate speech terms or racial slurs.
    * **Type:** `keyword`
    * **Example Patterns:** `["n-word", "k*k*k", ...]` (list of severe slurs)
    * **Mapped Policy Category:** `SHAFT-Hate`
    * **Individual Confidence:** `1.0`
    * **Early Exit Rule:** `true`
    * **Early Exit Threshold:** `1.0`
    * **Fallback Relevance:** Essential for blocking blatant hate speech.

3. **Rule:** `L1_SHAFT_FIREARMS_ILLEGAL_SALE_KEYWORD`
    * **Description:** Detects keywords indicating illegal sale/transfer of firearms.
    * **Type:** `keyword` (potentially with simple proximity logic if implementable via regex)
    * **Example Patterns:** `["buy Glock no papers", "sell AK47 unregistered", ...]`
    * **Mapped Policy Category:** `SHAFT-Firearms`
    * **Individual Confidence:** `0.95`
    * **Early Exit Rule:** `true`
    * **Early Exit Threshold:** `0.95`
    * **Fallback Relevance:** Catches obvious illegal firearm sale attempts.

4. **Rule:** `L1_SHAFT_ALCOHOL_TOBACCO_UNSOLICITED_PROMO_KEYWORD`
    * **Description:** Detects clear, unsolicited promotion of alcohol/tobacco, especially if age-gating context is absent.
    * **Type:** `keyword`
    * **Example Patterns:** `["free beer delivery", "cheap vapes now", ...]`
    * **Mapped Policy Category:** `SHAFT-Alcohol` (or `SHAFT-Tobacco`)
    * **Individual Confidence:** `0.85`
    * **Early Exit Rule:** `false` (Generally, as these terms can appear in legitimate contexts for training messages. An early exit would only apply if specific phrases are 100% violative for the user's message types.)
    * **Fallback Relevance:** Provides some coverage, but requires careful keyword selection.

5. **Rule:** `L1_PROHIBITED_SUBSTANCE_KEYWORD`
    * **Description:** Detects explicit mentions of federally illegal drugs or unambiguous slang.
    * **Type:** `keyword`
    * **Example Patterns:** `["heroin", "LSD", "methamphetamine", "buy fentanyl", ...]`
    * **Mapped Policy Category:** `Illegal-Substance`
    * **Individual Confidence:** `1.0` (for unambiguous terms)
    * **Early Exit Rule:** `true`
    * **Early Exit Threshold:** `1.0`
    * **Fallback Relevance:** Critical for blocking explicit mentions of hard drugs.

6. **Rule:** `L1_CANNABIS_CBD_KRATOM_PROMO_KEYWORD`
    * **Description:** Detects promotional language for Cannabis, CBD, or Kratom, which are restricted by Twilio in US/Canada.
    * **Type:** `keyword`
    * **Example Patterns:** `["buy cannabis online", "CBD oil special offer", "kratom for sale", ...]`
    * **Mapped Policy Category:** `Prohibited-Substance-CBD-Cannabis-Kratom`
    * **Individual Confidence:** `0.95` (if clearly promotional)
    * **Early Exit Rule:** `true`
    * **Early Exit Threshold:** `0.95`
    * **Fallback Relevance:** Important due to Twilio's strict stance.

7. **Rule:** `L1_PUBLIC_URL_SHORTENER`
    * **Description:** Detects the use of common, free public URL shorteners.
    * **Type:** `regex`
    * **Example Patterns:** `[/(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|ow\.ly)\/[a-zA-Z0-9]+/i]` (list will be expanded)
    * **Mapped Policy Category:** `Prohibited-URL-Shortener`
    * **Individual Confidence:** `0.90`
    * **Early Exit Rule:** `true`
    * **Early Exit Threshold:** `0.90`
    * **Fallback Relevance:** Catches a common and easily identifiable carrier violation.

8. **Rule:** `L1_PHISHING_URGENCY_KEYWORDS_WITH_LINK`
    * **Description:** Detects common phishing urgency phrases when a URL is also present.
    * **Type:** `keyword` (with regex check for any URL)
    * **Example Patterns:** Keywords like `"account suspended"`, `"verify immediately"`, `"urgent security alert"`, `"password expired"`, `"confirm your details"`. Regex for URL: `/https?:\/\/[^\s]+/i`
    * **Mapped Policy Category:** `Phishing-Attempt-Basic`
    * **Individual Confidence:** `0.80`
    * **Early Exit Rule:** `false` (Serves as a strong signal for Layer 2, as context is key for phishing).
    * **Fallback Relevance:** Provides basic phishing signal if LLM is unavailable.

9. **Rule:** `L1_EXCESSIVE_CAPITALIZATION`
    * **Description:** Detects excessive use of uppercase letters, a common spam indicator.
    * **Type:** `regex`
    * **Example Patterns:** `[/(?:[A-Z]\s*){15,}/]` (e.g., 15 or more capital letters, possibly separated by spaces, indicating a large portion of the message is capitalized or contains long capitalized sequences. This regex might need refinement based on message length considerations).
    * **Mapped Policy Category:** `Content-Evasion-Spam`
    * **Individual Confidence:** `0.70`
    * **Early Exit Rule:** `false`
    * **Fallback Relevance:** Catches a common spam tactic.

10. **Rule:** `L1_EXCESSIVE_SPECIAL_CHARACTERS`
    * **Description:** Detects an unusually high ratio or long sequences of special characters.
    * **Type:** `regex`
    * **Example Patterns:** `[/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\s]{7,}/]` (e.g., 7 or more consecutive special characters or spaces, indicating potential obfuscation).
    * **Mapped Policy Category:** `Content-Evasion-Spam`
    * **Individual Confidence:** `0.70`
    * **Early Exit Rule:** `false`
    * **Fallback Relevance:** Catches another spam/evasion tactic.

### 4.4. Layer 1 Processing Logic Algorithm

The following steps are executed when Layer 1 processing is invoked:

1.  **Initialization (within the main `message_analysis_report` which is being built):**
    * Ensure `violation_details` is an empty list.
    * Ensure `policy_category_scores` is an empty hash.
    * (These are typically initialized when the `message_analysis_report` is first created, as per Section 6.1).
2.  **Set Control Flag:**
    * `processing_halted = false`.
3.  **Iterate Through Loaded Layer 1 Rules:**
    * For each `rule` in the service's loaded and pre-processed collection of Layer 1 rules (where each `rule` now contains its `name`, `description`, `individual_confidence`, `mapped_policy_category`, `is_early_exit_rule`, `early_exit_threshold`, and its `compiled_patterns` which is an array of `Regexp` objects):
        * a.  Set `found_match_for_this_rule = false`.
        * b.  Set `matched_text_for_this_rule = nil`.
        * c.  **Apply Compiled Patterns:** Iterate through each `compiled_regex_pattern` in the `rule['compiled_patterns']` list:
            * i.  Attempt to match `compiled_regex_pattern` against the `message_body`.
            * ii. If a match is successful (e.g., `match_data = compiled_regex_pattern.match(message_body)` returns a `MatchData` object):
                1.  Set `found_match_for_this_rule = true`.
                2.  Set `matched_text_for_this_rule = match_data[0]` (capturing the full text that matched the pattern).
                3.  **Break** from iterating through this specific rule's `compiled_regex_pattern` list (as one pattern match is sufficient to consider the rule triggered).
        * d.  **Process Finding if Match Occurred:** If `found_match_for_this_rule` is `true`:
            * i.  Construct a `violation_detail` hash:
                * `layer: 1`
                * `filter_type: rule['name']`
                * `description: rule['description']`
                * `matched_value: matched_text_for_this_rule`
                * `individual_confidence: rule['individual_confidence']`
                * `policy_category: rule['mapped_policy_category']`
            * ii. Add this `violation_detail` to `message_analysis_report.violation_details`.
            * iii.Update `message_analysis_report.policy_category_scores`:
                * Let `category = rule['mapped_policy_category']`.
                * Let `current_score = rule['individual_confidence']`.
                * If `category` already exists in `policy_category_scores`, set its value to `[policy_category_scores[category], current_score].max`.
                * Else, add `category` with `current_score`.
            * iv. **Check for Early Exit:**
                * If `rule['is_early_exit_rule']` is `true` AND `rule['individual_confidence'] >= rule['early_exit_threshold']`:
                    1.  Set `message_analysis_report.result = :fail`.
                    2.  Set `message_analysis_report.confidence = rule['individual_confidence']`.
                    3.  Set `message_analysis_report.reason = "Early Exit - Violation Category: #{rule['mapped_policy_category']}"`. (This is for an early exit when `processing_mode` is initially `:full_analysis`. Section 7 handles `reason` if in fallback mode).
                    4.  Set `processing_halted = true`.
        * e.  If `processing_halted` became `true` in the step above (due to an early exit), **break** from the main loop that iterates through all Layer 1 `rule` definitions (as processing stops).

4.  **Conclude Layer 1:**
    * If `processing_halted` is `true` (due to a Layer 1 early exit), Layer 2 analysis is skipped. The `message_analysis_report` (with fields like `result`, `reason`, `confidence` set by the early exit rule) is now substantially complete from Layer 1's perspective. (The overall algorithm in Section 6 will then proceed to step 5 for rewrite suggestions if applicable).


# 5. Layer 2: Advanced LLM-Powered Analysis (Google Cloud Ecosystem)

## 5.1. Purpose
To perform a deep, contextual analysis of messages that are not definitively flagged by Layer 1's high-confidence early-exit rules. Layer 2 aims to identify nuanced violations, interpret subtleties, and synthesize multiple signals to assess compliance against a comprehensive list of 19 policy characteristics.

### 5.1.1 Defined Layer 2 Policy Characteristics

Layer 2 analysis involves prompting the Gemini API against each of the following 19 defined policy characteristics. For each characteristic, a curated snippet from relevant "Knowledge Sources" (e.g., Twilio's Acceptable Use Policy, Messaging Policy, and general carrier guidelines) is provided as additional context to the LLM to help guide its assessment.

The list of characteristics is configurable, but the core set includes:

1.  **`MisleadingSenderIdentity`**: Assesses if the sender is not clearly or accurately identified, or if there are signs of impersonation.
2.  **`FalseOrInaccurateContent`**: Evaluates if the content is verifiably false, misleading, or could deceive a recipient.
3.  **`HatefulContent`**: Screens for content promoting hate, discrimination, disparagement, or violence against protected groups (Corresponds to SHAFT-H).
4.  **`ServiceInterferenceOrFilterEvasion`**: Identifies tactics used specifically to evade detection systems or interfere with service operations (distinct from general content evasion patterns addressed by `AdvancedContentEvasionTactics`).
5.  **`SHAFT_Sex_AdultContent`**: Checks for explicit adult content, themes, or solicitation inappropriate for general SMS or violating SHAFT-S policies.
6.  **`SHAFT_Alcohol_ProhibitedPromotion`**: Assesses promotions of alcohol for compliance with age-gating, local laws, and carrier restrictions (SHAFT-A).
7.  **`SHAFT_Firearms_IllegalPromotion`**: Evaluates promotions or sales of firearms, particularly those that are illegal, unregulated, or under high scrutiny (SHAFT-F).
8.  **`SHAFT_Tobacco_ProhibitedPromotion`**: Screens promotions of tobacco, nicotine, or vaping products for compliance with age-gating, local laws, and carrier restrictions (SHAFT-T).
9.  **`ProhibitedSubstances_CannabisCBDKratom`**: Specifically checks for content related to Cannabis, CBD, or Kratom, which have stringent carrier restrictions.
10. **`RegulatedPharmaceuticals_PrescriptionOffers`**: Identifies offers for prescription medications or other regulated pharmaceuticals not permissible over-the-counter or via unsolicited SMS.
11. **`FraudulentOrMaliciousContent`**: Detects broader fraudulent claims, scams, or content indicative of malicious intent beyond specific phishing attempts.
12. **`HighRiskFinancialServices`**: Screens for promotions of high-risk financial products like payday loans, debt relief programs with questionable claims, or certain types of cryptocurrency offerings.
13. **`ProhibitedAffiliateMarketing`**: Identifies messages primarily focused on third-party lead generation or affiliate marketing schemes that are often restricted.
14. **`RestrictedDebtCollection`**: Assesses messages related to third-party debt collection for compliance with regulations and carrier policies.
15. **`GetRichQuickSchemes`**: Filters promotions for unrealistic financial schemes, work-from-home scams, or pyramid schemes.
16. **`GamblingPromotions`**: Checks for the promotion of gambling content, which is highly regulated and often restricted.
17. **`PhishingAndDeceptiveURLs`**: Focuses on attempts to fraudulently obtain sensitive information or the use of misleading/harmful URLs.
18. **`ProhibitedPublicURLShorteners`**: Assesses the use of common public URL shorteners if not caught by Layer 1, as these are often flagged by carriers.
19. **`AdvancedContentEvasionTactics`**: Uses LLM capabilities to detect nuanced content evasion techniques (e.g., subtle misspellings, unusual Unicode, complex rephrasing) that might bypass simpler Layer 1 regex/keyword checks.

***Note on Excluded Categories for Future Consideration:*** Characteristics like `A2P 10DLC Non-Compliance`, `Lack of Valid Consent`, and `IllegalContentJurisdictional` were excluded from the current scope as they require message metadata beyond the `message_body` itself (e.g., campaign registration details, consent status, recipient jurisdiction). Future iterations of the service could potentially incorporate these if such metadata can be provided as additional input.

## 5.2. Trigger Condition
Layer 2 analysis is executed only if Layer 1 processing completes without triggering an "early exit."

## 5.3. Core Engine: Google Gemini API
- **Role:** Gemini acts as the central "brain" for Layer 2. For each of the 19 defined policy characteristics relevant to the message, Gemini is specifically prompted to assess that characteristic. It considers the message text along with contextual information provided by auxiliary APIs.
- **Prompting Strategy: Direct Category Prompting:**
    - For each policy characteristic (e.g., "Phishing," "Hateful Content," "SHAFT-Alcohol"), a unique, carefully crafted prompt is sent to the Gemini API.
    - This prompt explicitly asks Gemini to evaluate the message against that specific characteristic and to return a confidence score (0.0-1.0) indicating the likelihood of violation, along with a brief textual rationale for its assessment.
    - Example **Prompt for "Phishing" Characteristic:**

    ```bash
        Analyze the following SMS message content and associated information for 'Phishing' indicators.
        Message Body: '[message_body_text_here]'
        Associated URL (if any): '[URL_here_or_N/A]'
        Google Safe Browse API Result for URL: '[SafeBrowse_status_or_N/A]'
        Policy Context for PhishingAndDeceptiveURLs:
        "[Curated text from Knowledge Source, e.g., 'Phishing is any attempt to deceptively acquire sensitive information. Misleading links are prohibited. (Source: Twilio AUP, Carrier Policies)']"

        Based on all the above, including the provided policy context, assess the likelihood that this message constitutes a 'Phishing' attempt according to standard industry definitions (e.g., attempts to deceptively acquire sensitive
        information like usernames, passwords, credit card details, or other personal data).

        Provide your response as a JSON object with two keys:
        1. "phishing_confidence_score": A float between 0.0 (no confidence of phishing) and 1.0
            (high confidence of phishing).
        2. "phishing_rationale": A brief textual explanation for your score.
    ```

    - Similar specific prompts are designed for each of the 19 policy characteristics, tailoring the input signals and descriptive criteria.
    - **Why this strategy?** Direct Category Prompting gives precise control over what Gemini evaluates, aligns its output directly with the service's internal policy categories, and makes parsing responses straightforward, largely obviating the need for a complex `LLM_CATEGORY_MAPPING` system.

## 5.4. Auxiliary APIs & Their Integration as Inputs to Gemini
***Overall Approach to Auxiliary APIs for Layer 2:*** These specialized APIs are primarily used to gather contextual signals that are fed into the Gemini prompts for each relevant policy characteristic. Additionally, the data (or absence thereof) obtained from these APIs during an initial pre-analysis phase (e.g., presence of URLs, extracted entities from Cloud NL) also informs the decision of whether a specific Layer 2 characteristic is relevant for the current message, helping to optimize LLM calls. If an auxiliary API call intended to provide data for a relevancy check fails (e.g., Cloud NL API is temporarily unavailable), the system is designed to robustly default to considering the dependent characteristics as relevant, ensuring they are still assessed by Gemini rather than being incorrectly skipped.

- **Google Safe Browse API (`threatMatches.find`):**
    - All URLs extracted from the `message_body` are submitted.
    - The API response (e.g., `threatType`: `MALWARE`, `SOCIAL_ENGINEERING`, `POTENTIALLY_HARMFUL_APPLICATION`, `UNWANTED_SOFTWARE`, or no threat found) for each URL is provided to Gemini prompts for characteristics like "Phishing & Deceptive URLs," "Fraudulent or Malicious Content."

- **Google Perspective API (`comments.analyze`):**
    - The `message_body` is sent to Perspective API requesting scores for attributes such as `TOXICITY`, `SEVERE_TOXICITY`, `IDENTITY_ATTACK`, `INSULT`, `PROFANITY`, `THREAT`, `SEXUALLY_EXPLICIT`.
    - These numerical scores (0.0-1.0) are provided to Gemini prompts for relevant characteristics like "Hateful Content," "SHAFT-Sex," "Misleading Sender Identity/Origin" (if tone is aggressive/insulting), etc.

- **Google Cloud Natural Language API (`analyzeEntities`, `analyzeSyntax`):**
    - Used to pre-process the `message_body` for tasks like:
        - Extracting entities (names of people, organizations, locations, products like drug names via `analyzeEntities`).
        - Potentially identifying unusual syntactic structures or token patterns via `analyzeSyntax` if needed for specific evasion detection characteristics.
    - These extracted entities or structural observations are provided as context to Gemini for specific prompts (e.g., when assessing "Prescription Medication Offers," extracted drug names are crucial).

## 5.5. Layer 2 Processing Logic Algorithm
1. For each of the 19 policy characteristics defined for Layer 2 analysis (this list of characteristics is configurable):
    * a. **Determine if this characteristic is relevant for LLM assessment:**
        This step aims to optimize LLM calls by skipping assessment for characteristics that are clearly inapplicable based on pre-analyzed message features. The system defaults to considering a characteristic relevant unless specific conditions to skip it are met and the data needed to evaluate those conditions is available.

        * i. **Pre-Analysis of Message Features (performed once before this loop):**
            * Extract URLs (Regex): `message_features['urls_present']` (boolean), `message_features['url_list']` (array).
            * Attempt Google Cloud NL API Call: `message_features['nl_api_call_succeeded']` (boolean), `message_features['nl_api_entities']` (array of entities, or empty if call failed or no entities found).
            * (Other pre-analysis steps can be added here as the system evolves).

        * ii. **Evaluate Relevancy for the Current `[CharacteristicName]`:**
            1. Assume `is_relevant_for_llm = true` by default.
            2. Retrieve any `relevancy_skip_conditions` defined for the current `[CharacteristicName]` from its YAML configuration (see Section 8). These conditions specify situations where the LLM check can be skipped.
            3. If `relevancy_skip_conditions` are defined, evaluate them:
                * **Example Condition Type 1: `skip_if_no_urls`** (used for `PhishingAndDeceptiveURLs`, `ProhibitedPublicURLShorteners`):
                    * If a condition is `{"type": "skip_if_no_urls"}` AND `message_features['urls_present']` is `false`, then set `is_relevant_for_llm = false`.
                * **Example Condition Type 2: `skip_if_no_specific_entities`** (e.g., for `RegulatedPharmaceuticals_PrescriptionOffers`, condition might be `{"type": "skip_if_no_specific_entities", "entity_type": "DRUG"}`):
                    * If such a condition exists AND `message_features['nl_api_call_succeeded']` is `true` AND the required entities (e.g., "DRUG") are *not* found in `message_features['nl_api_entities']`, then set `is_relevant_for_llm = false`.
                    * **Important:** If `message_features['nl_api_call_succeeded']` is `false`, this type of skip condition is *not* met (i.e., `is_relevant_for_llm` remains `true`) because the absence of entities cannot be confirmed.
                * (The system can be extended with more `type`s of `relevancy_skip_conditions` in the future.)
            4. If, after evaluating all its `relevancy_skip_conditions`, `is_relevant_for_llm` is `true`, proceed to step 5.5.1.b (Gather all necessary input signals for this characteristic).
            5. Else (if `is_relevant_for_llm` is `false`), skip LLM analysis for this characteristic for this message.
                * A `violation_detail` may still be added with a note like `description: "LLM assessment for [CharacteristicName] skipped as message did not meet relevancy criteria (e.g., no URLs found)."`, `individual_confidence: 0.0`.
                * The corresponding `policy_category_scores` entry for this characteristic will be 0.0 or omitted.
    * b. Gather all necessary input signals for this characteristic:
        * i. The full `message_body`.
        * ii. Curated policy context from knowledge sources for the current characteristic (e.g., a snippet from Twilio's AUP defining the violation).
        * iii. Results from Google Safe Browse API for any URLs (if URLs are present in the message and the API call was successful; otherwise, this signal indicates unavailability or no URLs).
        * iv. Scores from Google Perspective API (if the API call was successful; otherwise, this signal indicates unavailability).
        * v. Entities extracted by Cloud Natural Language API (if the API call was successful; otherwise, this signal indicates unavailability).
    * c. **Construct the Specific, Tailored Prompt for Gemini:**
        For each relevant policy characteristic (as determined in step 5.5.1.a), a unique and carefully crafted prompt is dynamically constructed to guide the Gemini LLM's assessment. This process adheres to the following principles and incorporates the gathered signals:

        * **Configuration-Driven Prompt Templates:**
            * The base structure for each prompt is defined as a template within the Layer 2 policy characteristic configuration (e.g., in `sms_policy_checker_llm_config.yml`, as per Section 8). Each of the 19 characteristics will have its own distinct prompt template.
            * This approach allows for fine-tuning prompts for individual characteristics without code changes, aligning with Rails best practices of separating configuration from code.

        * **Dynamic Population with Contextual Signals:**
            The selected prompt template for the current `[CharacteristicName]` is populated with the following information, gathered in step 5.5.1.b:
            1.  **Full `message_body`:** The entire content of the SMS message is provided to give Gemini maximum context.
            2.  **Target `[CharacteristicName]`:** The prompt clearly states which of the 19 policy characteristics Gemini should assess (e.g., "PhishingAndDeceptiveURLs," "HatefulContent").
            3.  **Curated `policy_context_snippet`:** The specific text snippet from knowledge sources (e.g., Twilio AUP) relevant to the current `[CharacteristicName]` is injected. This anchors the LLM's assessment in defined policy language.
            4.  **Auxiliary API Signals (Formatted and Conditional):**
                * **Google Safe Browse API Results:** If URLs were present and the Safe Browse API call was successful, a summary of findings (e.g., "URL [url1] flagged for MALWARE; URL [url2] found no threats.") is included. If no URLs were present, or the API call failed, this is noted appropriately (e.g., "Safe Browse: No URLs in message," or "Safe Browse: Data unavailable").
                * **Google Perspective API Scores:** Relevant scores (e.g., "Perspective API Scores - TOXICITY: 0.75, THREAT: 0.2, SEXUALLY_EXPLICIT: 0.1") are included if the API call was successful. If the call failed, "Perspective API: Data unavailable" is indicated.
                * **Google Cloud Natural Language API Entities:** Key extracted entities and their types (e.g., "Detected Entities: [Aspirin (DRUG), Arist (ORGANIZATION)]") are provided if the API call was successful and relevant entities were found. If not, "Cloud NL Entities: No relevant entities detected" or "Cloud NL API: Data unavailable" is used.
            * The prompt structure ensures that Gemini is aware of which signals are available and which are not, allowing it to make the best possible assessment with the given information.

        * **Explicit Instruction for Structured JSON Output:**
            * Following the strategy outlined in Section 5.3, the prompt explicitly instructs Gemini to return its response as a JSON object.
            * This JSON object must contain two keys:
                1.  `confidence_score` (Float): A score between 0.0 (no confidence of violation for this characteristic) and 1.0 (high confidence of violation). The key name in the JSON response from Gemini might be dynamically tied to the characteristic for easier parsing (e.g., `"[CharacteristicName]_confidence_score"` as shown in the example in Section 5.3, or a generic key if preferred).
                2.  `rationale` (String): A brief textual explanation from Gemini for its assessed confidence score regarding this specific characteristic.
            * This enforced structure is critical for reliably parsing Gemini's response in step 5.5.1.f.

        * **Implementation Note (Ruby/Rails):**
            * In the Ruby implementation, this dynamic prompt construction would typically involve loading the appropriate template string and using string formatting methods (e.g., `sprintf`, `String#%`, or a more sophisticated templating engine if prompts become extremely complex) to inject the contextual signals. API client wrappers (as a Rails best practice) would provide the auxiliary API data in a consistent format, including error/unavailability states.

    * d. Make the API call to Gemini.
    * e. Handle potential API errors (e.g., timeouts, rate limits – these contribute to the decision to enter Fallback Mode if persistent).
    * f. Parse Gemini's JSON response to extract the `confidence_score` and `rationale` for the assessed characteristic.
    * g. Construct a `violation_detail` hash:
        * `layer: 2`
        * `filter_type: "Gemini:[CharacteristicName]"` (e.g., "Gemini:Phishing")
        * `description: [Gemini's textual rationale]`
        * `matched_value: [Relevant message snippet or N/A]`
        * `individual_confidence: [Gemini's confidence_score for this characteristic]`
        * `policy_category: [The CharacteristicName itself, as it's directly prompted]`
    * h. Add this `violation_detail` to `message_analysis_report.violation_details`.
        * i. Update `message_analysis_report.policy_category_scores`:
            * Let `category = [The CharacteristicName]`.
            * Let `current_score = [Gemini's confidence_score]`.
            * If `category` already exists in `policy_category_scores`, set its value to `[policy_category_scores[category], current_score].max`.
            * Else, add `category` with `current_score`.
2. After all relevant characteristics have been assessed by Gemini, proceed to the Final Decision Logic.

# 6. Final Decision Logic & Overall Algorithm
This logic determines the final `message_analysis_report` after Layer 1 and, if applicable, Layer 2 have completed their processing.

1. **Initialization:**

    - Create `message_analysis_report` with default "pass" status:
        * `result: :pass`
        * `reason: "Compliant"`
        * `confidence: 0.0`
        * `rewrite_suggestion: nil`
        * `processing_mode: :full_analysis `(default, may change to `:fallback_layer1_only` if APIs fail)
        * `policy_category_scores: {}`
        * `violation_details: []`
    * Load `FINAL_THRESHOLD_FLAG` from YAML configuration (e.g., 0.75). This is the general threshold above which a message is considered failing if no critical or Layer 1 early exit occurs.

2. **Execute Layer 1 Processing Logic:**

    * As described in section 4.4.
    * If Layer 1 results in an "early exit" (`processing_halted = true`):
        * The `message_analysis_report` fields (`result`, `confidence`, `reason`) are already set by the Layer 1 logic as described in Section 4.4.b.iv.
        * Proceed to Step 5 (Message Rewrite Suggestion) if `message_analysis_report.result == :fail`. Then Return.

3. **Execute Layer 2 Processing Logic (if no Layer 1 early exit):**

* As described in section 5.5.
* After all characteristics are processed by Gemini and `violation_details` and `policy_category_scores` are populated from Layer 2:
    * a.  **Critical Failure Check:** Iterate through the predefined "Critical Failure" categories and their configured thresholds (loaded from YAML). These are checked first.
        * **"Phishing & Deceptive URLs":** If `policy_category_scores["Phishing"] >= 0.95` (configurable threshold).
        * **"Hateful Content":** If `policy_category_scores["Hateful Content"] >= 0.95`.
        * **"Illegal Content (direct promotion/solicitation of federally illegal activities/substances, or credible threats of violence)":** If `policy_category_scores["Illegal Content"] >= 0.98`.
        * **"SHAFT Content - Firearms (Direct, unregulated sale/transfer)":** If `policy_category_scores["SHAFT-Firearms"] >= 0.95`.
        * **"SHAFT Content - Sex (Explicit, non-consensual, or illegal child-related content)":** If `policy_category_scores["SHAFT-Sex"] >= 0.98`.
        * **"Fraudulent or Malicious Content (Blatant, High-Confidence Scams)":** If `policy_category_scores["Fraudulent Content"] >= 0.95`.
        * If any of these critical failure conditions are met:
            1.  Set `message_analysis_report.result = :fail`.
            2.  Set `message_analysis_report.confidence = [the Gemini score for the critical category]`.
            3.  Set `message_analysis_report.reason = [the name of the critical category]`.
            4.  Proceed to Step 5 (Message Rewrite Suggestion). Then Return.

    * b.  **Max Score Fallback (if no critical failures from Layer 2):**
        * i.  Initialize `max_observed_score = 0.0` and `leading_category_for_fail = "Compliant"`.
        * ii. Iterate through all scores in `message_analysis_report.policy_category_scores` (these now include contributions from relevant Layer 1 findings that weren't early exits, and all Layer 2 Gemini assessments).
            1.  If a `score > max_observed_score`, update `max_observed_score` to this `score` and `leading_category_for_fail` to its corresponding `policy_category`.
        * iii.Set `message_analysis_report.confidence = max_observed_score`.
        * iv. If `max_observed_score >= FINAL_THRESHOLD_FLAG`:
            1.  Set `message_analysis_report.result = :fail`.
            2.  Set `message_analysis_report.reason = leading_category_for_fail`.
        * v.  Else (if `max_observed_score < FINAL_THRESHOLD_FLAG`):
            1.  Set `message_analysis_report.result = :pass`.
            2.  `message_analysis_report.reason` remains "Compliant" (or could be updated to reflect the highest non-violating score if desired, but "Compliant" is simpler for a pass).
            3.  The `confidence` score (which is `max_observed_score`) will be below the threshold.

4. **Error Handling during API calls (leading to Fallback Mode):**

    * If, during Layer 2 processing, an essential API (like Gemini) becomes consistently unavailable (e.g., due to repeated timeouts, 5xx errors, or auth failures):
        * a. Log the API errors extensively.
        * b. The service should gracefully switch to Fallback Mode (see Section 7). Set `message_analysis_report.processing_mode = :fallback_layer1_only`.
        * c. The final decision will then be based only on Layer 1's findings as detailed in Section 7. Processing of further Layer 2 characteristics stops.

5. **Message Rewrite Suggestion (conditionally executed):**

    * This step is performed if:
        * `message_analysis_report.result == :fail` AND
        * `message_analysis_report.processing_mode == :full_analysis` (i.e., not in fallback).
    * If these conditions are not met, `message_analysis_report.rewrite_suggestion` remains `nil`.

    * **LLM Used:** The same Gemini model instance used for content analysis.

    * **Prompt Construction:**
        * Inputs: Original `message_body`, `message_analysis_report.reason` (primary category of failure), `message_analysis_report.confidence`.
        * Instruction: The LLM is prompted with a multi-part task.
            1.  It is asked to analyze the original message in light of the failure reason.
            2.  If it determines the message is **uncorrectable**, it is instructed to respond *only* with the text: "This message cannot be made compliant due to: [LLM explains why]".
            3.  If it determines the message is **correctable**, it is instructed to provide a structured response (preferably JSON, to be parsed into a Hash) containing two distinct pieces of information:
                * `general_fix_suggestions` (String): General advice on how to avoid the identified violation.
                * `literal_rewrite` (String): A suggested compliant rewritten version of the message.
        * (The exact phrasing of this prompt, including instructions for JSON output if desired, will be critical and require careful design and testing.)

    * **LLM Call and Response Handling:**
        * An API call is made to Gemini with the crafted multi-part prompt.
        * The service then processes Gemini's response:
            1.  If the response text from Gemini starts with "This message cannot be made compliant due to:", this full string response is stored directly in `message_analysis_report.rewrite_suggestion`.
            2.  Else, the service attempts to parse Gemini's response as the structured suggestion (e.g., as JSON into the two-key Hash for `general_fix_suggestions` and `literal_rewrite`).
                * If parsing is successful and both required fields are present, this Hash is stored in `message_analysis_report.rewrite_suggestion`.
            3.  If Gemini's response does not match the "uncorrectable" string format and also cannot be successfully parsed into the expected two-key Hash (e.g., malformed JSON, missing keys, empty response, generic error message, or LLM content filters block the output, or an API error occurred), `message_analysis_report.rewrite_suggestion` is set to `nil`.

6. **Return** `message_analysis_report`.

# 7. Fallback Mode: API Unavailability

This mode is critical for ensuring the service remains partially functional even if its external LLM dependencies are unavailable.

* **Trigger:** Persistent failures in calls to essential Layer 2 APIs (Gemini, Perspective, Safe Browse).
* **Behavior:**
    1. The `message_analysis_report.processing_mode` is set to `:fallback_layer1_only`.
    2. No Layer 2 API calls are attempted or retried further for the current message.
    3. The final decision is based solely on the outcomes of the Layer 1 Rule-Based Pre-filters.
    4. `rewrite_suggestion` will be `nil`.
* **Decision Logic in Fallback Mode:**
    1. **Layer 1 Early Exit:** If a Layer 1 rule (marked as `is_early_exit_rule`) matches with `individual_confidence >= early_exit_threshold`:
        * `result = :fail`
        * `confidence = rule['individual_confidence']`
        * `reason = "Fallback: Early Exit - Violation Category: #{rule['mapped_policy_category']}"`
        * `violation_details` and `policy_category_scores` reflect this finding.
    2. **Layer 1 Threshold Assessment. (if no L1 early exit):**
        * Let `max_l1_score` be the highest `individual_confidence` found among all triggered Layer 1 rules.
        * Let `contributing_l1_rules` be the list of `violation_detail` objects from Layer 1, sorted by `individual_confidence` descending.
        * Load `FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK` from YAML (e.g., 0.75, could be same or different from individual thresholds and `FINAL_THRESHOLD_FLAG`).
        * If `max_l1_score >= FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK`:
            * `result = :fail`
            * `confidence = max_l1_score`
            * Let `top_contributing_rule_category` be the `mapped_policy_category` of the Layer 1 rule that has the `max_l1_score`. (This can be found from the `contributing_l1_rules` list, specifically the category of the rule with the highest score).
            * `reason = "Fallback: Layer 1 Threshold Exceeded - Violation Category: #{top_contributing_rule_category}"`
        * Else (`max_l1_score < FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK`):
            * `result = :pass`
            * `confidence = max_l1_score` (this will be 0.0 if no Layer 1 rules were triggered with confidence > 0).
            * `reason = "Fallback: Compliant."`
    3. The violation_details and policy_category_scores in the report will only contain findings from Layer 1.

**Why this fallback design?** It ensures the service always provides a response, offers a baseline level of protection even during outages, and clearly communicates the limited nature of its analysis to the consuming application.

# 8. Configuration Management via YAML
All operational parameters and rules for the service are designed to be externalized into YAML configuration files, loaded by the Rails application.

* **Location:** `config/` directory (e.g., `sms_policy_checker_rules.yml`, `sms_policy_checker_thresholds.yml`, `sms_policy_checker_llm_config.yml`).
* **Managed Configurations:**
    * **Layer 1 Rules:** Full definitions as described in Section 4.2 (name, description, type, patterns, mapped_policy_category, individual_confidence, is_early_exit_rule, early_exit_threshold).
    * **Layer 2 Critical Failure Definitions:** A list mapping policy categories to their critical failure confidence thresholds (e.g., `Phishing: 0.95`).
    * **General Thresholds:**
        * `FINAL_THRESHOLD_FLAG` (for full analysis mode).
        * `FINAL_THRESHOLD_FLAG_FOR_L1_FALLBACK` (for Layer 1 fallback mode).
    * **LLM Configuration:** Specific model names/versions for Gemini (for analysis and for rewrites, though currently the same).
        * **Layer 2 Policy Characteristic Definitions (in `sms_policy_checker_llm_config.yml` or similar):**
            * For each of the 19 characteristics, its definition can include:
                * `name` (String): e.g., `PhishingAndDeceptiveURLs`.
                * `description` (String): For documentation.
                * `knowledge_source_context` (String): The curated text snippet from policy documents to provide to Gemini.
                * `relevancy_skip_conditions` (Array of Hashes, Optional): Conditions under which LLM assessment for this characteristic can be skipped. Each hash defines a condition type and its parameters. Examples:
                    * `{"type": "skip_if_no_urls"}`
                    * `{"type": "skip_if_no_specific_entities", "entity_type": "DRUG"}`
                * (Other parameters like specific prompt templates or critical thresholds if not managed globally).
The service logic for determining relevancy (Section 5.5.1.a) is designed to be extensible to support new `type`s of skip conditions defined here.
* **Loading Mechanism:** These YAML files will be parsed at application boot (e.g., in an initializer) or loaded on demand by the service, with their content made available as structured data (hashes/arrays) for the service logic to consume.

**Why YAML?** For this project's scope where rule/threshold updates are not expected to be extremely frequent or require non-developer "live" changes, YAML offers a simple, human-readable, version-controllable way to manage configurations directly within the codebase.

# 9. Efficiency & Scalability Considerations

* **Single Message Processing Interface:** As detailed in Section 2.3, the service processes one message per call.
* **High-Volume Screening (10k+ messages):** Efficiency for large volumes is primarily addressed by:
    1. **Fast Layer 1 Pre-filters:** Quickly dispositioning or flagging messages with obvious issues without LLM calls.
    2. **External Parallel Processing:** The architecture relies on the calling system (e.g., a Rails application using ActiveJob with Sidekiq) to manage high throughput by invoking multiple instances of the SmsPolicyCheckerService concurrently for different messages.
    3. The intrinsic performance of the chosen Google Cloud APIs.

**Why this approach?** It keeps the service object's internal logic focused and testable, delegating the heavy lifting of concurrent execution and queue management to established Rails ecosystem tools like Sidekiq, which are designed for such tasks.

# 10. Removed Requirements

* **Strategy to Avoid Duplicate LLM Calls (Caching):** The initial requirement to implement a caching strategy (e.g., using Redis) for LLM API calls and/or final service results has been **explicitly removed** from the project scope.
    * **Reason:** Implementing a robust, granular, and effective caching mechanism for the complex and varied inputs to the LLM (especially for per-characteristic analysis) was deemed to add significant development complexity and testing overhead, which was not feasible within the project's timeframe and current priorities. The focus was shifted to ensuring the core filtering logic, fallback mechanisms, and LLM integration were sound. This means that LLM calls will be made as needed for each message analysis, even if similar content has been processed previously.
