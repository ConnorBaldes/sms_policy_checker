# Trial Project: SMS Message Policy Checker

## Context

Our customers send short training messages to employees via SMS using Twilio. Sometimes, these messages get blocked due to Twilio error 30007 (carrier violation) -- usually caused by content that breaks Twilio or carrier rules. Even seemingly innocuous messages can sometimes run afoul of the rules.

Examples of violations:

- Phishing-style or shortened links
- SHAFT content (Sex, Hate, Alcohol, Firearms, Tobacco)
- Misleading sender names

[Twilio's guide on avoiding message blocks →](https://help.twilio.com/articles/1260803966670-How-do-I-prevent-my-Twilio-messages-from-being-filtered-blocked-)

## Your task

Create a Rails service object that checks message content before sending and flags potential policy violations.

### Deliverables

1. A Rails service class in app/services/sms_policy_checker_service.rb
2. RSpec tests in spec/services/sms_policy_checker_service_spec.rb
3. Brief README explaining your approach and design decisions

### Technical Requirements

- Service should accept message_body as input
- Returns a structured result with:
  - result: :pass/:fail
  - reason: "Why it failed"
  - confidence: 0.0-1.0
- Uses an LLM for content analysis
- Includes fallback mechanisms if API is unavailable
- Efficiently handles common violation patterns

### Evaluation Criteria

- Code quality and organization
- Appropriate test coverage
- Documentation
- Performance considerations
- Rails best practices

### Nice to have (optional)

- Suggest how to rewrite flagged messages
- Support screening 10k+ messages efficiently
- Strategy to avoid duplicate LLM calls
- Implementation of rule-based pre-filters before LLM analysis

## Helpful Resources

*(use quick web-search for relevant in these categories)*

- Twilio A2P messaging & compliance docs
- Twilio Error Code 30007 explanations
- Public LLM moderation resources (if helpful)

## How to Submit

Please send private GitHub repo link and a short Loom/video (max 3 min) explaining your approach. We will run your code against our recently flagged messages to evaluate it.

## Compensation

We pay **$150/hour, up to 3 hours ($450 cap)**.

Send your invoice to [support@arist.co](mailto:support@arist.co) -- we'll pay within 5 business days of reviewing your work.

## Timing

Start now. We expect this to take 1--3 focused hours.

Please send your project back within **72 hours** (unless you let us know otherwise).
