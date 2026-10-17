# Security Policy & Privacy Architecture

## Zero-Telemetry & Zero Data Exfiltration Guarantee

PromptShield AI was engineered specifically to protect developers, teams, and enterprises from inadvertently leaking proprietary credentials, API keys, and customer PII to cloud and third-party AI endpoints.

### Core Security Guarantees:

1. **100% Client-Side Processing**:
   - All token redaction, regex evaluations, and synthetic surrogate mapping occur inside the local browser / Node runtime.
   - No prompts or de-identification tables are sent to any external analytics, trackers, or cloud servers.

2. **Deterministic Regular Expression Engine**:
   - Rather than relying on non-deterministic LLMs to detect secrets (which often hallucinate or fail on novel token boundaries), PromptShield executes validated deterministic rules for API keys (Stripe, GitHub, AWS, Google Cloud), emails, phone numbers, IPv4/IPv6 addresses, credit cards, and file system paths.

3. **Collision-Free Surrogate Generation**:
   - Tokens are mapped to uniquely indexed surrogate tags (e.g. `[API_KEY_1]`, `[EMAIL_1]`).
   - If the exact same secret token appears multiple times within a prompt, it reuses the same surrogate identifier to maintain context and relational coherence across open-weight model generation.

4. **Bi-Directional Rehydration Security**:
   - Rehydration happens strictly on the user's local machine after the model has returned its response. The actual confidential value never crosses the network boundary to the model inference container.

## Reporting a Vulnerability

If you discover an issue, unhandled credential pattern, or edge-case bypass, please open an issue on the GitHub repository or contact the maintainer directly.
