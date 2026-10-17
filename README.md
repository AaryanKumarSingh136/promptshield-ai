# PromptShield AI 🛡️

> **Zero-Leak Local Redaction & Prompt Hardening Engine for Open-Weight Models**  
> *Built for Hacktoberfest 2026 Open-Source AI Challenge.*

[![Tests](https://github.com/AaryanKumarSingh136/promptshield-ai/actions/workflows/test.yml/badge.svg)](https://github.com/AaryanKumarSingh136/promptshield-ai/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-Zero%20Local-emerald.svg)](SECURITY.md)

---

## 💡 What is PromptShield AI?

As software engineers and enterprises rapidly adopt open-weight models (such as **Google Gemma 2**, **Meta Llama 3.2**, **Mistral**, and **Qwen**), confidential data leakage has become the primary operational barrier. Developers routinely paste internal stack traces, API keys, client tickets, customer emails, and server IP addresses into AI prompts.

Commercial cloud LLMs retain or process this data on remote servers, causing irreversible compliance violations. Even when running models locally or on private cloud instances, untrusted prompts can leak credentials into model activations, evaluation logs, or telemetry pipelines.

**PromptShield AI** solves this with a lightweight, local-first redaction proxy and bi-directional rehydration engine:
1. **Pre-Inference Redaction**: Deterministically scans and replaces API credentials, emails, phone numbers, IP addresses, credit card numbers, and filesystem paths with semantic synthetic surrogates (e.g. `[API_KEY_1]`, `[EMAIL_1]`).
2. **Context-Preserving Inference**: The open-weight model reasons and writes code over the surrogates without ever seeing the sensitive tokens.
3. **Post-Inference Rehydration**: Prompts and responses are privately rehydrated on the client device, restoring original values with zero data exfiltration.

---

## 🏗️ Architecture & Dataflow

```mermaid
flowchart TD
    A[Raw Confidential Prompt\nAPI Keys, Emails, PII, IPs] --> B[PromptShield Local Engine]
    B -->|Deterministic RegEx & Entropy Scan| C[Surrogate Mapping Store\nLocal Memory Map]
    B -->|Generates| D[Sanitized Prompt\nTokens replaced with [SURROGATE_N]]
    D --> E[Open-Weight Model\nLocal Gemma 2 / Ollama / LM Studio]
    E -->|Generates Response with Surrogates| F[Raw Model Output]
    C -.->|Reverse Surrogate Lookup| G[Rehydration Engine]
    F --> G
    G --> H[Final Safe Response\nConfidential Data Restored Privately]
```

---

## ⚡ Key Capabilities

- **100% Client-Side & Offline:** Zero external network calls. All redaction and surrogate mapping runs locally in your browser or Node.js environment.
- **Deterministic Accuracy:** Uses validated regex patterns and checksum analysis to eliminate LLM hallucinations on secret boundaries.
- **Relational Consistency:** If the same email or API token appears multiple times, it is assigned the same surrogate tag to maintain reasoning coherence across code blocks.
- **Open-Weight Model Integration:** Built-in runner supporting local [Ollama](https://ollama.com) instances (`gemma2:2b`, `llama3.2:3b`), LM Studio, or zero-install browser simulation.
- **Automated Verification Suite:** 9 automated tests verifying zero-leak guarantees and bi-directional surrogate restoration.

---

## 🚀 Quickstart

### 1. Run the Interactive Web UI
Simply open `index.html` in any web browser:
```bash
# On Windows (PowerShell)
Start-Process index.html

# Or serve locally
npx serve .
```

### 2. Run Automated Tests
```bash
node test_engine.js
```

---

## 🌐 Why Open Innovation Matters

In AI privacy and security, **closed-source APIs cannot be verified**. Relying on a third-party commercial cloud provider to scrub your data requires sending that very data across the internet to their servers first.

Open innovation changes the game:
1. **Auditable Security**: Anyone can inspect `app.js` and `test_engine.js` to verify that not a single byte of telemetry leaves the machine.
2. **Zero-Cost Scaling**: Solopreneurs and bootstrapped developers can run local open-weight models with enterprise-grade privacy protection for $0 in subscriptions.
3. **Offline Resilience**: Field technicians, developers on flights, and security teams in air-gapped environments can operate without internet access.

---

## 🏆 Hacktoberfest 2026 DEV Challenge

- **Event:** Hacktoberfest Open-Source AI Challenge
- **Tag:** `#hf26challenge`, `#devchallenge`
- **Partner Categories Targeted:** Best Use of Gemma, Best Use of GitHub Copilot
- **Live DEV Article:** [PromptShield AI on DEV](https://dev.to/aaryankumarsingh136)

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
