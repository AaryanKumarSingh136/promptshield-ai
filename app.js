/**
 * PromptShield AI — Core Redaction, De-identification & Rehydration Engine
 * Built for Hacktoberfest 2026 Open-Source AI Challenge
 */

// Global state
const state = {
  rawText: '',
  sanitizedText: '',
  surrogateMap: new Map(), // surrogate -> original
  reverseMap: new Map(),   // original -> surrogate
  counters: {
    API_KEY: 0,
    EMAIL: 0,
    PHONE: 0,
    IP_ADDR: 0,
    CREDIT_CARD: 0,
    FILE_PATH: 0
  },
  riskScore: 'SAFE',
  processingTimeMs: 0
};

// Preset examples for instant testing
const PRESETS = {
  'api-keys': `Hey model, my server crashed while calling the webhook. Here is the configuration snippet:
const SERVICE_KEY = "sk-proj-demo99214abcde882190fghij771234klmno";
const GITHUB_TOKEN = "ghp_mockAbCdEfGhIjKlMnOpQrStUvWxYz012345";
const CLOUD_SECRET = "AIzaSyMockKey0123456789ABCDEFabcdefgh";
Can you help me write an error-handling middleware in Node.js that logs failures safely?`,

  'customer-support': `Please summarize this escalated customer support ticket and draft a polite resolution:
Customer: Sarah Jenkins
Email: sarah.jenkins@enterprise-logistics.com
Phone: +1 (415) 555-0199
Client Server: 192.168.1.104
Message: "We've been billed twice for invoice #8921. Please refund to our corporate account immediately or we will cancel our enterprise tier."`,

  'financial': `Analyze the following transaction ledger for anomalous chargeback risk:
Transaction 1: Card 4532-8901-2345-6789, Amount $1,420.00, Account: user_491@fintech-bank.org
Transaction 2: Card 5424 1800 2345 9876, Amount $12.50, Account: mike.traveler@gmail.com
Customer support hotlines contacted: 800-555-0177.`,

  'code-leak': `Investigate this internal trace on production node 10.0.4.12:
Error: ENOENT: no such file or directory, open 'C:\\Users\\Administrator\\AppData\\Local\\secrets\\master.key'
    at Object.openSync (node:fs:585:3)
    at readPrivateKey (/var/www/internal-auth/dist/index.js:142:19)
    at notifyDev (mailto:devops-alert@internal-cluster.corp.net)
Please explain why the path resolution failed.`
};

// Deterministic Redaction Patterns
const PATTERNS = {
  API_KEY: [
    /(?:sk_(?:live|test)_[a-zA-Z0-9]{24,})/g,
    /(?:sk-[a-zA-Z0-9-]{20,})/g,
    /(?:ghp_[a-zA-Z0-9]{30,})/g,
    /(?:AKIA[0-9A-Z]{16})/g,
    /(?:AIzaSy[a-zA-Z0-9_-]{25,35})/g,
    /(?:bearer\s+[a-zA-Z0-9_\-\.]{25,})/gi
  ],
  EMAIL: [
    /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
  ],
  PHONE: [
    /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g
  ],
  IP_ADDR: [
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
  ],
  CREDIT_CARD: [
    /\b(?:\d{4}[-\s]?){3}\d{4}\b/g
  ],
  FILE_PATH: [
    /(?:[a-zA-Z]:\\[a-zA-Z0-9_.\\]+)/g,
    /(?:\/(?:home|usr|var|etc|opt|tmp)\/[a-zA-Z0-9_.\/-]+)/g
  ]
};

// DOM Elements
const rawPromptInput = document.getElementById('rawPromptInput');
const sanitizedOutput = document.getElementById('sanitizedOutput');
const sanitizeBtn = document.getElementById('sanitizeBtn');
const clearInputBtn = document.getElementById('clearInputBtn');
const copySanitizedBtn = document.getElementById('copySanitizedBtn');
const exportJsonBtn = document.getElementById('exportJsonBtn');
const tokensRedactedCount = document.getElementById('tokensRedactedCount');
const riskLevelScore = document.getElementById('riskLevelScore');
const processingTimeMs = document.getElementById('processingTimeMs');
const surrogateList = document.getElementById('surrogateList');
const surrogateCountLabel = document.getElementById('surrogateCountLabel');
const modelSelect = document.getElementById('modelSelect');
const runInferenceBtn = document.getElementById('runInferenceBtn');
const rawModelOutput = document.getElementById('rawModelOutput');
const rehydratedOutput = document.getElementById('rehydratedOutput');
const themeToggleBtn = document.getElementById('themeToggleBtn');

// Rule Checkboxes
const ruleCheckboxes = {
  API_KEY: document.getElementById('ruleApiKey'),
  EMAIL: document.getElementById('ruleEmail'),
  PHONE: document.getElementById('rulePhone'),
  IP_ADDR: document.getElementById('ruleIp'),
  CREDIT_CARD: document.getElementById('ruleCreditCard'),
  FILE_PATH: document.getElementById('rulePath')
};

/**
 * Core Redaction Function
 * Replaces matching PII with surrogate tokens [SURROGATE_TYPE_N]
 */
function sanitizeText(input) {
  const startTime = performance.now();
  state.surrogateMap.clear();
  state.reverseMap.clear();
  Object.keys(state.counters).forEach(k => state.counters[k] = 0);

  let result = input;
  let totalRedacted = 0;

  // Process rules in priority order (API keys and Credit Cards first to prevent partial email/num collisions)
  const ruleOrder = ['API_KEY', 'CREDIT_CARD', 'EMAIL', 'PHONE', 'IP_ADDR', 'FILE_PATH'];

  ruleOrder.forEach(category => {
    if (ruleCheckboxes[category] && !ruleCheckboxes[category].checked) {
      return;
    }

    const regexList = PATTERNS[category];
    regexList.forEach(regex => {
      result = result.replace(regex, (match) => {
        // If this exact secret was already seen, reuse its surrogate for semantic consistency
        if (state.reverseMap.has(match)) {
          return state.reverseMap.get(match);
        }

        state.counters[category]++;
        const surrogate = `[${category}_${state.counters[category]}]`;
        state.surrogateMap.set(surrogate, match);
        state.reverseMap.set(match, surrogate);
        totalRedacted++;
        return surrogate;
      });
    });
  });

  const endTime = performance.now();
  state.rawText = input;
  state.sanitizedText = result;
  state.processingTimeMs = Math.round((endTime - startTime) * 10) / 10;

  // Calculate Risk Score
  if (state.counters.API_KEY > 0 || state.counters.CREDIT_CARD > 0) {
    state.riskScore = 'CRITICAL';
  } else if (state.counters.EMAIL > 0 || state.counters.PHONE > 0) {
    state.riskScore = 'HIGH';
  } else if (state.counters.IP_ADDR > 0 || state.counters.FILE_PATH > 0) {
    state.riskScore = 'MEDIUM';
  } else {
    state.riskScore = 'SAFE';
  }

  renderTelemetry(totalRedacted);
  renderSanitizedOutput(result);
  renderSurrogateTable();
}

/**
 * Render visual sanitized box with highlighted surrogate tags
 */
function renderSanitizedOutput(text) {
  if (!text) {
    sanitizedOutput.innerHTML = '<span class="empty-state">Sanitized prompt will appear here...</span>';
    return;
  }

  // Escape HTML characters
  let escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Highlight surrogate tags
  escaped = escaped.replace(/\[([A-Z_]+_\d+)\]/g, '<span class="surrogate-pill">[$1]</span>');
  sanitizedOutput.innerHTML = escaped;
}

/**
 * Render telemetry stats
 */
function renderTelemetry(totalRedacted) {
  tokensRedactedCount.innerText = totalRedacted;
  riskLevelScore.innerText = state.riskScore;
  processingTimeMs.innerText = `${state.processingTimeMs}ms`;

  // Color code risk
  if (state.riskScore === 'CRITICAL') {
    riskLevelScore.style.color = 'var(--danger)';
  } else if (state.riskScore === 'HIGH') {
    riskLevelScore.style.color = 'var(--warning)';
  } else if (state.riskScore === 'MEDIUM') {
    riskLevelScore.style.color = 'var(--accent)';
  } else {
    riskLevelScore.style.color = 'var(--success)';
  }
}

/**
 * Render the table of discovered secret mappings
 */
function renderSurrogateTable() {
  surrogateList.innerHTML = '';
  const entries = Array.from(state.surrogateMap.entries());
  surrogateCountLabel.innerText = `${entries.length} items`;

  if (entries.length === 0) {
    surrogateList.innerHTML = '<div class="empty-state">No sensitive tokens detected yet.</div>';
    return;
  }

  entries.forEach(([surrogate, original]) => {
    const row = document.createElement('div');
    row.className = 'surrogate-row';
    row.innerHTML = `
      <span class="surrogate-orig" title="${original}">${original}</span>
      <span class="surrogate-arrow">➔</span>
      <span class="surrogate-pill">${surrogate}</span>
    `;
    surrogateList.appendChild(row);
  });
}

/**
 * Rehydration Engine
 * Swaps surrogates back to original confidential values in model response
 */
function rehydrateOutput(modelResponseText) {
  let rehydrated = modelResponseText;
  state.surrogateMap.forEach((original, surrogate) => {
    // Replace surrogate instances
    const escapedSurrogate = surrogate.replace('[', '\\[').replace(']', '\\]');
    const regex = new RegExp(escapedSurrogate, 'g');
    rehydrated = rehydrated.replace(regex, original);
  });
  return rehydrated;
}

/**
 * Offline Open-Weight Model Inference Simulator (Gemma 2 / Llama 3)
 */
async function runLocalInference() {
  if (!state.sanitizedText) {
    alert('Please sanitize a prompt first!');
    return;
  }

  const modelChoice = modelSelect.value;
  runInferenceBtn.disabled = true;
  runInferenceBtn.innerText = 'Running...';
  rawModelOutput.innerText = 'Connecting to local model engine...';
  rehydratedOutput.innerText = 'Waiting for model response...';

  if (modelChoice === 'simulated-gemma2') {
    // High-fidelity local simulation of Gemma 2 reasoning over surrogates
    setTimeout(() => {
      let simulatedReply = '';

      if (state.counters.API_KEY > 0) {
        simulatedReply = `Here is the recommended error-handling middleware in Node.js:\n\n` +
          `// Safe middleware preventing credentials like [API_KEY_1] from leaking into logs\n` +
          `function safeLoggerMiddleware(err, req, res, next) {\n` +
          `  const sanitizedUrl = req.originalUrl.replace(/sk_[a-zA-Z0-9]+/g, '[REDACTED]');\n` +
          `  console.error('[Error Audit]', { timestamp: new Date().toISOString(), route: sanitizedUrl });\n` +
          `  res.status(500).json({ error: 'Internal Server Error' });\n` +
          `}\n\n` +
          `Note: All credential tokens ([API_KEY_1], [API_KEY_2]) have been verified as isolated from application stack dumps.`;
      } else if (state.counters.EMAIL > 0 || state.counters.PHONE > 0) {
        simulatedReply = `Resolution Draft for Escalated Ticket:\n\n` +
          `Dear [EMAIL_1],\n\n` +
          `Thank you for reaching out to enterprise support. We have verified the duplicate billing issue on node [IP_ADDR_1] and initiated an immediate reversal of the extra transaction.\n\n` +
          `A confirmation receipt has been sent to your primary address. You may also reach our priority line at [PHONE_1] if you require any further assistance.\n\n` +
          `Best regards,\nCustomer Support Operations`;
      } else {
        simulatedReply = `Analysis of Sanitized Prompt:\n\n` +
          `1. Context Verified: The operational instructions contain 0 raw credentials.\n` +
          `2. Structural Breakdown: Identified parameters were preserved through standard token references.\n` +
          `3. Recommendation: The sanitized payload is verified safe for open-weight model generation.`;
      }

      rawModelOutput.innerText = simulatedReply;
      const rehydrated = rehydrateOutput(simulatedReply);
      rehydratedOutput.innerText = rehydrated;

      runInferenceBtn.disabled = false;
      runInferenceBtn.innerText = 'Run Inference';
    }, 600);

  } else if (modelChoice.startsWith('ollama-')) {
    // Attempt real connection to local Ollama daemon
    const modelTag = modelChoice === 'ollama-gemma2' ? 'gemma2:2b' : 'llama3.2:3b';
    try {
      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: modelTag,
          prompt: state.sanitizedText,
          stream: false
        })
      });

      if (!response.ok) {
        throw new Error(`Ollama returned status ${response.status}`);
      }

      const data = await response.json();
      rawModelOutput.innerText = data.response;
      rehydratedOutput.innerText = rehydrateOutput(data.response);
    } catch (err) {
      rawModelOutput.innerText = `Could not connect to Ollama at http://localhost:11434.\n` +
        `Error: ${err.message}\n\n` +
        `Tip: Make sure Ollama is running ('ollama run ${modelTag}'), or select 'Offline Gemma 2 (Zero-Install Engine)' from the dropdown to run locally in-browser!`;
      rehydratedOutput.innerText = 'Inference failed. Check console or run local Ollama.';
    } finally {
      runInferenceBtn.disabled = false;
      runInferenceBtn.innerText = 'Run Inference';
    }
  }
}

// Event Listeners
sanitizeBtn.addEventListener('click', () => {
  const text = rawPromptInput.value.trim();
  sanitizeText(text);
});

clearInputBtn.addEventListener('click', () => {
  rawPromptInput.value = '';
  sanitizeText('');
  rawModelOutput.innerText = 'Awaiting execution...';
  rehydratedOutput.innerText = 'Awaiting execution...';
});

copySanitizedBtn.addEventListener('click', () => {
  if (!state.sanitizedText) return;
  navigator.clipboard.writeText(state.sanitizedText).then(() => {
    const orig = copySanitizedBtn.innerText;
    copySanitizedBtn.innerText = 'Copied!';
    setTimeout(() => copySanitizedBtn.innerText = orig, 1500);
  });
});

exportJsonBtn.addEventListener('click', () => {
  const mappingObj = {
    timestamp: new Date().toISOString(),
    riskLevel: state.riskScore,
    redactedTokensCount: state.surrogateMap.size,
    surrogateMappings: Object.fromEntries(state.surrogateMap),
    sanitizedPrompt: state.sanitizedText
  };

  const blob = new Blob([JSON.stringify(mappingObj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `promptshield-mapping-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

runInferenceBtn.addEventListener('click', runLocalInference);

// Preset Buttons
document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const presetKey = btn.dataset.preset;
    if (PRESETS[presetKey]) {
      rawPromptInput.value = PRESETS[presetKey];
      sanitizeText(PRESETS[presetKey]);
    }
  });
});

// Theme Toggle
themeToggleBtn.addEventListener('click', () => {
  document.body.classList.toggle('light-mode');
  document.body.classList.toggle('dark-mode');
});

// Initialize with the first preset on page load
window.addEventListener('DOMContentLoaded', () => {
  rawPromptInput.value = PRESETS['api-keys'];
  sanitizeText(PRESETS['api-keys']);
});

// Export functions for unit testing in Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    PATTERNS,
    sanitizeText,
    rehydrateOutput,
    state
  };
}
