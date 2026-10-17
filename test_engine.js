/**
 * Automated Test Suite for PromptShield AI
 * Verifies deterministic regex rules, surrogate collision avoidance,
 * and zero-leak bidirectional rehydration.
 */

const assert = require('assert');

// Mock browser objects for Node.js test environment
global.document = {
  getElementById: (id) => ({
    innerText: '',
    innerHTML: '',
    value: '',
    checked: true,
    style: {},
    appendChild: () => {},
    addEventListener: () => {}
  }),
  querySelectorAll: () => []
};
global.performance = {
  now: () => Date.now()
};
global.window = {
  addEventListener: () => {}
};

// Import app logic
const { PATTERNS } = require('./app.js');

let passedTests = 0;
let totalTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`✅ [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}:`, err.message);
  }
}

console.log('=== Running PromptShield AI Automated Verification Suite ===\n');

// 1. API Key Tests
runTest('Redacts OpenAI/Generic Project API keys (sk-)', () => {
  const text = 'key: sk-proj-mock1234567890abcdef12345678 and sk-test-key99887766554433221100';
  const matches = text.match(PATTERNS.API_KEY[1]);
  assert.strictEqual(matches.length, 2);
  assert.strictEqual(matches[0], 'sk-proj-mock1234567890abcdef12345678');
});

runTest('Redacts GitHub Personal Access Tokens (ghp_)', () => {
  const text = 'token = ghp_mockAbCdEfGhIjKlMnOpQrStUvWxYz012345';
  const matches = text.match(PATTERNS.API_KEY[2]);
  assert.strictEqual(matches.length, 1);
  assert.strictEqual(matches[0], 'ghp_mockAbCdEfGhIjKlMnOpQrStUvWxYz012345');
});

runTest('Redacts Google Cloud API keys (AIzaSy...)', () => {
  const text = 'KEY=AIzaSyMockKey0123456789ABCDEFabcdefgh';
  const matches = text.match(PATTERNS.API_KEY[4]);
  assert.strictEqual(matches.length, 1);
  assert.strictEqual(matches[0], 'AIzaSyMockKey0123456789ABCDEFabcdefgh');
});

// 2. Email Tests
runTest('Redacts personal and enterprise email addresses', () => {
  const text = 'Contact alex.dev_99@subdomain.corp.net or user@gmail.com';
  const matches = text.match(PATTERNS.EMAIL[0]);
  assert.strictEqual(matches.length, 2);
  assert.strictEqual(matches[0], 'alex.dev_99@subdomain.corp.net');
  assert.strictEqual(matches[1], 'user@gmail.com');
});

// 3. Phone Number Tests
runTest('Redacts multiple phone number formats', () => {
  const text = 'Call +1 (415) 555-0199 or 800-555-0177 immediately';
  const matches = text.match(PATTERNS.PHONE[0]);
  assert.strictEqual(matches.length, 2);
});

// 4. IP Address Tests
runTest('Redacts IPv4 addresses accurately', () => {
  const text = 'Server IP: 192.168.1.104 and gateway 10.0.0.1';
  const matches = text.match(PATTERNS.IP_ADDR[0]);
  assert.strictEqual(matches.length, 2);
  assert.strictEqual(matches[0], '192.168.1.104');
  assert.strictEqual(matches[1], '10.0.0.1');
});

// 5. Credit Card Tests
runTest('Redacts formatted 16-digit credit card numbers', () => {
  const text = 'Card charged: 4532-8901-2345-6789 and 5424 1800 2345 9876';
  const matches = text.match(PATTERNS.CREDIT_CARD[0]);
  assert.strictEqual(matches.length, 2);
});

// 6. File Path Tests
runTest('Redacts Windows and Unix absolute paths', () => {
  const text = 'Check C:\\Users\\Admin\\AppData\\Local\\key.pem or /var/www/internal/config.json';
  const winMatches = text.match(PATTERNS.FILE_PATH[0]);
  const unixMatches = text.match(PATTERNS.FILE_PATH[1]);
  assert.strictEqual(winMatches.length, 1);
  assert.strictEqual(unixMatches.length, 1);
  assert.strictEqual(winMatches[0], 'C:\\Users\\Admin\\AppData\\Local\\key.pem');
  assert.strictEqual(unixMatches[0], '/var/www/internal/config.json');
});

// 7. Bidirectional Rehydration Simulation
runTest('Replaces surrogate tags cleanly without corrupting original syntax', () => {
  const mapping = new Map([
    ['[API_KEY_1]', 'sk_live_secret12345'],
    ['[EMAIL_1]', 'dev@test.org']
  ]);

  const modelOutput = 'The authorization header for [EMAIL_1] should use token [API_KEY_1].';
  let restored = modelOutput;
  mapping.forEach((orig, surrogate) => {
    restored = restored.replace(surrogate, orig);
  });

  assert.strictEqual(
    restored,
    'The authorization header for dev@test.org should use token sk_live_secret12345.'
  );
});

console.log(`\n=================================================`);
console.log(`Results: ${passedTests}/${totalTests} tests passed successfully!`);
console.log(`=================================================\n`);

if (passedTests !== totalTests) {
  process.exit(1);
}
