// SPDX-License-Identifier: MIT
/**
 * Unit tests for the shared privacy primitives in security-core:
 * fingerprint-field stripping, URL storage sanitization, and the WaiTag
 * format. These are the single implementations used by both the
 * TypeScript API and the demo servers.
 */
const { test } = require('node:test');
const assert = require('node:assert');

const {
  stripFingerprintFields,
  sanitizeUrlForStorage,
  FORBIDDEN_FINGERPRINT_FIELDS,
  WAITAG_PATTERN
} = require('../server/utils/security-core');

test('stripFingerprintFields removes fingerprint keys at any depth, case-insensitively', () => {
  const input = {
    eventType: 'click',
    userAgent: 'Mozilla/5.0',
    UserAgent: 'shouty',
    SCREENWIDTH: 1920,
    metadata: {
      label: 'buy-button',
      language: 'en-US',
      nested: [{ timezone: 'America/Los_Angeles', ok: true }]
    },
    clickX: 10,
    clickY: 20
  };
  const out = stripFingerprintFields(input);

  assert.strictEqual(out.eventType, 'click');
  assert.strictEqual(out.metadata.label, 'buy-button');
  assert.strictEqual(out.metadata.nested[0].ok, true);

  assert.strictEqual('userAgent' in out, false);
  assert.strictEqual('UserAgent' in out, false);
  assert.strictEqual('SCREENWIDTH' in out, false);
  assert.strictEqual('clickX' in out, false);
  assert.strictEqual('clickY' in out, false);
  assert.strictEqual('language' in out.metadata, false);
  assert.strictEqual('timezone' in out.metadata.nested[0], false);

  // The original object is not mutated.
  assert.strictEqual(input.userAgent, 'Mozilla/5.0');
});

test('stripFingerprintFields covers every documented forbidden field', () => {
  const poison = {};
  for (const field of FORBIDDEN_FINGERPRINT_FIELDS) poison[field] = 'x';
  poison.keepMe = 'yes';
  const out = stripFingerprintFields(poison);
  assert.deepStrictEqual(Object.keys(out), ['keepMe']);
});

test('stripFingerprintFields passes primitives and null through', () => {
  assert.strictEqual(stripFingerprintFields(null), null);
  assert.strictEqual(stripFingerprintFields(42), 42);
  assert.strictEqual(stripFingerprintFields('str'), 'str');
});

test('sanitizeUrlForStorage strips query strings and fragments', () => {
  assert.strictEqual(
    sanitizeUrlForStorage('https://shop.example.com/checkout?email=a@b.com&token=secret#step2'),
    'https://shop.example.com/checkout'
  );
  assert.strictEqual(
    sanitizeUrlForStorage('http://example.com/'),
    'http://example.com/'
  );
});

test('sanitizeUrlForStorage rejects non-http(s) and unparseable URLs outright', () => {
  assert.strictEqual(sanitizeUrlForStorage('javascript:alert(1)'), '');
  assert.strictEqual(sanitizeUrlForStorage('data:text/html,<b>x</b>'), '');
  assert.strictEqual(sanitizeUrlForStorage('not a url'), '');
  assert.strictEqual(sanitizeUrlForStorage(''), '');
  assert.strictEqual(sanitizeUrlForStorage(null), '');
  assert.strictEqual(sanitizeUrlForStorage(12345), '');
});

test('sanitizeUrlForStorage caps stored length', () => {
  const long = 'https://example.com/' + 'a'.repeat(5000);
  assert.ok(sanitizeUrlForStorage(long).length <= 2048);
});

test('WAITAG_PATTERN accepts valid tags and rejects malformed ones', () => {
  assert.ok(WAITAG_PATTERN.test('wai_1234567890_abc'));
  assert.ok(WAITAG_PATTERN.test('wai_abcDEF12345_Z9'));
  assert.ok(WAITAG_PATTERN.test('demo-123-deadbeef'));

  assert.strictEqual(WAITAG_PATTERN.test('wai_short_x'), false);
  assert.strictEqual(WAITAG_PATTERN.test('wai_1234567890_'), false);
  assert.strictEqual(WAITAG_PATTERN.test('<script>alert(1)</script>'), false);
  assert.strictEqual(WAITAG_PATTERN.test(''), false);
  assert.strictEqual(WAITAG_PATTERN.test('wai_1234567890_abc extra'), false);
});

// --- Adversarial hardening regressions: semantic key matching, URL string
// --- values, and serialized-JSON smuggling (architect review findings). ---
const SecurityCoreX = require('../server/utils/security-core');

test('stripFingerprintFields is semantic: alias and separator variants are removed', () => {
  const out = SecurityCoreX.stripFingerprintFields({
    'user-agent': 'UA', 'User Agent': 'UA', uaString: 'UA', browserUserAgent: 'UA',
    capabilities: ['x'], deviceCapabilities: { gpu: 'x' },
    clientX: 4, clientY: 2, 'time-zone': 'UTC', tzTimezoneOffset: -480,
    keep: 'ok'
  });
  assert.deepStrictEqual(out, { keep: 'ok' });
});

test('legitimate keys that merely resemble forbidden ones survive', () => {
  const input = {
    screenName: 'display-name', platformFee: 12,
    programmingLanguage: 'js', uaeOffice: true
  };
  assert.deepStrictEqual(SecurityCoreX.stripFingerprintFields(input), input);
});

test('URL string values anywhere in the payload are minimized to origin + path', () => {
  const out = SecurityCoreX.stripFingerprintFields({
    referrer: 'https://a.example.com/page?tok=SECRET#frag',
    nested: { href: 'http://b.example.com/x?email=user@example.com' },
    note: 'https is mentioned but this is not a url'
  });
  assert.strictEqual(out.referrer, 'https://a.example.com/page');
  assert.strictEqual(out.nested.href, 'http://b.example.com/x');
  assert.strictEqual(out.note, 'https is mentioned but this is not a url');
});

test('serialized JSON strings are parsed, stripped, and re-serialized (no string smuggling)', () => {
  const metadata = JSON.stringify({
    userAgent: 'UA', screenWidth: 1920, ok: 1,
    link: 'https://c.example.com/p?q=term#h'
  });
  const out = SecurityCoreX.stripFingerprintFields({ metadata });
  assert.deepStrictEqual(JSON.parse(out.metadata), { ok: 1, link: 'https://c.example.com/p' });
});

test('non-JSON strings pass through unchanged', () => {
  const out = SecurityCoreX.stripFingerprintFields({ metadata: '{not json', note: 'plain' });
  assert.strictEqual(out.metadata, '{not json');
  assert.strictEqual(out.note, 'plain');
});
