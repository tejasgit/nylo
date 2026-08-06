// SPDX-License-Identifier: MIT
const { test } = require('node:test');
const assert = require('node:assert');
const { isValidDomainName, hostMatchesPattern, originAllowed } = require('../server/utils/security-core');

test('isValidDomainName accepts valid domains', () => {
  assert.ok(isValidDomainName('example.com'));
  assert.ok(isValidDomainName('sub.example.co.uk'));
  assert.ok(isValidDomainName('localhost'));
});

test('isValidDomainName rejects invalid input', () => {
  assert.ok(!isValidDomainName(''));
  assert.ok(!isValidDomainName(null));
  assert.ok(!isValidDomainName('evil<script>localhost'));
  assert.ok(!isValidDomainName('has space.com'));
  assert.ok(!isValidDomainName('-leading.com'));
  assert.ok(!isValidDomainName('a'.repeat(260) + '.com'));
  assert.ok(!isValidDomainName('http://example.com'));
});

test('hostMatchesPattern exact match only for bare domains', () => {
  assert.ok(hostMatchesPattern('example.com', 'example.com'));
  assert.ok(!hostMatchesPattern('sub.example.com', 'example.com'));
  assert.ok(!hostMatchesPattern('evilexample.com', 'example.com'));
});

test('hostMatchesPattern wildcard respects host boundaries', () => {
  assert.ok(hostMatchesPattern('example.com', '*.example.com'));
  assert.ok(hostMatchesPattern('a.example.com', '*.example.com'));
  assert.ok(hostMatchesPattern('a.b.example.com', '*.example.com'));
  // no suffix-matching lookalikes
  assert.ok(!hostMatchesPattern('evilexample.com', '*.example.com'));
  assert.ok(!hostMatchesPattern('example.com.evil.io', '*.example.com'));
  assert.ok(!hostMatchesPattern('anything.com', '*.'));
});

test('originAllowed matches exact origins and hosts', () => {
  assert.ok(originAllowed('https://app.example.com', ['*.example.com']));
  assert.ok(originAllowed('https://example.com', ['example.com']));
  assert.ok(originAllowed('https://example.com:8443', ['https://example.com:8443']));
  assert.ok(!originAllowed('https://example.com:8443', ['https://example.com']));
  assert.ok(!originAllowed('https://evilexample.com', ['*.example.com']));
  assert.ok(!originAllowed('ftp://example.com', ['example.com']));
  assert.ok(!originAllowed('not-a-url', ['example.com']));
});

test('originAllowed fails closed with empty allowlist in production', () => {
  assert.ok(!originAllowed('https://anything.com', [], { production: true, allowDevLoopback: true }));
  assert.ok(!originAllowed('http://localhost:5000', [], { production: true, allowDevLoopback: true }));
});

test('originAllowed only allows loopback in dev with empty allowlist', () => {
  assert.ok(originAllowed('http://localhost:5000', [], { production: false, allowDevLoopback: true }));
  assert.ok(originAllowed('http://127.0.0.1:3000', [], { production: false, allowDevLoopback: true }));
  assert.ok(!originAllowed('https://evil.com', [], { production: false, allowDevLoopback: true }));
  assert.ok(!originAllowed('http://localhost:5000', [], { production: false }));
});
