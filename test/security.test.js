'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {
  isPathWithin,
  isSafeHttpsUrl,
  normalizeIdentifiers,
  validateCsvText,
  validateGitHubToken
} = require('../src/lib/security');

test('normalizes only valid CVE and GHSA identifiers', () => {
  assert.deepEqual(normalizeIdentifiers([
    ' cve-2021-44228 ',
    'CVE-2021-44228',
    'GHSA-JFHM-5GHH-2F97',
    'not-an-id'
  ]), ['CVE-2021-44228', 'GHSA-JFHM-5GHH-2F97']);
});

test('rejects oversized identifier collections', () => {
  const ids = Array.from({ length: 1001 }, (_, index) => `CVE-2026-${String(index + 1000).padStart(4, '0')}`);
  assert.throws(() => normalizeIdentifiers(ids), /Too many/);
});

test('validates token shape without persisting it', () => {
  assert.equal(validateGitHubToken('github_pat_example123'), 'github_pat_example123');
  assert.throws(() => validateGitHubToken('token with spaces'), /whitespace/);
  assert.throws(() => validateGitHubToken(`x${'a'.repeat(2048)}`), /long/);
});

test('checks containment without prefix confusion', () => {
  const root = path.join(path.sep, 'tmp', 'reports');
  assert.equal(isPathWithin(root, path.join(root, 'nested', 'report.json')), true);
  assert.equal(isPathWithin(root, path.join(path.sep, 'tmp', 'reports-evil', 'report.json')), false);
});

test('permits only credential-free HTTPS URLs', () => {
  assert.equal(isSafeHttpsUrl('https://github.com/org/repo'), true);
  assert.equal(isSafeHttpsUrl('http://github.com/org/repo'), false);
  assert.equal(isSafeHttpsUrl('https://user:pass@example.com/'), false);
  assert.equal(isSafeHttpsUrl('javascript:alert(1)'), false);
});

test('limits exported CSV text', () => {
  assert.equal(validateCsvText('a,b\r\n1,2'), 'a,b\r\n1,2');
  assert.throws(() => validateCsvText('a\u0000b'), /null byte/);
  assert.throws(() => validateCsvText('x'.repeat(10 * 1024 * 1024 + 1)), /larger/);
});
