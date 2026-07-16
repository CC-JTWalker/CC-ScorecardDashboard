'use strict';

const path = require('node:path');

const VULNERABILITY_ID_PATTERN = /^(?:CVE-\d{4}-\d{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})$/i;
const MAX_IDENTIFIERS = 1000;
const MAX_TOKEN_LENGTH = 2048;
const MAX_CSV_BYTES = 10 * 1024 * 1024;

function normalizeIdentifiers(values, max = MAX_IDENTIFIERS) {
  if (!Array.isArray(values)) throw new TypeError('Vulnerability identifiers must be an array.');
  if (values.length > max * 4) throw new RangeError(`Too many vulnerability identifiers; maximum is ${max}.`);

  const output = [];
  const seen = new Set();
  for (const value of values) {
    const id = String(value || '').trim().toUpperCase();
    if (!VULNERABILITY_ID_PATTERN.test(id) || seen.has(id)) continue;
    seen.add(id);
    output.push(id);
    if (output.length > max) throw new RangeError(`Too many vulnerability identifiers; maximum is ${max}.`);
  }
  return output;
}

function validateGitHubToken(value) {
  const token = String(value || '').trim();
  if (!token) return '';
  if (token.length > MAX_TOKEN_LENGTH) throw new RangeError('The GitHub token is unexpectedly long.');
  if (/[\u0000-\u001f\u007f\s]/.test(token)) throw new TypeError('The GitHub token contains invalid whitespace or control characters.');
  return token;
}

function validateCsvText(value) {
  if (typeof value !== 'string') throw new TypeError('CSV export data must be text.');
  if (Buffer.byteLength(value, 'utf8') > MAX_CSV_BYTES) {
    throw new RangeError(`CSV export is larger than ${MAX_CSV_BYTES / 1024 / 1024} MB.`);
  }
  if (value.includes('\u0000')) throw new TypeError('CSV export contains a null byte.');
  return value;
}

function isPathWithin(root, candidate) {
  if (!root || !candidate) return false;
  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(candidate);
  const relative = path.relative(resolvedRoot, resolvedCandidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function isSafeHttpsUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'https:' && !url.username && !url.password && (!url.port || url.port === '443');
  } catch {
    return false;
  }
}

module.exports = {
  MAX_CSV_BYTES,
  MAX_IDENTIFIERS,
  VULNERABILITY_ID_PATTERN,
  isPathWithin,
  isSafeHttpsUrl,
  normalizeIdentifiers,
  validateCsvText,
  validateGitHubToken
};
