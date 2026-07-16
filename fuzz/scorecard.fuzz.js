'use strict';

const assert = require('node:assert/strict');
const fc = require('fast-check');
const { extractIdentifiers, parseReportText } = require('../src/lib/scorecard');

const shortText = fc.string({ maxLength: 160 });
const checkArbitrary = fc.record({
  name: shortText,
  score: fc.oneof(fc.double({ min: -1, max: 10, noNaN: true }), shortText),
  reason: shortText,
  details: fc.array(shortText, { maxLength: 8 })
});
const reportArbitrary = fc.record({
  date: fc.date({ min: new Date('2000-01-01T00:00:00Z'), max: new Date('2100-01-01T00:00:00Z'), noInvalidDate: true }).map((date) => date.toISOString()),
  repo: fc.record({ name: shortText, commit: shortText }),
  score: fc.double({ min: -100, max: 100, noNaN: true }),
  checks: fc.array(checkArbitrary, { maxLength: 40 })
});

fc.assert(fc.property(reportArbitrary, (input) => {
  const reports = parseReportText(JSON.stringify(input), '/tmp/fuzz-report.json');
  assert.equal(reports.length, 1);
  assert.ok(Array.isArray(reports[0].checks));
  assert.ok(Array.isArray(reports[0].issues));
  assert.ok(Array.isArray(reports[0].identifiers));
}), { numRuns: 1000 });

fc.assert(fc.property(fc.array(shortText, { maxLength: 100 }), (values) => {
  const identifiers = extractIdentifiers({ values });
  assert.equal(identifiers.length, new Set(identifiers).size);
  for (const identifier of identifiers) {
    assert.match(identifier, /^(?:CVE-\d{4}-\d{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})$/);
  }
}), { numRuns: 1000 });

console.log('Property-based fuzz tests passed (2,000 generated cases).');
