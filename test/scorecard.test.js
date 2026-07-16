'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  extractIdentifiers,
  latestByRepository,
  parseReportText,
  staleLevel
} = require('../src/lib/scorecard');
const { combineIntel, mapKev } = require('../src/lib/vuln-intel');

test('parses and normalizes a Scorecard JSON report', () => {
  const [report] = parseReportText(JSON.stringify({
    date: '2026-01-02T03:04:05Z',
    repo: { name: 'github.com/acme/widget', commit: 'abc123' },
    score: 6.5,
    checks: [{ name: 'Branch-Protection', score: 3, reason: 'not enabled' }]
  }), '/tmp/widget.json');

  assert.equal(report.repo, 'github.com/acme/widget');
  assert.equal(report.score, 6.5);
  assert.equal(report.grade, 'D');
  assert.equal(report.issues[0].risk, 'high');
  assert.equal(report.repoUrl, 'https://github.com/acme/widget');
});

test('supports newline-delimited reports and ignores unrelated JSON objects', () => {
  const input = [
    JSON.stringify({ repo: { name: 'github.com/acme/a' }, score: 8, checks: [] }),
    JSON.stringify({ unrelated: true }),
    JSON.stringify({ repo: { name: 'github.com/acme/b' }, score: 4, checks: [] })
  ].join('\n');
  const reports = parseReportText(input, '/tmp/reports.json');
  assert.equal(reports.length, 2);
});

test('extracts and deduplicates CVE and GHSA identifiers recursively', () => {
  const ids = extractIdentifiers({
    reason: 'CVE-2021-44228 and ghsa-jfhm-5ghh-2f97',
    nested: ['CVE-2021-44228']
  });
  assert.deepEqual(ids, ['CVE-2021-44228', 'GHSA-JFHM-5GHH-2F97']);
});

test('applies exact stale thresholds', () => {
  const now = new Date('2026-07-16T00:00:00Z');
  assert.equal(staleLevel('2025-10-19T00:00:00Z', now), 'fresh'); // 270 days
  assert.equal(staleLevel('2025-10-18T00:00:00Z', now), 'yellow'); // 271 days
  assert.equal(staleLevel('2025-07-21T00:00:00Z', now), 'yellow'); // 360 days
  assert.equal(staleLevel('2025-07-20T00:00:00Z', now), 'red'); // 361 days
});

test('groups history and computes latest score delta', () => {
  const reports = [
    ...parseReportText(JSON.stringify({ date: '2025-01-01', repo: { name: 'github.com/acme/a' }, score: 5, checks: [] }), 'old.json'),
    ...parseReportText(JSON.stringify({ date: '2026-01-01', repo: { name: 'github.com/acme/a' }, score: 7.5, checks: [] }), 'new.json')
  ];
  const [latest] = latestByRepository(reports);
  assert.equal(latest.fileName, 'new.json');
  assert.equal(latest.reportCount, 2);
  assert.equal(latest.scoreDelta, 2.5);
});

test('CISA KEV evidence forces critical priority', () => {
  const kevMap = mapKev({ vulnerabilities: [{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }] });
  const result = combineIntel('CVE-2021-44228', {
    github: { severity: 'critical', summary: 'Example', cvss: { score: 10, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' } },
    osv: null,
    kev: kevMap.get('CVE-2021-44228'),
    epss: { probability: 0.9, percentile: 0.999 },
    aliases: ['CVE-2021-44228']
  });
  assert.equal(result.priority, 100);
  assert.equal(result.priorityLabel, 'Critical');
  assert.match(result.reasons.join(' '), /Confirmed exploitation/);
});

test('calculates CVSS v3 base score from OSV vectors', () => {
  const result = combineIntel('CVE-2099-0001', {
    github: null,
    osv: {
      summary: 'Vector-only advisory',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      affected: []
    },
    kev: null,
    epss: { probability: 0.01, percentile: 0.5 },
    aliases: ['CVE-2099-0001']
  });
  assert.equal(result.cvss.score, 9.8);
  assert.equal(result.severity, 'critical');
});
