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

test('rejects excessively nested report containers without overflowing the stack', () => {
  let value = { repo: { name: 'github.com/acme/deep' }, score: 7, checks: [] };
  for (let index = 0; index < 110; index += 1) value = [value];
  assert.throws(() => parseReportText(JSON.stringify(value), '/tmp/deep.json'), /nesting exceeds/);
});

test('bounds oversized text fields and check collections', () => {
  const [report] = parseReportText(JSON.stringify({
    repo: { name: `github.com/acme/${'x'.repeat(25000)}` },
    score: 7,
    checks: Array.from({ length: 5100 }, (_, index) => ({ name: `Check-${index}`, score: 10 }))
  }), '/tmp/bounds.json');
  assert.equal(report.checks.length, 5000);
  assert.ok(report.repo.length <= 20000);
});

test('bounds untrusted advisory text before returning it to the renderer', () => {
  const result = combineIntel('CVE-2099-0002', {
    github: {
      severity: 'high',
      summary: 't'.repeat(1000),
      description: 'd'.repeat(25000),
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: 'p'.repeat(1000) },
        vulnerable_version_range: 'r'.repeat(3000),
        first_patched_version: '1.2.3'
      }]
    },
    osv: null,
    kev: null,
    epss: null,
    aliases: Array.from({ length: 150 }, (_, index) => `CVE-2099-${String(index).padStart(4, '0')}`)
  });
  assert.ok(result.title.length <= 501);
  assert.ok(result.description.length <= 20001);
  assert.equal(result.aliases.length, 100);
  assert.ok(result.affected[0].package.length <= 501);
  assert.ok(result.affected[0].vulnerableRange.length <= 2001);
});
