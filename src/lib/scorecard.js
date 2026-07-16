'use strict';

const path = require('node:path');

const CHECK_RISK = Object.freeze({
  'Binary-Artifacts': 'high',
  'Branch-Protection': 'high',
  'Code-Review': 'high',
  'Dangerous-Workflow': 'critical',
  'Maintained': 'high',
  'Packaging': 'high',
  'Token-Permissions': 'high',
  'Vulnerabilities': 'critical',
  'Pinned-Dependencies': 'medium',
  'Fuzzing': 'medium',
  'SAST': 'medium',
  'Security-Policy': 'medium',
  'Signed-Releases': 'medium',
  'CI-Tests': 'low',
  'CII-Best-Practices': 'low',
  'Contributors': 'low',
  'Dependency-Update-Tool': 'low',
  'License': 'low',
  'Webhooks': 'medium'
});

const RISK_WEIGHT = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, unknown: 1 });
const ID_PATTERN = /\b(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b/gi;

function parseReportText(text, filePath = 'unknown.json') {
  const trimmed = String(text || '').trim();
  if (!trimmed) return [];

  let value;
  try {
    value = JSON.parse(trimmed);
  } catch (jsonError) {
    const lines = trimmed.split(/\r?\n/).filter(Boolean);
    const parsed = [];
    for (let i = 0; i < lines.length; i += 1) {
      try {
        parsed.push(JSON.parse(lines[i]));
      } catch {
        const error = new Error(`Invalid JSON or NDJSON at line ${i + 1}: ${jsonError.message}`);
        error.cause = jsonError;
        throw error;
      }
    }
    value = parsed;
  }

  return flattenPotentialReports(value)
    .filter(looksLikeScorecard)
    .map((item, index) => normalizeReport(item, filePath, index));
}

function flattenPotentialReports(value) {
  if (Array.isArray(value)) return value.flatMap(flattenPotentialReports);
  if (!value || typeof value !== 'object') return [];

  if (Array.isArray(value.results) && !looksLikeScorecard(value)) {
    return value.results.flatMap(flattenPotentialReports);
  }
  if (Array.isArray(value.scorecards)) {
    return value.scorecards.flatMap(flattenPotentialReports);
  }
  return [value];
}

function looksLikeScorecard(value) {
  return Boolean(
    value.score !== undefined ||
    value.checks ||
    value.repo ||
    value.repository ||
    value.metadata?.scorecard ||
    value.run?.score
  );
}

function normalizeReport(raw, filePath, index = 0) {
  const repoName = firstString(
    raw?.repo?.name,
    raw?.repository?.name,
    raw?.repository,
    raw?.project?.name,
    raw?.project,
    raw?.target,
    raw?.metadata?.repository,
    raw?.metadata?.repo,
    raw?.source?.repository
  ) || inferRepoFromFilename(filePath);

  const score = firstNumber(raw?.score, raw?.overallScore, raw?.overall_score, raw?.run?.score, raw?.metadata?.score);
  const date = normalizeDate(firstString(
    raw?.date,
    raw?.timestamp,
    raw?.scanDate,
    raw?.scan_date,
    raw?.generatedAt,
    raw?.generated_at,
    raw?.metadata?.date,
    raw?.metadata?.timestamp,
    raw?.run?.date
  ));

  const checks = normalizeChecks(raw?.checks || raw?.results?.checks || raw?.run?.checks || []);
  const identifiers = extractIdentifiers(raw);
  const commit = firstString(raw?.repo?.commit, raw?.repository?.commit, raw?.commit, raw?.sha, raw?.metadata?.commit);
  const scorecardVersion = firstString(raw?.scorecard?.version, raw?.metadata?.scorecard?.version, raw?.version);

  const issues = checks
    .filter((check) => Number.isFinite(check.score) && check.score < 7)
    .map((check) => ({
      ...check,
      risk: CHECK_RISK[check.name] || 'unknown',
      severityWeight: (10 - check.score) * (RISK_WEIGHT[CHECK_RISK[check.name] || 'unknown'] || 1)
    }))
    .sort((a, b) => b.severityWeight - a.severityWeight || a.score - b.score || a.name.localeCompare(b.name));

  return {
    id: `${filePath}#${index}`,
    filePath,
    fileName: path.basename(filePath),
    reportIndex: index,
    repo: normalizeRepoName(repoName),
    repoUrl: toRepoUrl(repoName),
    score,
    grade: gradeForScore(score),
    date,
    commit,
    scorecardVersion,
    checks,
    issues,
    identifiers,
    raw
  };
}

function normalizeChecks(checks) {
  if (!Array.isArray(checks)) return [];
  return checks.map((check, index) => {
    if (typeof check === 'string') {
      return { name: check, score: null, reason: '', details: [], documentation: '', index };
    }

    const detailsValue = check?.details ?? check?.detail ?? check?.findings ?? check?.results ?? [];
    return {
      name: firstString(check?.name, check?.check, check?.id) || `Check ${index + 1}`,
      score: firstNumber(check?.score, check?.value),
      reason: firstString(check?.reason, check?.summary, check?.message) || '',
      details: normalizeDetails(detailsValue),
      documentation: normalizeExternalUrl(firstString(check?.documentation?.url, check?.documentation, check?.docs, check?.url) || ''),
      risk: CHECK_RISK[firstString(check?.name, check?.check, check?.id)] || 'unknown',
      raw: check
    };
  });
}

function normalizeDetails(value) {
  if (value == null) return [];
  if (Array.isArray(value)) return value.flatMap(normalizeDetails).filter(Boolean);
  if (typeof value === 'string') return [value];
  if (typeof value === 'number' || typeof value === 'boolean') return [String(value)];
  if (typeof value === 'object') {
    const preferred = firstString(value.message, value.reason, value.text, value.path, value.name);
    if (preferred) return [preferred];
    try {
      return [JSON.stringify(value)];
    } catch {
      return [];
    }
  }
  return [];
}

function extractIdentifiers(value) {
  const found = new Set();
  const seen = new WeakSet();

  function walk(item, depth = 0) {
    if (depth > 30 || item == null) return;
    if (typeof item === 'string') {
      const matches = item.match(ID_PATTERN) || [];
      for (const match of matches) found.add(match.toUpperCase());
      return;
    }
    if (typeof item !== 'object') return;
    if (seen.has(item)) return;
    seen.add(item);
    if (Array.isArray(item)) {
      item.forEach((entry) => walk(entry, depth + 1));
      return;
    }
    for (const entry of Object.values(item)) walk(entry, depth + 1);
  }

  walk(value);
  return [...found].sort();
}

function normalizeRepoName(value) {
  let repo = String(value || '').trim();
  repo = repo.replace(/^https?:\/\//i, '').replace(/^git@github\.com:/i, 'github.com/');
  repo = repo.replace(/\.git$/i, '').replace(/\/$/, '');
  return repo || 'Unknown repository';
}

function toRepoUrl(repoName) {
  const repo = normalizeRepoName(repoName);
  if (/^(github|gitlab|bitbucket)\.com\//i.test(repo)) return `https://${repo}`;
  if (/^[\w.-]+\/[\w.-]+$/.test(repo)) return `https://github.com/${repo}`;
  return '';
}


function normalizeExternalUrl(value) {
  const url = String(value || '').trim();
  if (!url) return '';
  if (/^https:\/\//i.test(url)) return url;
  if (/^(github|gitlab|bitbucket)\.com\//i.test(url)) return `https://${url}`;
  return '';
}

function inferRepoFromFilename(filePath) {
  return path.basename(filePath, path.extname(filePath)).replace(/[_]+/g, '/').replace(/--+/g, '/');
}

function normalizeDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function gradeForScore(score) {
  if (!Number.isFinite(score)) return '?';
  if (score >= 9) return 'A';
  if (score >= 8) return 'B';
  if (score >= 7) return 'C';
  if (score >= 5) return 'D';
  return 'F';
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function firstNumber(...values) {
  for (const value of values) {
    const number = typeof value === 'number' ? value : Number.parseFloat(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function ageInDays(isoDate, now = new Date()) {
  if (!isoDate) return null;
  const date = new Date(isoDate);
  if (Number.isNaN(date.getTime())) return null;
  return Math.max(0, Math.floor((now.getTime() - date.getTime()) / 86400000));
}

function staleLevel(isoDate, now = new Date()) {
  const days = ageInDays(isoDate, now);
  if (days == null) return 'unknown';
  if (days > 360) return 'red';
  if (days > 270) return 'yellow';
  return 'fresh';
}

function latestByRepository(reports) {
  const groups = new Map();
  for (const report of reports) {
    const key = report.repo.toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(report);
  }

  const output = [];
  for (const history of groups.values()) {
    history.sort((a, b) => reportTime(b) - reportTime(a));
    const latest = history[0];
    const previous = history[1] || null;
    output.push({
      ...latest,
      history,
      previousScore: previous?.score ?? null,
      scoreDelta: Number.isFinite(latest.score) && Number.isFinite(previous?.score)
        ? Number((latest.score - previous.score).toFixed(2))
        : null,
      reportCount: history.length
    });
  }
  return output;
}

function reportTime(report) {
  const parsed = report.date ? new Date(report.date).getTime() : 0;
  return Number.isFinite(parsed) ? parsed : 0;
}

module.exports = {
  CHECK_RISK,
  ageInDays,
  extractIdentifiers,
  gradeForScore,
  latestByRepository,
  normalizeReport,
  parseReportText,
  staleLevel
};
