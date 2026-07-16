'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { isSafeHttpsUrl, normalizeIdentifiers } = require('./security');

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const OSV_URL = 'https://api.osv.dev/v1/vulns/';
const GITHUB_ADVISORIES_URL = 'https://api.github.com/advisories';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const KEV_CACHE_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_ADVISORY_BYTES = 5 * 1024 * 1024;
const MAX_EPSS_BYTES = 10 * 1024 * 1024;
const MAX_KEV_BYTES = 30 * 1024 * 1024;
const USER_AGENT = 'Scorecard-Radar/1.1.0';

class VulnerabilityIntelService {
  constructor({ cacheDir, getGitHubToken = () => '' } = {}) {
    this.cacheDir = cacheDir || path.join(process.cwd(), '.cache');
    this.getGitHubToken = getGitHubToken;
    this.kevMap = null;
    this.kevLoadedAt = 0;
  }

  async enrich(identifiers, onProgress = () => {}) {
    const ids = normalizeIdentifiers(identifiers);
    if (!ids.length) return [];

    await fs.mkdir(this.cacheDir, { recursive: true, mode: 0o700 });
    const cached = new Map();
    const pending = [];

    for (const id of ids) {
      const value = await this.readCache(id);
      if (value) cached.set(id, { ...value, cacheStatus: 'cached' });
      else pending.push(id);
    }

    onProgress({ phase: 'cache', completed: cached.size, total: ids.length });
    if (!pending.length) return ids.map((id) => cached.get(id));

    const kevPromise = this.loadKev().catch(() => new Map());
    const cveIds = pending.filter((id) => id.startsWith('CVE-'));
    const epssPromise = this.fetchEpss(cveIds).catch(() => new Map());

    const fresh = new Map();
    let complete = cached.size;
    await mapLimit(pending, 4, async (id) => {
      const [github, osv, kevMap, epssMap] = await Promise.all([
        this.fetchGitHubAdvisory(id).catch((error) => ({ error: error.message })),
        this.fetchOsv(id).catch((error) => ({ error: error.message })),
        kevPromise,
        epssPromise
      ]);

      const aliases = collectAliases(id, github, osv);
      let kev = null;
      let epss = null;
      const aliasCves = aliases.filter((alias) => alias.startsWith('CVE-'));
      for (const alias of aliasCves) {
        if (!kev) kev = kevMap.get(alias) || null;
        if (!epss) epss = epssMap.get(alias) || null;
      }
      if (!epss && aliasCves.length) {
        const aliasEpss = await this.fetchEpss(aliasCves).catch(() => new Map());
        for (const alias of aliasCves) {
          if (!epss) epss = aliasEpss.get(alias) || null;
        }
      }

      const enriched = combineIntel(id, { github, osv, kev, epss, aliases });
      fresh.set(id, enriched);
      await this.writeCache(id, enriched).catch(() => {});
      complete += 1;
      onProgress({ phase: 'network', completed: complete, total: ids.length, id });
    });

    return ids.map((id) => fresh.get(id) || cached.get(id));
  }

  async fetchGitHubAdvisory(id) {
    const url = new URL(GITHUB_ADVISORIES_URL);
    if (id.startsWith('GHSA-')) url.searchParams.set('ghsa_id', id);
    else if (id.startsWith('CVE-')) url.searchParams.set('cve_id', id);
    else return null;
    url.searchParams.set('per_page', '1');

    const token = String(this.getGitHubToken() || '').trim();
    const headers = {
      Accept: 'application/vnd.github+json',
      'User-Agent': USER_AGENT
    };
    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetchWithTimeout(url, { headers }, 15000);
    if (response.status === 403 || response.status === 429) {
      throw new Error('GitHub advisory rate limit reached; add a GitHub token in Settings.');
    }
    if (!response.ok) throw new Error(`GitHub advisory request failed (${response.status})`);
    const data = await readJsonResponse(response, MAX_ADVISORY_BYTES);
    return Array.isArray(data) ? data[0] || null : data;
  }

  async fetchOsv(id) {
    const response = await fetchWithTimeout(`${OSV_URL}${encodeURIComponent(id)}`, {
      headers: { 'User-Agent': USER_AGENT }
    }, 15000);
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`OSV request failed (${response.status})`);
    return readJsonResponse(response, MAX_ADVISORY_BYTES);
  }

  async fetchEpss(cveIds) {
    const result = new Map();
    for (const chunk of chunks(cveIds, 100)) {
      if (!chunk.length) continue;
      const url = new URL(EPSS_URL);
      url.searchParams.set('cve', chunk.join(','));
      const response = await fetchWithTimeout(url, {
        headers: { 'User-Agent': USER_AGENT }
      }, 15000);
      if (!response.ok) throw new Error(`EPSS request failed (${response.status})`);
      const payload = await readJsonResponse(response, MAX_EPSS_BYTES);
      for (const item of payload?.data || []) {
        result.set(String(item.cve).toUpperCase(), {
          probability: toNumber(item.epss),
          percentile: toNumber(item.percentile),
          date: item.date || null
        });
      }
    }
    return result;
  }

  async loadKev() {
    if (this.kevMap && Date.now() - this.kevLoadedAt < KEV_CACHE_TTL_MS) return this.kevMap;

    const cachePath = path.join(this.cacheDir, 'cisa-kev.json');
    const cached = await readJson(cachePath).catch(() => null);
    if (cached?.savedAt && Date.now() - cached.savedAt < KEV_CACHE_TTL_MS && cached.payload) {
      this.kevMap = mapKev(cached.payload);
      this.kevLoadedAt = cached.savedAt;
      return this.kevMap;
    }

    try {
      const response = await fetchWithTimeout(CISA_KEV_URL, {
        headers: { 'User-Agent': USER_AGENT }
      }, 20000);
      if (!response.ok) throw new Error(`CISA KEV request failed (${response.status})`);
      const payload = await readJsonResponse(response, MAX_KEV_BYTES);
      this.kevMap = mapKev(payload);
      this.kevLoadedAt = Date.now();
      await writeJsonAtomic(cachePath, { savedAt: this.kevLoadedAt, payload });
      return this.kevMap;
    } catch (error) {
      if (cached?.payload) {
        this.kevMap = mapKev(cached.payload);
        this.kevLoadedAt = cached.savedAt || 0;
        return this.kevMap;
      }
      throw error;
    }
  }

  async readCache(id) {
    const cachePath = path.join(this.cacheDir, 'vulnerabilities', `${safeName(id)}.json`);
    const cached = await readJson(cachePath).catch(() => null);
    if (!cached?.savedAt || !cached?.data) return null;
    if (Date.now() - cached.savedAt > CACHE_TTL_MS) return null;
    return cached.data;
  }

  async writeCache(id, data) {
    const cachePath = path.join(this.cacheDir, 'vulnerabilities', `${safeName(id)}.json`);
    await writeJsonAtomic(cachePath, { savedAt: Date.now(), data });
  }

  async clearCache() {
    await fs.rm(this.cacheDir, { recursive: true, force: true });
    this.kevMap = null;
    this.kevLoadedAt = 0;
  }
}

function combineIntel(id, { github, osv, kev, epss, aliases }) {
  const cvss = bestCvss(github, osv);
  const severity = String(github?.severity || severityFromCvss(cvss?.score) || 'unknown').toLowerCase();
  const affected = collectAffected(github, osv);
  const fixedAvailable = affected.some((item) => item.fixedVersion || item.fixedRanges?.length);
  const vector = cvss?.vector || '';
  const networkReachable = /\/AV:N(?:\/|$)/.test(vector);
  const noPrivileges = /\/PR:N(?:\/|$)/.test(vector);
  const noUserInteraction = /\/UI:N(?:\/|$)/.test(vector);

  let priority = Number.isFinite(cvss?.score) ? cvss.score * 6 : severityBase(severity);
  const reasons = [];

  if (kev) {
    priority = 100;
    reasons.push('Confirmed exploitation in the wild (CISA KEV)');
  } else {
    if (epss?.probability >= 0.5) {
      priority += 25;
      reasons.push(`Very high EPSS probability (${formatPercent(epss.probability)})`);
    } else if (epss?.probability >= 0.1) {
      priority += 18;
      reasons.push(`High EPSS probability (${formatPercent(epss.probability)})`);
    } else if (epss?.probability >= 0.02) {
      priority += 10;
      reasons.push(`Elevated EPSS probability (${formatPercent(epss.probability)})`);
    } else if (epss) {
      priority += Math.min(5, epss.probability * 100);
      reasons.push(`Low current EPSS probability (${formatPercent(epss.probability)})`);
    }

    if (epss?.percentile >= 0.95) priority += 8;
    else if (epss?.percentile >= 0.8) priority += 4;

    if (networkReachable) {
      priority += 5;
      reasons.push('Network-reachable attack vector');
    }
    if (noPrivileges) {
      priority += 3;
      reasons.push('No privileges required');
    }
    if (noUserInteraction) priority += 2;
    if (!fixedAvailable && affected.length) {
      priority += 8;
      reasons.push('No fixed version identified');
    }
  }

  if (Number.isFinite(cvss?.score)) reasons.unshift(`CVSS ${cvss.score.toFixed(1)} (${cvss.version || 'unknown version'})`);
  if (fixedAvailable) reasons.push('A fixed version is available');
  priority = Math.max(0, Math.min(100, Math.round(priority)));

  return {
    id,
    aliases: aliases.slice(0, 100),
    title: limitText(github?.summary || osv?.summary || id, 500),
    description: limitText(github?.description || osv?.details || '', 20000),
    severity,
    priority,
    priorityLabel: priorityLabel(priority, Boolean(kev)),
    reasons: dedupe(reasons),
    cvss,
    epss: epss || null,
    kev: kev || null,
    affected,
    fixedAvailable,
    publishedAt: github?.published_at || osv?.published || null,
    updatedAt: github?.updated_at || osv?.modified || null,
    references: dedupe([
      github?.html_url,
      ...(github?.references || []),
      ...((osv?.references || []).map((ref) => ref.url))
    ].filter(isSafeHttpsUrl)).slice(0, 12),
    sources: {
      github: Boolean(github && !github.error),
      osv: Boolean(osv && !osv.error),
      cisaKev: Boolean(kev),
      epss: Boolean(epss)
    },
    errors: [github?.error, osv?.error].filter(Boolean),
    checkedAt: new Date().toISOString(),
    cacheStatus: 'fresh'
  };
}

function bestCvss(github, osv) {
  const candidates = [];
  const gh = github?.cvss_severities;
  if (gh?.cvss_v4?.score) candidates.push({ score: toNumber(gh.cvss_v4.score), vector: gh.cvss_v4.vector_string, version: '4.0' });
  if (gh?.cvss_v3?.score) candidates.push({ score: toNumber(gh.cvss_v3.score), vector: gh.cvss_v3.vector_string, version: '3.x' });
  if (github?.cvss?.score) candidates.push({ score: toNumber(github.cvss.score), vector: github.cvss.vector_string, version: '3.x' });

  for (const item of osv?.severity || []) {
    const score = extractCvssBaseScore(item?.score);
    if (Number.isFinite(score)) {
      candidates.push({ score, vector: item.score, version: item.type?.replace('CVSS_V', '').replace('_', '.') || 'unknown' });
    }
  }
  return candidates.filter((item) => Number.isFinite(item.score)).sort((a, b) => b.score - a.score)[0] || null;
}

function collectAffected(github, osv) {
  const output = [];
  for (const item of github?.vulnerabilities || []) {
    output.push({
      ecosystem: limitText(item?.package?.ecosystem || '', 100),
      package: limitText(item?.package?.name || '', 500),
      vulnerableRange: limitText(item?.vulnerable_version_range || '', 2000),
      fixedVersion: limitText(item?.first_patched_version || '', 500),
      fixedRanges: [],
      source: 'GitHub Advisory Database'
    });
  }
  for (const item of osv?.affected || []) {
    const fixedRanges = [];
    for (const range of item?.ranges || []) {
      for (const event of range?.events || []) {
        if (event.fixed) fixedRanges.push(event.fixed);
      }
    }
    output.push({
      ecosystem: limitText(item?.package?.ecosystem || '', 100),
      package: limitText(item?.package?.name || item?.package?.purl || '', 500),
      vulnerableRange: limitText(summarizeOsvRanges(item?.ranges || []), 2000),
      fixedVersion: limitText(fixedRanges[0] || '', 500),
      fixedRanges: fixedRanges.map((value) => limitText(value, 500)).slice(0, 50),
      source: 'OSV'
    });
  }

  const seen = new Set();
  return output.filter((item) => {
    const key = `${item.ecosystem}|${item.package}|${item.vulnerableRange}|${item.fixedVersion}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return Boolean(item.package || item.vulnerableRange || item.fixedVersion);
  }).slice(0, 30);
}

function summarizeOsvRanges(ranges) {
  const parts = [];
  for (const range of ranges || []) {
    const introduced = [];
    const fixed = [];
    for (const event of range?.events || []) {
      if (event.introduced) introduced.push(event.introduced);
      if (event.fixed) fixed.push(event.fixed);
      if (event.last_affected) fixed.push(`through ${event.last_affected}`);
    }
    if (introduced.length || fixed.length) {
      parts.push(`${range.type || 'range'}: ${introduced.join(', ') || 'unknown'} → ${fixed.join(', ') || 'unfixed'}`);
    }
  }
  return limitText(parts.join('; '), 2000);
}

function collectAliases(id, github, osv) {
  const values = [id, osv?.id, ...(osv?.aliases || [])];
  for (const item of github?.identifiers || []) values.push(item?.value);
  if (github?.ghsa_id) values.push(github.ghsa_id);
  if (github?.cve_id) values.push(github.cve_id);
  return dedupe(values.filter(Boolean).map((value) => limitText(value, 100).toUpperCase())).slice(0, 100);
}

function mapKev(payload) {
  const map = new Map();
  for (const item of payload?.vulnerabilities || []) {
    if (!item?.cveID) continue;
    map.set(String(item.cveID).toUpperCase(), {
      cveId: limitText(item.cveID, 100),
      vendorProject: limitText(item.vendorProject || '', 500),
      product: limitText(item.product || '', 500),
      vulnerabilityName: limitText(item.vulnerabilityName || '', 1000),
      dateAdded: limitText(item.dateAdded || '', 50) || null,
      dueDate: limitText(item.dueDate || '', 50) || null,
      requiredAction: limitText(item.requiredAction || '', 5000),
      knownRansomwareCampaignUse: limitText(item.knownRansomwareCampaignUse || 'Unknown', 100),
      notes: limitText(item.notes || '', 5000)
    });
  }
  return map;
}

function severityBase(severity) {
  return ({ critical: 60, high: 45, medium: 25, low: 10, unknown: 15 })[severity] || 15;
}

function severityFromCvss(score) {
  if (!Number.isFinite(score)) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function priorityLabel(score, kev) {
  if (kev || score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 35) return 'Medium';
  return 'Low';
}

function extractCvssBaseScore(vector) {
  if (typeof vector !== 'string') return null;
  const match = vector.match(/(?:^|\/)SCORE:([0-9.]+)/i);
  if (match) return toNumber(match[1]);
  if (/^CVSS:3\.[01]\//i.test(vector)) return calculateCvss3(vector);
  return null;
}


function calculateCvss3(vector) {
  const metrics = Object.fromEntries(vector.split('/').slice(1).map((part) => part.split(':')));
  const av = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 })[metrics.AV];
  const ac = ({ L: 0.77, H: 0.44 })[metrics.AC];
  const ui = ({ N: 0.85, R: 0.62 })[metrics.UI];
  const scopeChanged = metrics.S === 'C';
  const pr = scopeChanged
    ? ({ N: 0.85, L: 0.68, H: 0.5 })[metrics.PR]
    : ({ N: 0.85, L: 0.62, H: 0.27 })[metrics.PR];
  const c = ({ N: 0, L: 0.22, H: 0.56 })[metrics.C];
  const i = ({ N: 0, L: 0.22, H: 0.56 })[metrics.I];
  const a = ({ N: 0, L: 0.22, H: 0.56 })[metrics.A];
  if ([av, ac, ui, pr, c, i, a].some((value) => !Number.isFinite(value))) return null;

  const impactSubScore = 1 - ((1 - c) * (1 - i) * (1 - a));
  const impact = scopeChanged
    ? 7.52 * (impactSubScore - 0.029) - 3.25 * Math.pow(impactSubScore - 0.02, 15)
    : 6.42 * impactSubScore;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const base = scopeChanged
    ? Math.min(10, 1.08 * (impact + exploitability))
    : Math.min(10, impact + exploitability);
  return roundUp1(base);
}

function roundUp1(value) {
  return Math.ceil((value - 1e-10) * 10) / 10;
}

function formatPercent(value) {
  return `${(Number(value) * 100).toFixed(value >= 0.1 ? 1 : 2)}%`;
}

function chunks(items, size) {
  const result = [];
  for (let i = 0; i < items.length; i += size) result.push(items.slice(i, i + size));
  return result;
}

async function mapLimit(items, limit, mapper) {
  const queue = [...items];
  const workers = Array.from({ length: Math.min(limit, queue.length) }, async () => {
    while (queue.length) {
      const item = queue.shift();
      await mapper(item);
    }
  });
  await Promise.all(workers);
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { redirect: 'error', credentials: 'omit', referrerPolicy: 'no-referrer', ...options, signal: controller.signal });
  } catch (error) {
    if (error.name === 'AbortError') throw new Error(`Request timed out after ${Math.round(timeoutMs / 1000)} seconds`);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}


async function readJsonResponse(response, maxBytes) {
  const declaredLength = Number.parseInt(response.headers.get('content-length') || '', 10);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error(`Response exceeded the ${Math.round(maxBytes / 1024 / 1024)} MB safety limit.`);
  }

  if (!response.body?.getReader) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('Response exceeded the safety limit.');
    return JSON.parse(text);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`Response exceeded the ${Math.round(maxBytes / 1024 / 1024)} MB safety limit.`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
}

async function readJson(filePath) {
  const stat = await fs.stat(filePath);
  if (stat.size > MAX_KEV_BYTES) throw new Error('Cached intelligence file is unexpectedly large.');
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

async function writeJsonAtomic(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(temp, JSON.stringify(value), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await fs.rename(temp, filePath);
  await fs.chmod(filePath, 0o600).catch(() => {});
}

function safeName(value) {
  return String(value).replace(/[^a-z0-9._-]+/gi, '_');
}

function limitText(value, maxLength) {
  const text = String(value ?? '');
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}…`;
}

function toNumber(value) {
  const number = Number.parseFloat(value);
  return Number.isFinite(number) ? number : null;
}

function dedupe(items) {
  return [...new Set(items)];
}

module.exports = {
  VulnerabilityIntelService,
  combineIntel,
  mapKev,
  priorityLabel
};
