'use strict';

const api = window.scorecardRadar;
const els = Object.fromEntries([...document.querySelectorAll('[id]')].map((el) => [el.id, el]));

const state = {
  directory: '',
  allReports: [],
  errors: [],
  intel: new Map(),
  selectedReportId: null,
  activeTab: 'overview',
  enriching: false,
  settings: {
    recursive: loadBoolean('recursive', true),
    autoEnrich: loadBoolean('autoEnrich', true),
    latestOnly: loadBoolean('latestOnly', true)
  }
};

els.recursiveToggle.checked = state.settings.recursive;
els.autoEnrichToggle.checked = state.settings.autoEnrich;
els.latestOnlyToggle.checked = state.settings.latestOnly;

els.openButton.addEventListener('click', chooseDirectory);
els.welcomeOpenButton.addEventListener('click', chooseDirectory);
els.refreshButton.addEventListener('click', () => scanDirectory(state.directory));
els.enrichButton.addEventListener('click', () => enrichAll(true));
els.searchInput.addEventListener('input', renderAll);
els.statusFilter.addEventListener('change', renderAll);
els.sortSelect.addEventListener('change', renderAll);
els.latestOnlyToggle.addEventListener('change', () => {
  state.settings.latestOnly = els.latestOnlyToggle.checked;
  saveBoolean('latestOnly', state.settings.latestOnly);
  renderAll();
});
els.exportButton.addEventListener('click', exportCsv);
els.closeDrawerButton.addEventListener('click', closeDrawer);
els.drawerBackdrop.addEventListener('click', closeDrawer);
els.settingsButton.addEventListener('click', openSettings);
els.recursiveToggle.addEventListener('change', () => {
  state.settings.recursive = els.recursiveToggle.checked;
  saveBoolean('recursive', state.settings.recursive);
});
els.autoEnrichToggle.addEventListener('change', () => {
  state.settings.autoEnrich = els.autoEnrichToggle.checked;
  saveBoolean('autoEnrich', state.settings.autoEnrich);
});
els.saveTokenButton.addEventListener('click', saveToken);
els.removeTokenButton.addEventListener('click', removeToken);
els.clearCacheButton.addEventListener('click', clearCache);
els.drawerTabs.addEventListener('click', (event) => {
  const button = event.target.closest('button[data-tab]');
  if (!button) return;
  state.activeTab = button.dataset.tab;
  renderDrawer();
});
document.addEventListener('dragover', (event) => {
  event.preventDefault();
  event.dataTransfer.dropEffect = 'copy';
});
document.addEventListener('drop', async (event) => {
  event.preventDefault();
  const file = event.dataTransfer.files?.[0];
  if (!file) return;
  try {
    const droppedPath = api.getPathForFile(file);
    await scanDirectory(droppedPath);
  } catch (error) {
    toast(error.message || 'Drop a directory containing Scorecard JSON files.');
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && els.detailDrawer.classList.contains('open')) closeDrawer();
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'o') {
    event.preventDefault();
    chooseDirectory();
  }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'r' && state.directory) {
    event.preventDefault();
    scanDirectory(state.directory);
  }
});

api.onDirectoryRequested((directory) => scanDirectory(directory));
api.onIntelProgress((progress) => {
  els.scanStatus.textContent = `Vulnerability intelligence ${progress.completed}/${progress.total}${progress.id ? ` · ${progress.id}` : ''}`;
});

async function chooseDirectory() {
  const directory = await api.chooseDirectory();
  if (directory) await scanDirectory(directory);
}

async function scanDirectory(directory) {
  if (!directory) return;
  setBusy(true, 'Reading JSON reports…');
  try {
    const result = await api.scanDirectory({ directory, recursive: state.settings.recursive });
    state.directory = result.directory;
    state.allReports = result.reports;
    state.errors = result.errors;
    state.intel.clear();
    state.selectedReportId = null;
    closeDrawer();

    els.welcome.classList.add('hidden');
    els.dashboard.classList.remove('hidden');
    els.directoryPath.textContent = result.directory;
    els.scanStatus.textContent = `${result.reports.length} report${plural(result.reports.length)} from ${result.fileCount} JSON file${plural(result.fileCount)}`;
    els.refreshButton.disabled = false;
    els.enrichButton.disabled = !allIdentifiers().length;
    renderAll();

    if (state.settings.autoEnrich && allIdentifiers().length) await enrichAll(false);
  } catch (error) {
    toast(error.message || 'The directory could not be scanned.');
  } finally {
    setBusy(false);
  }
}

async function enrichAll(userInitiated) {
  const identifiers = allIdentifiers();
  if (!identifiers.length) {
    if (userInitiated) toast('No CVE or GHSA identifiers were found in these reports.');
    return;
  }
  if (state.enriching) return;
  state.enriching = true;
  els.enrichButton.disabled = true;
  els.enrichButton.textContent = 'Checking…';
  try {
    const intelligence = await api.enrichVulnerabilities(identifiers);
    for (const item of intelligence.filter(Boolean)) state.intel.set(item.id, item);
    const latestCheck = intelligence.map((item) => item?.checkedAt).filter(Boolean).sort().at(-1);
    els.intelFreshness.textContent = latestCheck
      ? `Intelligence checked ${formatRelativeTime(latestCheck)} · ${intelligence.length} identifier${plural(intelligence.length)}`
      : 'No vulnerability intelligence returned';
    renderAll();
    if (state.selectedReportId) renderDrawer();
    if (userInitiated) toast(`Updated intelligence for ${intelligence.length} identifier${plural(intelligence.length)}.`);
  } catch (error) {
    els.intelFreshness.textContent = 'Intelligence check incomplete';
    toast(error.message || 'Vulnerability intelligence could not be loaded.');
  } finally {
    state.enriching = false;
    els.enrichButton.disabled = false;
    els.enrichButton.textContent = 'Check vulnerabilities';
    els.scanStatus.textContent = `${state.allReports.length} report${plural(state.allReports.length)} loaded`;
  }
}

function renderAll() {
  if (!state.allReports.length) {
    els.summaryCards.innerHTML = summaryCard('Reports', '0', 'No recognizable reports', '');
    els.attentionQueue.innerHTML = '<div class="empty-results">No actionable Scorecard report data was found.</div>';
  }
  const baseReports = state.settings.latestOnly ? latestByRepo(state.allReports) : state.allReports.map(withHistoryMetadata);
  const reports = filterAndSort(baseReports);
  renderSummary(baseReports);
  renderAttentionQueue(baseReports);
  renderTable(reports);
  renderErrors();
}

function renderSummary(reports) {
  const numericScores = reports.map((report) => report.score).filter(Number.isFinite);
  const average = numericScores.length ? numericScores.reduce((sum, score) => sum + score, 0) / numericScores.length : null;
  const stale = reports.filter((report) => ageDays(report.date) > 270).length;
  const expired = reports.filter((report) => ageDays(report.date) > 360).length;
  const critical = reports.filter((report) => reportPriority(report) >= 80).length;
  const weakChecks = reports.reduce((sum, report) => sum + report.issues.filter((issue) => issue.score < 5).length, 0);
  const ids = new Set(reports.flatMap((report) => report.identifiers));

  els.summaryCards.innerHTML = [
    summaryCard('Repositories', reports.length, `${state.allReports.length} total report${plural(state.allReports.length)}`, ''),
    summaryCard('Average score', average == null ? '—' : average.toFixed(1), scoreDescriptor(average), average >= 8 ? 'good' : average < 6 ? 'alert' : 'warn'),
    summaryCard('Critical attention', critical, 'Confirmed or high contextual risk', critical ? 'alert' : 'good'),
    summaryCard('Weak checks', weakChecks, 'Check score below 5', weakChecks ? 'warn' : 'good'),
    summaryCard('Stale reports', stale, `${expired} over 360 days`, expired ? 'alert' : stale ? 'warn' : 'good'),
    summaryCard('Vulnerability IDs', ids.size, state.intel.size ? `${state.intel.size} enriched` : 'Awaiting enrichment', ids.size ? 'warn' : 'good')
  ].join('');
}

function renderAttentionQueue(reports) {
  const items = [];
  for (const report of reports) {
    for (const issue of report.issues.slice(0, 3)) {
      items.push({
        report,
        kind: 'check',
        label: issue.name,
        detail: `${report.repo} · ${truncate(issue.reason || 'Low check score', 76)}`,
        score: Math.round(issue.severityWeight),
        rank: issue.severityWeight
      });
    }
    for (const id of report.identifiers) {
      const intel = intelForId(id);
      if (!intel || intel.priority < 35) continue;
      items.push({
        report,
        kind: 'vulnerability',
        label: `${intel.priorityLabel}: ${id}`,
        detail: `${report.repo} · ${truncate(intel.title, 76)}`,
        score: intel.priority,
        rank: intel.priority + (intel.kev ? 30 : 0)
      });
    }
    const days = ageDays(report.date);
    if (days > 270) {
      items.push({
        report,
        kind: 'stale',
        label: days > 360 ? 'Expired security picture' : 'Stale security picture',
        detail: `${report.repo} · Last scanned ${days} days ago`,
        score: days,
        rank: days > 360 ? 78 + Math.min(days - 360, 50) : 42 + Math.min(days - 270, 25)
      });
    }
  }

  const top = items.sort((a, b) => b.rank - a.rank).slice(0, 6);
  els.attentionQueue.innerHTML = top.length ? top.map((item) => `
    <article class="attention-item" data-report-id="${escapeAttr(item.report.id)}">
      <div class="attention-icon">${item.kind === 'vulnerability' ? 'V' : item.kind === 'stale' ? 'T' : '!'}</div>
      <div><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.detail)}</small></div>
      <span class="attention-score">${escapeHtml(String(item.score))}</span>
    </article>`).join('') : '<div class="empty-results">No major issues are currently visible in the loaded reports.</div>';

  els.attentionQueue.querySelectorAll('[data-report-id]').forEach((item) => {
    item.addEventListener('click', () => openReport(item.dataset.reportId));
  });
}

function renderTable(reports) {
  els.resultCount.textContent = `${reports.length} shown`;
  els.emptyResults.classList.toggle('hidden', reports.length > 0);
  els.reportTableBody.innerHTML = reports.map((report) => {
    const days = ageDays(report.date);
    const staleClass = days > 360 ? 'stale-red' : days > 270 ? 'stale-yellow' : '';
    const issue = report.issues[0];
    const risk = reportVulnerabilityRisk(report);
    return `<tr class="${staleClass}" data-report-id="${escapeAttr(report.id)}">
      <td class="repo-cell"><strong>${escapeHtml(shortRepo(report.repo))}</strong><small title="${escapeAttr(report.filePath)}">${escapeHtml(report.fileName)}${report.reportCount > 1 ? ` · ${report.reportCount} scans` : ''}</small></td>
      <td><div class="score-wrap"><span class="score-badge ${scoreClass(report.score)}">${formatScore(report.score)}</span><span class="grade">Grade ${escapeHtml(report.grade)}</span></div></td>
      <td>${trendHtml(report.scoreDelta)}</td>
      <td>${issue ? `<span class="issue-name">${escapeHtml(issue.name)} · ${formatScore(issue.score)}/10</span><span class="issue-reason">${escapeHtml(issue.reason || 'No reason supplied')}</span>` : '<span class="issue-name">No low checks</span><span class="issue-reason">All scored checks are 7 or above</span>'}</td>
      <td>${riskPill(risk)}</td>
      <td class="date-cell"><strong>${formatDate(report.date)}</strong><small>${escapeHtml(report.dateSource || 'report')}</small></td>
      <td>${ageHtml(days)}</td>
    </tr>`;
  }).join('');

  els.reportTableBody.querySelectorAll('tr[data-report-id]').forEach((row) => {
    row.addEventListener('click', () => openReport(row.dataset.reportId));
  });
}

function renderErrors() {
  els.scanErrorsPanel.classList.toggle('hidden', !state.errors.length);
  els.scanErrorCount.textContent = state.errors.length;
  els.scanErrors.innerHTML = state.errors.map((error) => `<p><strong>${escapeHtml(error.filePath)}</strong><br>${escapeHtml(error.message)}</p>`).join('');
}

function openReport(reportId) {
  state.selectedReportId = reportId;
  state.activeTab = 'overview';
  renderDrawer();
  els.detailDrawer.classList.add('open');
  els.detailDrawer.setAttribute('aria-hidden', 'false');
  els.drawerBackdrop.classList.remove('hidden');
}

function closeDrawer() {
  els.detailDrawer.classList.remove('open');
  els.detailDrawer.setAttribute('aria-hidden', 'true');
  els.drawerBackdrop.classList.add('hidden');
}

function renderDrawer() {
  const report = selectedReport();
  if (!report) return;
  const days = ageDays(report.date);
  const risk = reportVulnerabilityRisk(report);
  els.drawerEyebrow.textContent = report.repo;
  els.drawerTitle.textContent = report.fileName;
  els.drawerHero.innerHTML = [
    heroStat('Score', `${formatScore(report.score)}/10`),
    heroStat('Grade', report.grade),
    heroStat('Vulnerability risk', risk.label),
    heroStat('Scan age', days == null ? 'Unknown' : `${days} days`)
  ].join('');
  els.drawerTabs.querySelectorAll('button').forEach((button) => button.classList.toggle('active', button.dataset.tab === state.activeTab));

  if (state.activeTab === 'overview') els.drawerContent.innerHTML = overviewHtml(report);
  if (state.activeTab === 'checks') els.drawerContent.innerHTML = checksHtml(report);
  if (state.activeTab === 'vulnerabilities') els.drawerContent.innerHTML = vulnerabilitiesHtml(report);
  if (state.activeTab === 'history') els.drawerContent.innerHTML = historyHtml(report);
  if (state.activeTab === 'raw') els.drawerContent.innerHTML = `<pre class="raw">${escapeHtml(rawJsonForDisplay(report.raw))}</pre>`;
  bindDrawerActions(report);
}

function overviewHtml(report) {
  const issueCards = report.issues.slice(0, 8).map((issue) => `
    <article class="issue-card">
      <div class="issue-card-head"><h3>${escapeHtml(issue.name)}</h3><span class="risk-pill ${escapeAttr(issue.risk)}">${escapeHtml(issue.risk)} · ${formatScore(issue.score)}/10</span></div>
      <p>${escapeHtml(issue.reason || 'No reason supplied by Scorecard.')}</p>
    </article>`).join('');
  return `
    <div class="action-row">
      ${report.repoUrl ? '<button class="button secondary" data-action="open-repo">Open repository</button>' : ''}
      <button class="button ghost" data-action="show-file">Show JSON file</button>
      ${report.identifiers.length ? '<button class="button ghost" data-action="enrich-report">Refresh vulnerability intelligence</button>' : ''}
    </div>
    <h3 class="section-title">Report details</h3>
    <div class="overview-grid">
      ${infoCard('Repository', report.repo)}
      ${infoCard('Last scanned', `${formatDateTime(report.date)} (${report.dateSource || 'report'})`)}
      ${infoCard('Commit', report.commit || 'Not provided')}
      ${infoCard('Scorecard version', report.scorecardVersion || 'Not provided')}
      ${infoCard('JSON file', report.filePath)}
      ${infoCard('Identifiers found', report.identifiers.join(', ') || 'None')}
    </div>
    <h3 class="section-title">Highest-impact weak checks</h3>
    <div class="issue-list">${issueCards || '<div class="info-card"><strong>No scored checks below 7.</strong></div>'}</div>`;
}

function checksHtml(report) {
  const checks = [...report.checks].sort((a, b) => nullSafeScore(a.score) - nullSafeScore(b.score));
  return `<div class="check-list">${checks.map((check) => `
    <article class="check-card">
      <div class="check-card-head"><h3>${escapeHtml(check.name)}</h3><span class="check-score ${scoreClass(check.score)}">${formatScore(check.score)}/10</span></div>
      <p>${escapeHtml(check.reason || 'No reason supplied.')}</p>
      ${check.details.length ? `<ul class="detail-lines">${check.details.slice(0, 20).map((detail) => `<li>${escapeHtml(detail)}</li>`).join('')}</ul>` : ''}
      ${check.documentation ? `<p><a href="#" data-external="${escapeAttr(check.documentation)}">Open remediation documentation</a></p>` : ''}
    </article>`).join('') || '<div class="info-card"><strong>No check details were found.</strong></div>'}</div>`;
}

function vulnerabilitiesHtml(report) {
  if (!report.identifiers.length) return '<div class="info-card"><strong>No CVE or GHSA identifiers were found in this report.</strong><span>The Scorecard Vulnerabilities check may still include a score without embedded identifiers.</span></div>';
  return `<div class="action-row"><button class="button secondary" data-action="enrich-report">Refresh this report</button></div><div class="vuln-list">${report.identifiers.map((id) => vulnerabilityCard(id)).join('')}</div>`;
}

function vulnerabilityCard(id) {
  const intel = intelForId(id);
  if (!intel) {
    return `<article class="vuln-card"><div class="vuln-card-head"><h3>${escapeHtml(id)}</h3><span class="risk-pill">Not checked</span></div><p>Run vulnerability checking to retrieve advisory, EPSS, affected-version, and CISA KEV context.</p></article>`;
  }
  const affectedRows = intel.affected?.slice(0, 12).map((item) => `<tr><td>${escapeHtml(item.ecosystem || '—')}</td><td>${escapeHtml(item.package || '—')}</td><td>${escapeHtml(item.vulnerableRange || '—')}</td><td>${escapeHtml(item.fixedVersion || 'No fix identified')}</td></tr>`).join('') || '';
  return `<article class="vuln-card ${escapeAttr(intel.priorityLabel.toLowerCase())}">
    <div class="vuln-card-head"><h3>${escapeHtml(id)} · ${escapeHtml(intel.title)}</h3><span class="risk-pill ${escapeAttr(intel.priorityLabel.toLowerCase())}">${escapeHtml(intel.priorityLabel)} ${intel.priority}/100</span></div>
    <p>${escapeHtml(truncate(intel.description || 'No advisory description available.', 900))}</p>
    ${intel.kev ? `<div class="kev-banner">Confirmed exploited · Added ${escapeHtml(intel.kev.dateAdded || 'unknown')} · Ransomware use: ${escapeHtml(intel.kev.knownRansomwareCampaignUse || 'Unknown')}</div>` : ''}
    <div class="vuln-meta">
      ${intel.cvss ? `<span class="mini-pill">CVSS ${escapeHtml(String(intel.cvss.score))}</span>` : ''}
      ${intel.epss ? `<span class="mini-pill">EPSS ${(intel.epss.probability * 100).toFixed(2)}%</span><span class="mini-pill">Percentile ${(intel.epss.percentile * 100).toFixed(1)}%</span>` : ''}
      <span class="mini-pill">${intel.fixedAvailable ? 'Fix available' : 'No fix identified'}</span>
      ${intel.aliases?.length > 1 ? `<span class="mini-pill">${escapeHtml(intel.aliases.join(' · '))}</span>` : ''}
    </div>
    ${intel.reasons?.length ? `<ul class="detail-lines">${intel.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>` : ''}
    ${affectedRows ? `<table class="affected-table"><thead><tr><th>Ecosystem</th><th>Package</th><th>Affected</th><th>Fix</th></tr></thead><tbody>${affectedRows}</tbody></table>` : ''}
    <div class="source-line">Sources: ${sourceMark('GitHub', intel.sources?.github)} · ${sourceMark('OSV', intel.sources?.osv)} · ${sourceMark('EPSS', intel.sources?.epss)} · ${sourceMark('CISA KEV', intel.sources?.cisaKev)} · Checked ${escapeHtml(formatRelativeTime(intel.checkedAt))}</div>
    ${intel.references?.length ? `<p><a href="#" data-external="${escapeAttr(intel.references[0])}">Open primary advisory</a></p>` : ''}
  </article>`;
}

function historyHtml(report) {
  const history = report.history || findHistory(report.repo);
  return `<div class="history-list">${history.map((item, index) => `
    <article class="history-item">
      <div><strong>${escapeHtml(formatDateTime(item.date))}</strong><span>${escapeHtml(item.fileName)}${item.commit ? ` · ${escapeHtml(item.commit.slice(0, 10))}` : ''}</span></div>
      <span class="history-score">${formatScore(item.score)}/10${index < history.length - 1 && Number.isFinite(item.score) && Number.isFinite(history[index + 1].score) ? ` (${signed(item.score - history[index + 1].score)})` : ''}</span>
    </article>`).join('')}</div>`;
}

function bindDrawerActions(report) {
  els.drawerContent.querySelector('[data-action="show-file"]')?.addEventListener('click', () => api.showInFolder(report.filePath));
  els.drawerContent.querySelector('[data-action="open-repo"]')?.addEventListener('click', () => api.openExternal(report.repoUrl));
  els.drawerContent.querySelectorAll('[data-action="enrich-report"]').forEach((button) => button.addEventListener('click', () => enrichReport(report)));
  els.drawerContent.querySelectorAll('[data-external]').forEach((link) => link.addEventListener('click', (event) => {
    event.preventDefault();
    api.openExternal(link.dataset.external).catch((error) => toast(error.message));
  }));
}

async function enrichReport(report) {
  if (!report.identifiers.length || state.enriching) return;
  state.enriching = true;
  try {
    const intelligence = await api.enrichVulnerabilities(report.identifiers);
    for (const item of intelligence.filter(Boolean)) state.intel.set(item.id, item);
    renderAll();
    renderDrawer();
    toast(`Updated ${intelligence.length} identifier${plural(intelligence.length)}.`);
  } catch (error) {
    toast(error.message || 'Vulnerability intelligence could not be updated.');
  } finally {
    state.enriching = false;
  }
}

function filterAndSort(reports) {
  const query = els.searchInput.value.trim().toLowerCase();
  const status = els.statusFilter.value;
  const output = reports.filter((report) => {
    const haystack = [report.repo, report.fileName, report.filePath, ...report.identifiers, ...report.checks.flatMap((check) => [check.name, check.reason])].join(' ').toLowerCase();
    if (query && !haystack.includes(query)) return false;
    const days = ageDays(report.date);
    if (status === 'critical' && reportPriority(report) < 80) return false;
    if (status === 'low-score' && !(report.score < 7)) return false;
    if (status === 'stale' && !(days > 270)) return false;
    if (status === 'expired' && !(days > 360)) return false;
    if (status === 'vulnerable' && !report.identifiers.length) return false;
    return true;
  });

  const sort = els.sortSelect.value;
  output.sort((a, b) => {
    if (sort === 'priority-desc') return reportPriority(b) - reportPriority(a) || nullSafeScore(a.score) - nullSafeScore(b.score);
    if (sort === 'score-asc') return nullSafeScore(a.score) - nullSafeScore(b.score);
    if (sort === 'score-desc') return scoreDescValue(b.score) - scoreDescValue(a.score);
    if (sort === 'date-asc') return dateValue(a.date) - dateValue(b.date);
    if (sort === 'date-desc') return dateValue(b.date) - dateValue(a.date);
    return a.repo.localeCompare(b.repo);
  });
  return output;
}

function latestByRepo(reports) {
  const groups = new Map();
  for (const report of reports) {
    const key = report.repo.toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(report);
  }
  return [...groups.values()].map((history) => {
    history.sort((a, b) => dateValue(b.date) - dateValue(a.date));
    const latest = history[0];
    const previous = history[1];
    return {
      ...latest,
      history,
      reportCount: history.length,
      previousScore: previous?.score ?? null,
      scoreDelta: Number.isFinite(latest.score) && Number.isFinite(previous?.score) ? Number((latest.score - previous.score).toFixed(2)) : null
    };
  });
}

function withHistoryMetadata(report) {
  const history = findHistory(report.repo);
  const index = history.findIndex((item) => item.id === report.id);
  const previous = history[index + 1];
  return {
    ...report,
    history,
    reportCount: history.length,
    previousScore: previous?.score ?? null,
    scoreDelta: Number.isFinite(report.score) && Number.isFinite(previous?.score) ? Number((report.score - previous.score).toFixed(2)) : null
  };
}

function findHistory(repo) {
  return state.allReports.filter((report) => report.repo.toLowerCase() === repo.toLowerCase()).sort((a, b) => dateValue(b.date) - dateValue(a.date));
}

function selectedReport() {
  const report = state.allReports.find((item) => item.id === state.selectedReportId);
  return report ? withHistoryMetadata(report) : null;
}

function reportPriority(report) {
  const vuln = report.identifiers.reduce((max, id) => Math.max(max, intelForId(id)?.priority || 0), 0);
  const check = report.issues[0]?.severityWeight ? Math.min(79, Math.round(report.issues[0].severityWeight * 2.1)) : 0;
  const stale = ageDays(report.date) > 360 ? 72 : ageDays(report.date) > 270 ? 45 : 0;
  return Math.max(vuln, check, stale);
}

function reportVulnerabilityRisk(report) {
  if (!report.identifiers.length) return { label: 'None found', priority: 0, className: 'low' };
  const enriched = report.identifiers.map(intelForId).filter(Boolean);
  if (!enriched.length) return { label: `${report.identifiers.length} unchecked`, priority: null, className: '' };
  const max = enriched.sort((a, b) => b.priority - a.priority)[0];
  return { label: `${max.priorityLabel} ${max.priority}/100`, priority: max.priority, className: max.priorityLabel.toLowerCase() };
}

function intelForId(id) {
  if (state.intel.has(id)) return state.intel.get(id);
  for (const value of state.intel.values()) {
    if (value.aliases?.includes(id)) return value;
  }
  return null;
}

function allIdentifiers() {
  return [...new Set(state.allReports.flatMap((report) => report.identifiers))];
}

async function exportCsv() {
  const reports = filterAndSort(state.settings.latestOnly ? latestByRepo(state.allReports) : state.allReports.map(withHistoryMetadata));
  const rows = [[
    'Repository', 'Score', 'Grade', 'Score delta', 'Biggest issue', 'Issue score', 'Vulnerability IDs', 'Contextual vulnerability risk', 'Last scanned', 'Age days', 'Report file'
  ]];
  for (const report of reports) {
    const risk = reportVulnerabilityRisk(report);
    rows.push([
      report.repo, report.score ?? '', report.grade, report.scoreDelta ?? '', report.issues[0]?.name || '', report.issues[0]?.score ?? '',
      report.identifiers.join(' '), risk.label, report.date || '', ageDays(report.date) ?? '', report.filePath
    ]);
  }
  const csv = rows.map((row) => row.map(csvCell).join(',')).join('\r\n');
  const filePath = await api.exportCsv(csv);
  if (filePath) toast(`Exported ${reports.length} row${plural(reports.length)}.`);
}

async function openSettings() {
  const settings = await api.getSettings();
  els.tokenStatus.textContent = settings.hasGitHubToken ? 'A GitHub token is saved.' : 'No GitHub token is saved; public rate limits apply.';
  els.githubToken.value = '';
  els.settingsDialog.showModal();
}

async function saveToken() {
  const token = els.githubToken.value.trim();
  if (!token) {
    toast('Enter a token, or use Remove to delete the saved token.');
    return;
  }
  try {
    await api.setGitHubToken(token);
    els.githubToken.value = '';
    els.tokenStatus.textContent = 'GitHub token saved securely.';
    toast('GitHub token saved.');
  } catch (error) {
    toast(error.message || 'Token could not be saved.');
  }
}

async function removeToken() {
  try {
    await api.setGitHubToken('');
    els.githubToken.value = '';
    els.tokenStatus.textContent = 'No GitHub token is saved; public rate limits apply.';
    toast('GitHub token removed.');
  } catch (error) {
    toast(error.message || 'Token could not be removed.');
  }
}

async function clearCache() {
  await api.clearIntelCache();
  state.intel.clear();
  els.intelFreshness.textContent = 'Vulnerability intelligence cache cleared';
  renderAll();
  if (state.selectedReportId) renderDrawer();
  toast('Cached vulnerability intelligence cleared.');
}

function setBusy(busy, text = '') {
  els.openButton.disabled = busy;
  els.welcomeOpenButton.disabled = busy;
  els.refreshButton.disabled = busy || !state.directory;
  if (text) els.scanStatus.textContent = text;
}

function toast(message) {
  els.toast.textContent = message;
  els.toast.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => els.toast.classList.remove('show'), 3200);
}

function summaryCard(label, value, subvalue, className) {
  return `<article class="summary-card ${className}"><span class="label">${escapeHtml(String(label))}</span><div class="value">${escapeHtml(String(value))}</div><div class="subvalue">${escapeHtml(String(subvalue))}</div></article>`;
}
function heroStat(label, value) { return `<div class="hero-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`; }
function infoCard(label, value) { return `<div class="info-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`; }
function riskPill(risk) { return `<span class="risk-pill ${escapeAttr(risk.className || '')}">${escapeHtml(risk.label)}</span>`; }
function sourceMark(label, enabled) { return `<span class="${enabled ? 'on' : 'off'}">${escapeHtml(label)} ${enabled ? '✓' : '—'}</span>`; }
function trendHtml(delta) {
  if (!Number.isFinite(delta)) return '<span class="trend flat">—</span>';
  if (delta > 0) return `<span class="trend up">↑ ${escapeHtml(Math.abs(delta).toFixed(1))}</span>`;
  if (delta < 0) return `<span class="trend down">↓ ${escapeHtml(Math.abs(delta).toFixed(1))}</span>`;
  return '<span class="trend flat">→ 0.0</span>';
}
function ageHtml(days) {
  if (days == null) return '<span class="age-tag">Unknown</span>';
  const className = days > 360 ? 'red' : days > 270 ? 'yellow' : 'fresh';
  return `<span class="age-tag ${className}">${days}d</span>`;
}
function scoreClass(score) { return !Number.isFinite(score) ? '' : score < 5 ? 'bad' : score < 8 ? 'mid' : 'good'; }
function formatScore(score) { return Number.isFinite(score) ? Number(score).toFixed(1) : '—'; }
function scoreDescriptor(score) { return score == null ? 'No numeric scores' : score >= 8 ? 'Strong aggregate posture' : score >= 6 ? 'Improvement needed' : 'Material control gaps'; }
function shortRepo(repo) { return repo.replace(/^(github|gitlab|bitbucket)\.com\//i, ''); }
function ageDays(value) { const time = dateValue(value); return time ? Math.max(0, Math.floor((Date.now() - time) / 86400000)) : null; }
function dateValue(value) { const time = value ? new Date(value).getTime() : 0; return Number.isFinite(time) ? time : 0; }
function formatDate(value) { return value ? new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(value)) : 'Unknown'; }
function formatDateTime(value) { return value ? new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(value)) : 'Unknown'; }
function formatRelativeTime(value) { const days = ageDays(value); if (days == null) return 'at an unknown time'; if (days === 0) return 'today'; if (days === 1) return 'yesterday'; return `${days} days ago`; }
function nullSafeScore(value) { return Number.isFinite(value) ? value : 999; }
function scoreDescValue(value) { return Number.isFinite(value) ? value : -999; }
function signed(value) { return `${value >= 0 ? '+' : ''}${Number(value).toFixed(1)}`; }
function plural(number) { return number === 1 ? '' : 's'; }
function truncate(value, length) { const text = String(value || ''); return text.length > length ? `${text.slice(0, length - 1)}…` : text; }
function csvCell(value) { const raw = String(value ?? ''); const text = /^[=+\-@]/.test(raw) ? `'${raw}` : raw; return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text; }
function rawJsonForDisplay(value) {
  const maxChars = 2 * 1024 * 1024;
  const serialized = JSON.stringify(value, null, 2) || '';
  if (serialized.length <= maxChars) return serialized;
  return `${serialized.slice(0, maxChars)}\n\n… output truncated (${serialized.length - maxChars} characters omitted)`;
}

function escapeHtml(value) { return String(value ?? '').replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[char]); }
function escapeAttr(value) { return escapeHtml(value).replaceAll("'", '&#39;'); }
function loadBoolean(key, fallback) { const value = localStorage.getItem(`scorecard-radar:${key}`); return value == null ? fallback : value === 'true'; }
function saveBoolean(key, value) { localStorage.setItem(`scorecard-radar:${key}`, String(Boolean(value))); }
