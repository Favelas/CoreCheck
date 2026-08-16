'use strict';

const STORAGE_KEY = 'corecheck_viewer_api_key';

const els = {
  apiKey: document.getElementById('apiKey'),
  btnConnect: document.getElementById('btnConnect'),
  btnClear: document.getElementById('btnClear'),
  authStatus: document.getElementById('authStatus'),
  workspace: document.getElementById('workspace'),
  btnRefresh: document.getElementById('btnRefresh'),
  btnApplyFilters: document.getElementById('btnApplyFilters'),
  filterUrl: document.getElementById('filterUrl'),
  filterGate: document.getElementById('filterGate'),
  filterQ: document.getElementById('filterQ'),
  listMeta: document.getElementById('listMeta'),
  reportList: document.getElementById('reportList'),
  detail: document.getElementById('detail'),
  detailTitle: document.getElementById('detailTitle'),
  detailBody: document.getElementById('detailBody'),
  btnVerify: document.getElementById('btnVerify'),
  verifyStatus: document.getElementById('verifyStatus'),
  trendStats: document.getElementById('trendStats'),
  statRuns: document.getElementById('statRuns'),
  statAvg: document.getElementById('statAvg'),
  statDelta: document.getElementById('statDelta'),
  statFailRate: document.getElementById('statFailRate'),
  sparkWrap: document.getElementById('sparkWrap'),
  sparkBars: document.getElementById('sparkBars'),
  btnDiff: document.getElementById('btnDiff'),
  diffPanel: document.getElementById('diffPanel'),
  diffSummary: document.getElementById('diffSummary'),
  diffBody: document.getElementById('diffBody'),
  btnCloseDiff: document.getElementById('btnCloseDiff')
};

/** @type {string | null} */
let selectedId = null;

function setStatus(el, message, kind) {
  el.textContent = message;
  el.classList.remove('is-error', 'is-ok');
  if (kind) {
    el.classList.add(kind);
  }
}

function getApiKey() {
  return (els.apiKey.value || '').trim();
}

function buildQuery(extra) {
  const params = new URLSearchParams();
  const url = (els.filterUrl.value || '').trim();
  const gate = els.filterGate.value;
  const q = (els.filterQ.value || '').trim();
  if (url) params.set('url', url);
  if (gate) params.set('gateFailed', gate);
  if (q) params.set('q', q);
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      if (v !== undefined && v !== null && String(v) !== '') {
        params.set(k, String(v));
      }
    }
  }
  const s = params.toString();
  return s ? `?${s}` : '';
}

async function api(method, path, body) {
  const key = getApiKey();
  const headers = {
    Accept: 'application/json',
    Authorization: `Bearer ${key}`
  };
  /** @type {RequestInit} */
  const init = { method, headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { error: 'PARSE_ERROR', message: text.slice(0, 200) };
  }
  return { status: res.status, json };
}

async function connect() {
  const key = getApiKey();
  if (!key) {
    setStatus(els.authStatus, 'Enter an API key bound to a tenant.', 'is-error');
    return;
  }

  setStatus(els.authStatus, 'Connecting…');
  const res = await api('GET', `/api/reports${buildQuery()}`);
  if (res.status === 401 || res.status === 503) {
    sessionStorage.removeItem(STORAGE_KEY);
    els.workspace.hidden = true;
    setStatus(
      els.authStatus,
      res.json?.message || `Auth failed (${res.status})`,
      'is-error'
    );
    return;
  }
  if (res.status !== 200) {
    setStatus(
      els.authStatus,
      res.json?.message || `Unexpected ${res.status}`,
      'is-error'
    );
    return;
  }

  sessionStorage.setItem(STORAGE_KEY, key);
  els.workspace.hidden = false;
  setStatus(els.authStatus, 'Connected — tenant scope active.', 'is-ok');
  renderList(res.json);
  await loadTrends();

  const hashId = location.hash.replace(/^#/, '');
  if (hashId) {
    void openReport(hashId);
  }
}

async function loadTrends() {
  const url = (els.filterUrl.value || '').trim();
  const qs = url ? `?url=${encodeURIComponent(url)}` : '';
  const res = await api('GET', `/api/reports/insights/trends${qs}`);
  if (res.status !== 200) {
    els.trendStats.hidden = true;
    els.sparkWrap.hidden = true;
    return;
  }

  const t = res.json;
  els.trendStats.hidden = false;
  els.statRuns.textContent = String(t.totalRuns ?? 0);
  els.statAvg.textContent =
    t.avgScore === null || t.avgScore === undefined ? '—' : String(t.avgScore);
  els.statFailRate.textContent =
    typeof t.gateFailRate === 'number'
      ? `${Math.round(t.gateFailRate * 100)}%`
      : '—';

  const deltaEl = els.statDelta;
  deltaEl.classList.remove('is-up', 'is-down');
  if (t.scoreDelta === null || t.scoreDelta === undefined) {
    deltaEl.textContent = '—';
  } else {
    const sign = t.scoreDelta > 0 ? '+' : '';
    deltaEl.textContent = `${sign}${t.scoreDelta}`;
    if (t.scoreDelta > 0) deltaEl.classList.add('is-up');
    if (t.scoreDelta < 0) deltaEl.classList.add('is-down');
  }

  const series = Array.isArray(t.series) ? t.series : [];
  const scores = series
    .map((p) => p.digitalQualityScore)
    .filter((n) => typeof n === 'number');
  if (scores.length === 0) {
    els.sparkWrap.hidden = true;
    return;
  }
  els.sparkWrap.hidden = false;
  const max = Math.max(...scores, 1);
  els.sparkBars.replaceChildren();
  for (const score of scores) {
    const bar = document.createElement('span');
    bar.style.height = `${Math.max(8, Math.round((score / max) * 100))}%`;
    bar.title = String(score);
    els.sparkBars.appendChild(bar);
  }
}

function renderList(envelope) {
  const total = envelope?.total ?? 0;
  const data = Array.isArray(envelope?.data) ? envelope.data : [];
  els.listMeta.textContent =
    total === 0
      ? 'No reports match filters (empty list is 200, not 404).'
      : `${total} report(s)`;

  els.reportList.replaceChildren();
  for (const report of data) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'row' + (report.id === selectedId ? ' is-active' : '');
    const gate =
      report.gateFailed === true
        ? '<span class="badge fail">GATE FAIL</span>'
        : report.gateFailed === false
          ? '<span class="badge pass">GATE PASS</span>'
          : '';
    const score =
      typeof report.digitalQualityScore === 'number'
        ? `<span class="badge">score ${report.digitalQualityScore}</span>`
        : '';
    btn.innerHTML = `<span class="row-id">${escapeHtml(report.id)}</span>
      <span class="row-url">${escapeHtml(report.url || '(no url)')}</span>
      <span class="row-id">${escapeHtml(report.createdAt || '')}</span>
      <span class="row-badges">${gate}${score}</span>`;
    btn.addEventListener('click', () => void openReport(report.id));
    li.appendChild(btn);
    els.reportList.appendChild(li);
  }
}

async function openReport(id) {
  selectedId = id;
  location.hash = id;
  setStatus(els.verifyStatus, '');
  const res = await api('GET', `/api/reports/${encodeURIComponent(id)}`);
  if (res.status !== 200) {
    els.detail.hidden = false;
    els.detailTitle.textContent = 'Unavailable';
    els.detailBody.textContent = JSON.stringify(res.json, null, 2);
    return;
  }
  els.detail.hidden = false;
  els.detailTitle.textContent = res.json.url || id;
  els.detailBody.textContent = JSON.stringify(res.json, null, 2);
  for (const btn of els.reportList.querySelectorAll('button.row')) {
    const first = btn.querySelector('.row-id');
    btn.classList.toggle('is-active', first?.textContent === id);
  }
}

async function verifySelected() {
  if (!selectedId) {
    setStatus(els.verifyStatus, 'Select a report first.', 'is-error');
    return;
  }
  const res = await api(
    'POST',
    `/api/reports/${encodeURIComponent(selectedId)}/verify`
  );
  if (res.status !== 200) {
    setStatus(
      els.verifyStatus,
      res.json?.message || `Verify failed (${res.status})`,
      'is-error'
    );
    return;
  }
  const ok = res.json?.valid === true;
  setStatus(
    els.verifyStatus,
    res.json?.message || (ok ? 'Integrity OK' : 'Integrity failed'),
    ok ? 'is-ok' : 'is-error'
  );
}

async function runDiff() {
  const url = (els.filterUrl.value || '').trim();
  const qs = url ? `?url=${encodeURIComponent(url)}` : '';
  const res = await api('GET', `/api/reports/insights/diff${qs}`);
  els.diffPanel.hidden = false;
  if (res.status !== 200) {
    els.diffSummary.textContent = res.json?.message || `Diff failed (${res.status})`;
    els.diffBody.textContent = JSON.stringify(res.json, null, 2);
    return;
  }
  const d = res.json;
  els.diffSummary.textContent = [
    d.regression ? 'REGRESSION' : 'OK',
    `scoreΔ=${d.scoreDelta ?? '—'}`,
    `findingsΔ=${d.findingsCountDelta}`,
    `added=${d.added?.length ?? 0}`,
    `removed=${d.removed?.length ?? 0}`,
    `${d.baseId.slice(0, 8)}… → ${d.targetId.slice(0, 8)}…`
  ].join(' · ');
  els.diffBody.textContent = JSON.stringify(d, null, 2);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

els.btnConnect.addEventListener('click', () => void connect());
els.btnRefresh.addEventListener('click', () => void connect());
els.btnApplyFilters.addEventListener('click', () => void connect());
els.btnVerify.addEventListener('click', () => void verifySelected());
els.btnDiff.addEventListener('click', () => void runDiff());
els.btnCloseDiff.addEventListener('click', () => {
  els.diffPanel.hidden = true;
});
els.btnClear.addEventListener('click', () => {
  sessionStorage.removeItem(STORAGE_KEY);
  els.apiKey.value = '';
  els.workspace.hidden = true;
  els.detail.hidden = true;
  els.diffPanel.hidden = true;
  selectedId = null;
  setStatus(els.authStatus, 'Cleared session key.');
});
els.apiKey.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    void connect();
  }
});
for (const input of [els.filterUrl, els.filterQ]) {
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      void connect();
    }
  });
}

const saved = sessionStorage.getItem(STORAGE_KEY);
if (saved) {
  els.apiKey.value = saved;
  void connect();
}
