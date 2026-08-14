'use strict';

const STORAGE_KEY = 'corecheck_viewer_api_key';

const els = {
  apiKey: document.getElementById('apiKey'),
  btnConnect: document.getElementById('btnConnect'),
  btnClear: document.getElementById('btnClear'),
  authStatus: document.getElementById('authStatus'),
  workspace: document.getElementById('workspace'),
  btnRefresh: document.getElementById('btnRefresh'),
  listMeta: document.getElementById('listMeta'),
  reportList: document.getElementById('reportList'),
  detail: document.getElementById('detail'),
  detailTitle: document.getElementById('detailTitle'),
  detailBody: document.getElementById('detailBody'),
  btnVerify: document.getElementById('btnVerify'),
  verifyStatus: document.getElementById('verifyStatus')
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
  const res = await api('GET', '/api/reports');
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
}

function renderList(envelope) {
  const total = envelope?.total ?? 0;
  const data = Array.isArray(envelope?.data) ? envelope.data : [];
  els.listMeta.textContent =
    total === 0
      ? 'No reports yet (empty list is 200, not 404).'
      : `${total} report(s) in this tenant.`;

  els.reportList.replaceChildren();
  for (const report of data) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'row' + (report.id === selectedId ? ' is-active' : '');
    btn.innerHTML = `<span class="row-id">${escapeHtml(report.id)}</span>
      <span class="row-url">${escapeHtml(report.url || '(no url)')}</span>
      <span class="row-id">${escapeHtml(report.createdAt || '')}</span>`;
    btn.addEventListener('click', () => void openReport(report.id));
    li.appendChild(btn);
    els.reportList.appendChild(li);
  }
}

async function openReport(id) {
  selectedId = id;
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
    btn.classList.toggle('is-active', btn.querySelector('.row-id')?.textContent === id);
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

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

els.btnConnect.addEventListener('click', () => void connect());
els.btnRefresh.addEventListener('click', () => void connect());
els.btnVerify.addEventListener('click', () => void verifySelected());
els.btnClear.addEventListener('click', () => {
  sessionStorage.removeItem(STORAGE_KEY);
  els.apiKey.value = '';
  els.workspace.hidden = true;
  els.detail.hidden = true;
  selectedId = null;
  setStatus(els.authStatus, 'Cleared session key.');
});
els.apiKey.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    void connect();
  }
});

const saved = sessionStorage.getItem(STORAGE_KEY);
if (saved) {
  els.apiKey.value = saved;
  void connect();
}
