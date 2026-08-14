'use strict';

const http = require('http');
const { createApp } = require('../../src/app');
const { InMemoryReportsStore } = require('../../src/store/reports.store');

const TEST_API_KEY = 'cc_test_key';
const TEST_ACCOUNT_ID = 'tenant_default';

const TENANT_ALPHA_KEY = 'cc_key_alpha';
const TENANT_BETA_KEY = 'cc_key_beta';
const TENANT_ALPHA_ID = 'tenant_alpha';
const TENANT_BETA_ID = 'tenant_beta';

/** Un store por suite — createApp lo registra vía DI. */
const memoryStore = new InMemoryReportsStore();

function startTestServer(options = {}) {
  const repository = options.repository ?? memoryStore;
  const app =
    options.app ??
    createApp({
      repository,
      apiKeyBindings: [
        { key: TEST_API_KEY, accountId: TEST_ACCOUNT_ID },
        { key: TENANT_ALPHA_KEY, accountId: TENANT_ALPHA_ID },
        { key: TENANT_BETA_KEY, accountId: TENANT_BETA_ID }
      ]
    });
  const server = http.createServer(app);

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        apiKey: TEST_API_KEY,
        repository,
        async close() {
          await new Promise((r) => server.close(r));
        }
      });
    });
  });
}

async function api(baseUrl, method, path, body, options = {}) {
  const auth = options.auth !== false;
  const apiKey = options.apiKey ?? TEST_API_KEY;
  const headers = {};

  if (auth) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }

  let payload;
  if (body !== undefined) {
    payload = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload);
  }

  const res = await fetch(`${baseUrl}${path}`, { method, headers, body: payload });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return { status: res.status, json, text, headers: res.headers };
}

module.exports = {
  TEST_API_KEY,
  TEST_ACCOUNT_ID,
  TENANT_ALPHA_KEY,
  TENANT_BETA_KEY,
  TENANT_ALPHA_ID,
  TENANT_BETA_ID,
  memoryStore,
  startTestServer,
  api,
  resetStore: () => memoryStore.clear()
};
