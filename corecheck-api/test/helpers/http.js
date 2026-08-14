'use strict';

const http = require('http');
const { createApp } = require('../../src/app');
const { reportsStore } = require('../../src/store/reports.store');

/** Key de prueba — inyectada vía createApp (no depende del env del developer). */
const TEST_API_KEY = 'cc_test_key';

function startTestServer() {
  const app = createApp({ apiKeys: [TEST_API_KEY] });
  const server = http.createServer(app);

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        apiKey: TEST_API_KEY,
        async close() {
          await new Promise((r) => server.close(r));
        }
      });
    });
  });
}

/**
 * @param {object} [options]
 * @param {boolean} [options.auth=true] — si false, no envía API key (tests 401)
 * @param {string} [options.apiKey] — override de key
 */
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
  startTestServer,
  api,
  resetStore: () => reportsStore.clear()
};
