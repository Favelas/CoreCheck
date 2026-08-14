'use strict';

const http = require('http');
const { createApp } = require('../../src/app');
const { reportsStore } = require('../../src/store/reports.store');

/**
 * Cliente HTTP mínimo contra un puerto efímero.
 * Evita dependencias extra (supertest) en Fase B.5.
 */
function startTestServer() {
  const app = createApp();
  const server = http.createServer(app);

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        async close() {
          await new Promise((r) => server.close(r));
        }
      });
    });
  });
}

async function api(baseUrl, method, path, body) {
  const headers = {};
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
  startTestServer,
  api,
  resetStore: () => reportsStore.clear()
};
