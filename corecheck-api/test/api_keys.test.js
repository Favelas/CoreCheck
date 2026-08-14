'use strict';

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApp } = require('../src/app');
const { InMemoryReportsStore } = require('../src/store/reports.store');
const { InMemoryApiKeyRepository } = require('../src/store/inMemoryApiKeys.store');
const { hashApiKey } = require('../src/store/apiKeys.repository');

const BOOTSTRAP = 'cc_bootstrap';
const ACCOUNT = 'tenant_default';

describe('Slice 2 — dynamic API keys', () => {
  /** @type {{ baseUrl: string, close: () => Promise<void>, keys: import('../src/store/inMemoryApiKeys.store').InMemoryApiKeyRepository }} */
  let ctx;

  before(async () => {
    const keys = new InMemoryApiKeyRepository();
    const app = createApp({
      repository: new InMemoryReportsStore(),
      apiKeyRepository: keys,
      disableRateLimit: true,
      apiKeyBindings: [{ key: BOOTSTRAP, accountId: ACCOUNT }]
    });
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    ctx = {
      baseUrl: `http://127.0.0.1:${port}`,
      keys,
      async close() {
        await new Promise((r) => server.close(r));
      }
    };
  });

  after(async () => {
    await ctx.close();
  });

  beforeEach(() => {
    ctx.keys.clear();
  });

  async function api(method, path, body, apiKey = BOOTSTRAP) {
    const headers = {
      Authorization: `Bearer ${apiKey}`,
      Accept: 'application/json'
    };
    let payload;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }
    const res = await fetch(`${ctx.baseUrl}${path}`, {
      method,
      headers,
      body: payload
    });
    const text = await res.text();
    const json = text ? JSON.parse(text) : null;
    return { status: res.status, json };
  }

  it('POST /api/admin/api-keys mint key (plaintext once) y hash no se reexpone', async () => {
    const created = await api('POST', '/api/admin/api-keys', {
      label: 'ci-runner'
    });
    assert.equal(created.status, 201);
    assert.ok(created.json.apiKey.startsWith('cc_live_'));
    assert.equal(created.json.accountId, ACCOUNT);
    assert.equal(created.json.label, 'ci-runner');
    assert.ok(created.json.id);

    const listed = await api('GET', '/api/admin/api-keys');
    assert.equal(listed.status, 200);
    assert.equal(listed.json.total, 1);
    assert.equal(listed.json.data[0].keyPrefix, created.json.apiKey.slice(0, 12));
    assert.equal(listed.json.data[0].apiKey, undefined);
    assert.equal(listed.json.data[0].keyHash, undefined);
  });

  it('key dinámica autentica POST /api/reports', async () => {
    const created = await api('POST', '/api/admin/api-keys', { label: 'upload' });
    const dynamicKey = created.json.apiKey;

    const report = await api(
      'POST',
      '/api/reports',
      { url: 'https://example.com', summary: 'from dynamic key' },
      dynamicKey
    );
    assert.equal(report.status, 201);
    assert.equal(report.json.accountId, ACCOUNT);
    assert.equal(report.json.url, 'https://example.com');
  });

  it('revoke invalida la key (401) y list muestra revokedAt', async () => {
    const created = await api('POST', '/api/admin/api-keys', {});
    const { id, apiKey } = created.json;

    const revoked = await api('DELETE', `/api/admin/api-keys/${id}`);
    assert.equal(revoked.status, 200);
    assert.equal(revoked.json.revoked, true);
    assert.ok(revoked.json.key.revokedAt);

    const denied = await api(
      'GET',
      '/api/reports',
      undefined,
      apiKey
    );
    assert.equal(denied.status, 401);
    assert.equal(denied.json.error, 'UNAUTHORIZED');
  });

  it('cross-tenant revoke → 404', async () => {
    const appB = createApp({
      repository: new InMemoryReportsStore(),
      apiKeyRepository: ctx.keys,
      disableRateLimit: true,
      apiKeyBindings: [
        { key: BOOTSTRAP, accountId: ACCOUNT },
        { key: 'cc_beta', accountId: 'tenant_beta' }
      ]
    });
    // Reuse same key repo: create key as default tenant
    const created = await api('POST', '/api/admin/api-keys', {});
    const id = created.json.id;

    const serverB = http.createServer(appB);
    await new Promise((resolve) => serverB.listen(0, '127.0.0.1', resolve));
    const portB = serverB.address().port;

    const res = await fetch(
      `http://127.0.0.1:${portB}/api/admin/api-keys/${id}`,
      {
        method: 'DELETE',
        headers: { Authorization: 'Bearer cc_beta' }
      }
    );
    assert.equal(res.status, 404);
    await new Promise((r) => serverB.close(r));
  });

  it('hashApiKey es determinista y no igual al secreto', () => {
    const raw = 'cc_live_abc';
    const h = hashApiKey(raw);
    assert.equal(h, hashApiKey(raw));
    assert.notEqual(h, raw);
    assert.equal(h.length, 64);
  });
});
