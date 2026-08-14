'use strict';

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { startTestServer, api, resetStore } = require('./helpers/http');

describe('CoreCheck API — contratos HTTP (Fase B.5)', () => {
  /** @type {{ baseUrl: string, close: () => Promise<void> }} */
  let server;

  before(async () => {
    server = await startTestServer();
  });

  after(async () => {
    await server.close();
  });

  beforeEach(() => {
    resetStore();
  });

  it('GET / → 200 health JSON', async () => {
    const res = await api(server.baseUrl, 'GET', '/', undefined, { auth: false });
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'ok');
    assert.equal(res.json.service, 'Corecheck API');
    assert.ok(typeof res.json.timestamp === 'string');
  });

  it('GET /api/reports sin API key → 401 UNAUTHORIZED', async () => {
    const res = await api(server.baseUrl, 'GET', '/api/reports', undefined, {
      auth: false
    });
    assert.equal(res.status, 401);
    assert.equal(res.json.error, 'UNAUTHORIZED');
  });

  it('GET /api/reports con API key inválida → 401', async () => {
    const res = await api(server.baseUrl, 'GET', '/api/reports', undefined, {
      apiKey: 'wrong-key'
    });
    assert.equal(res.status, 401);
    assert.equal(res.json.error, 'UNAUTHORIZED');
  });

  it('GET /api/reports → 200 envelope vacío', async () => {
    const res = await api(server.baseUrl, 'GET', '/api/reports');
    assert.equal(res.status, 200);
    assert.equal(res.json.total, 0);
    assert.deepEqual(res.json.data, []);
  });

  it('POST /api/reports → 201 con id y createdAt del servidor', async () => {
    const res = await api(server.baseUrl, 'POST', '/api/reports', {
      url: 'https://example.com',
      failOn: 'HIGH'
    });

    assert.equal(res.status, 201);
    assert.equal(res.json.url, 'https://example.com');
    assert.ok(res.json.id);
    assert.ok(res.json.createdAt);
    assert.equal(res.json.accountId, 'tenant_default');
  });

  it('POST ignora id/createdAt del cliente', async () => {
    const res = await api(server.baseUrl, 'POST', '/api/reports', {
      url: 'https://example.com',
      id: 'client-forged-id',
      createdAt: '2000-01-01T00:00:00.000Z'
    });

    assert.equal(res.status, 201);
    assert.notEqual(res.json.id, 'client-forged-id');
    assert.notEqual(res.json.createdAt, '2000-01-01T00:00:00.000Z');
  });

  it('POST {} → 400 BAD_REQUEST', async () => {
    const res = await api(server.baseUrl, 'POST', '/api/reports', {});
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'BAD_REQUEST');
    assert.ok(res.json.message);
  });

  it('POST sin url → 400 BAD_REQUEST', async () => {
    const res = await api(server.baseUrl, 'POST', '/api/reports', {
      failOn: 'HIGH',
      findingsCount: 1
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'BAD_REQUEST');
    assert.match(String(res.json.message), /url/i);
  });

  it('POST con apiKey → 201 y secreto no se persiste ni se reexpone (SEC-API-01)', async () => {
    const created = await api(server.baseUrl, 'POST', '/api/reports', {
      url: 'https://example.com',
      apiKey: 'secret123',
      authorization: 'Bearer sk-live-test',
      password: 'p@ss',
      token: 'tok',
      secret: 'sec',
      cookie: 'session=abc',
      summary: 'safe-field'
    });

    assert.equal(created.status, 201);
    assert.equal(created.json.url, 'https://example.com');
    assert.equal(created.json.summary, 'safe-field');
    assert.equal(created.json.apiKey, undefined);
    assert.equal(created.json.authorization, undefined);
    assert.equal(created.json.password, undefined);
    assert.equal(created.json.token, undefined);
    assert.equal(created.json.secret, undefined);
    assert.equal(created.json.cookie, undefined);
    assert.equal(Object.hasOwn(created.json, 'apiKey'), false);

    const byId = await api(
      server.baseUrl,
      'GET',
      `/api/reports/${created.json.id}`
    );
    assert.equal(byId.status, 200);
    assert.equal(byId.json.apiKey, undefined);
    assert.equal(Object.hasOwn(byId.json, 'apiKey'), false);

    const list = await api(server.baseUrl, 'GET', '/api/reports');
    assert.equal(list.status, 200);
    const row = list.json.data.find((r) => r.id === created.json.id);
    assert.ok(row);
    assert.equal(row.apiKey, undefined);
    assert.equal(Object.hasOwn(row, 'apiKey'), false);
  });

  it('GET /api/reports/:id → 200 happy path', async () => {
    const created = await api(server.baseUrl, 'POST', '/api/reports', {
      url: 'https://example.com'
    });
    const res = await api(
      server.baseUrl,
      'GET',
      `/api/reports/${created.json.id}`
    );

    assert.equal(res.status, 200);
    assert.equal(res.json.id, created.json.id);
    assert.equal(res.json.url, 'https://example.com');
  });

  it('GET /api/reports/:id inexistente → 404 JSON', async () => {
    const res = await api(
      server.baseUrl,
      'GET',
      '/api/reports/00000000-0000-0000-0000-000000000000'
    );
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'NOT_FOUND');
    assert.match(res.text, /\{/); // JSON, no HTML
  });

  it('GET /nope → 404 JSON (ruta desconocida)', async () => {
    const res = await api(server.baseUrl, 'GET', '/nope');
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'NOT_FOUND');
    assert.equal(res.headers.get('content-type')?.includes('json'), true);
  });

  it('Multi-tenant: Beta no ve ni lee reporte de Alpha (404, lista vacía de R1)', async () => {
    const {
      TENANT_ALPHA_KEY,
      TENANT_BETA_KEY,
      TENANT_ALPHA_ID
    } = require('./helpers/http');

    const created = await api(
      server.baseUrl,
      'POST',
      '/api/reports',
      { url: 'https://alpha.example.com', summary: 'R1-alpha' },
      { apiKey: TENANT_ALPHA_KEY }
    );
    assert.equal(created.status, 201);
    assert.equal(created.json.accountId, TENANT_ALPHA_ID);
    const reportId = created.json.id;

    const crossGet = await api(
      server.baseUrl,
      'GET',
      `/api/reports/${reportId}`,
      undefined,
      { apiKey: TENANT_BETA_KEY }
    );
    assert.equal(crossGet.status, 404);
    assert.equal(crossGet.json.error, 'NOT_FOUND');

    const betaList = await api(
      server.baseUrl,
      'GET',
      '/api/reports',
      undefined,
      { apiKey: TENANT_BETA_KEY }
    );
    assert.equal(betaList.status, 200);
    assert.equal(betaList.json.total, 0);
    assert.equal(
      betaList.json.data.some((r) => r.id === reportId),
      false
    );

    const alphaGet = await api(
      server.baseUrl,
      'GET',
      `/api/reports/${reportId}`,
      undefined,
      { apiKey: TENANT_ALPHA_KEY }
    );
    assert.equal(alphaGet.status, 200);
    assert.equal(alphaGet.json.id, reportId);
    assert.equal(alphaGet.json.accountId, TENANT_ALPHA_ID);

    const forged = await api(
      server.baseUrl,
      'POST',
      '/api/reports',
      {
        url: 'https://beta.example.com',
        accountId: TENANT_ALPHA_ID,
        summary: 'forged-tenant'
      },
      { apiKey: TENANT_BETA_KEY }
    );
    assert.equal(forged.status, 201);
    assert.equal(forged.json.accountId, 'tenant_beta');
    assert.notEqual(forged.json.accountId, TENANT_ALPHA_ID);
  });

  it('POST create sella contentHash SHA-256 y verify OK', async () => {
    const created = await api(server.baseUrl, 'POST', '/api/reports', {
      url: 'https://example.com',
      summary: 'integrity'
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.integrityAlgorithm, 'SHA-256');
    assert.equal(typeof created.json.contentHash, 'string');
    assert.equal(created.json.contentHash.length, 64);
    assert.equal(created.json.hmacSignature, undefined);

    const verified = await api(
      server.baseUrl,
      'POST',
      `/api/reports/${created.json.id}/verify`
    );
    assert.equal(verified.status, 200);
    assert.equal(verified.json.valid, true);
    assert.equal(verified.json.hashMatches, true);
  });

  it('verify detecta tampering at-rest (contentHash mismatch)', async () => {
    const created = await api(server.baseUrl, 'POST', '/api/reports', {
      url: 'https://example.com',
      summary: 'before-tamper'
    });
    assert.equal(created.status, 201);

    const { memoryStore } = require('./helpers/http');
    memoryStore.__dangerouslyReplaceForTests({
      ...created.json,
      summary: 'tampered-after-seal'
    });

    const verified = await api(
      server.baseUrl,
      'POST',
      `/api/reports/${created.json.id}/verify`
    );
    assert.equal(verified.status, 200);
    assert.equal(verified.json.valid, false);
    assert.equal(verified.json.hashMatches, false);
  });
});
