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
    const res = await api(server.baseUrl, 'GET', '/');
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'ok');
    assert.equal(res.json.service, 'Corecheck API');
    assert.ok(typeof res.json.timestamp === 'string');
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
});
