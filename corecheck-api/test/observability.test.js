'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApp } = require('../src/app');
const { InMemoryReportsStore } = require('../src/store/reports.store');
const { setReportsRepository } = require('../src/store/repository.context');
const { runRetentionPurge } = require('../src/ops/retention');

describe('Phase 4 observability & retention', () => {
  it('rate limit devuelve 429 tras exceder max', async () => {
    const store = new InMemoryReportsStore();
    const app = createApp({
      repository: store,
      apiKeyBindings: [{ key: 'rl_key', accountId: 'tenant_rl' }],
      rateLimit: { windowMs: 60_000, max: 2 }
    });

    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    const base = `http://127.0.0.1:${port}`;

    const hit = async () => {
      const res = await fetch(`${base}/api/reports`, {
        headers: { Authorization: 'Bearer rl_key' }
      });
      return res.status;
    };

    assert.equal(await hit(), 200);
    assert.equal(await hit(), 200);
    assert.equal(await hit(), 429);

    await new Promise((r) => server.close(r));
  });

  it('retention purge elimina reportes antiguos', async () => {
    const store = new InMemoryReportsStore();
    setReportsRepository(store);

    const oldIso = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    await store.saveReport({ url: 'https://old.example.com' }, 'tenant_a');
    // Forzar createdAt antiguo vía tamper hook + re-seal skip: replace whole object
    const list = await store.getAllReports('tenant_a');
    const current = list.data[0];
    store.__dangerouslyReplaceForTests({
      ...current,
      createdAt: oldIso
    });

    await store.saveReport({ url: 'https://new.example.com' }, 'tenant_a');

    const cutoff = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
    const removed = await store.purgeOlderThan(cutoff);
    assert.equal(removed, 1);

    const after = await store.getAllReports('tenant_a');
    assert.equal(after.total, 1);
    assert.equal(after.data[0].url, 'https://new.example.com');

    // runRetentionPurge con days=0 no borra
    assert.equal(await runRetentionPurge(0), 0);
  });
});
