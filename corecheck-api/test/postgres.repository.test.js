'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const {
  PostgresReportsRepository
} = require('../src/repositories/PostgresReportsRepository');
const { runMigrations } = require('../src/db/migrate');
const { resolvePoolConfig } = require('../src/db/pool');

/**
 * Pool mock in-memory — sin Postgres real durante npm test.
 */
function createMockPool() {
  /** @type {Map<string, any>} */
  const byId = new Map();
  /** @type {Set<string>} */
  const migrations = new Set();

  const pool = {
    async query(text, params = []) {
      const sql = String(text).replace(/\s+/g, ' ').trim();

      if (sql.startsWith('CREATE TABLE IF NOT EXISTS schema_migrations')) {
        return { rowCount: 0, rows: [] };
      }
      if (sql.includes('FROM schema_migrations WHERE id')) {
        const id = params[0];
        if (migrations.has(id)) {
          return { rowCount: 1, rows: [{ '?column?': 1 }] };
        }
        return { rowCount: 0, rows: [] };
      }
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') {
        return { rowCount: 0, rows: [] };
      }
      if (sql.includes('INSERT INTO schema_migrations')) {
        migrations.add(params[0]);
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes('CREATE TABLE IF NOT EXISTS reports')) {
        return { rowCount: 0, rows: [] };
      }
      if (sql.includes('CREATE INDEX IF NOT EXISTS')) {
        return { rowCount: 0, rows: [] };
      }

      if (sql.startsWith('INSERT INTO reports')) {
        const [
          id,
          accountId,
          url,
          contentHash,
          hmacSignature,
          integrityAlgorithm,
          payloadJson,
          createdAt
        ] = params;
        const payload = JSON.parse(payloadJson);
        byId.set(id, {
          id,
          account_id: accountId,
          url,
          content_hash: contentHash,
          hmac_signature: hmacSignature,
          integrity_algorithm: integrityAlgorithm,
          payload,
          created_at: createdAt
        });
        return { rowCount: 1, rows: [] };
      }

      if (sql.includes('FROM reports') && sql.includes('ORDER BY created_at DESC')) {
        const accountId = params[0];
        const rows = [...byId.values()]
          .filter((r) => r.account_id === accountId)
          .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
        return { rowCount: rows.length, rows };
      }

      if (
        sql.includes('FROM reports') &&
        sql.includes('WHERE id = $1 AND account_id = $2')
      ) {
        const [id, accountId] = params;
        const row = byId.get(id);
        if (!row || row.account_id !== accountId) {
          return { rowCount: 0, rows: [] };
        }
        return { rowCount: 1, rows: [row] };
      }

      if (sql.startsWith('DELETE FROM reports WHERE created_at')) {
        const cutoff = params[0];
        let removed = 0;
        for (const [id, row] of [...byId.entries()]) {
          if (String(row.created_at) < String(cutoff)) {
            byId.delete(id);
            removed += 1;
          }
        }
        return { rowCount: removed, rows: [] };
      }

      if (sql.startsWith('DELETE FROM reports')) {
        byId.clear();
        return { rowCount: 0, rows: [] };
      }

      throw new Error(`Mock pool: query no manejada: ${sql}`);
    },
    async connect() {
      return {
        query: (...args) => pool.query(...args),
        release() {}
      };
    },
    async end() {}
  };

  return pool;
}

describe('PostgresReportsRepository (Phase 3.2 mocked)', () => {
  /** @type {ReturnType<typeof createMockPool>} */
  let pool;
  /** @type {InstanceType<typeof PostgresReportsRepository>} */
  let repo;

  beforeEach(async () => {
    pool = createMockPool();
    repo = new PostgresReportsRepository(pool);
    await repo.clear();
  });

  it('resolvePoolConfig usa DATABASE_URL o variables discretas', () => {
    const fromUrl = resolvePoolConfig({
      DATABASE_URL: 'postgres://u:p@localhost:5432/db'
    });
    assert.equal(fromUrl.connectionString, 'postgres://u:p@localhost:5432/db');

    const fromParts = resolvePoolConfig({
      POSTGRES_HOST: 'db.local',
      POSTGRES_PORT: '5433',
      POSTGRES_DB: 'corecheck_api',
      POSTGRES_USER: 'corecheck',
      POSTGRES_PASSWORD: 'secret'
    });
    assert.equal(fromParts.host, 'db.local');
    assert.equal(fromParts.port, 5433);
    assert.equal(fromParts.database, 'corecheck_api');
  });

  it('runMigrations es idempotente sobre el mock', async () => {
    const applied1 = await runMigrations(pool);
    assert.ok(applied1.includes('001_reports.sql'));
    const applied2 = await runMigrations(pool);
    assert.deepEqual(applied2, []);
  });

  it('saveReport + getAllReports + getReportById respetan accountId', async () => {
    const saved = await repo.saveReport(
      { url: 'https://example.com', summary: 'pg' },
      'tenant_alpha'
    );

    assert.equal(saved.accountId, 'tenant_alpha');
    assert.ok(saved.contentHash);
    assert.equal(saved.integrityAlgorithm, 'SHA-256');

    const listAlpha = await repo.getAllReports('tenant_alpha');
    assert.equal(listAlpha.total, 1);
    assert.equal(listAlpha.data[0].id, saved.id);

    const listBeta = await repo.getAllReports('tenant_beta');
    assert.equal(listBeta.total, 0);

    assert.equal(await repo.getReportById(saved.id, 'tenant_beta'), undefined);
    const found = await repo.getReportById(saved.id, 'tenant_alpha');
    assert.ok(found);
    assert.equal(found.url, 'https://example.com');
  });
});
