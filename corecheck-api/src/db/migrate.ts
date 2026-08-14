import type { Pool } from 'pg';
import { SQL_MIGRATIONS } from './migrations/index';

/**
 * Aplica migraciones SQL idempotentes registradas en schema_migrations.
 */
export async function runMigrations(pool: Pool): Promise<string[]> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const applied: string[] = [];

  for (const migration of SQL_MIGRATIONS) {
    const existing = await pool.query(
      'SELECT 1 FROM schema_migrations WHERE id = $1',
      [migration.id]
    );
    if ((existing.rowCount ?? 0) > 0) {
      continue;
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(migration.sql);
      await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [
        migration.id
      ]);
      await client.query('COMMIT');
      applied.push(migration.id);
      console.log(`[migrate] applied ${migration.id}`);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  return applied;
}
