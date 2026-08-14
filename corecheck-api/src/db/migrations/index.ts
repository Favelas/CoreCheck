export interface SqlMigration {
  readonly id: string;
  readonly sql: string;
}

/**
 * Migraciones versionadas (Fase 3.2).
 * Definidas en TS para que `tsc` las emita a dist sin paso de copy.
 */
export const SQL_MIGRATIONS: readonly SqlMigration[] = [
  {
    id: '001_reports.sql',
    sql: `
CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY,
  account_id VARCHAR(128) NOT NULL,
  url TEXT NOT NULL,
  content_hash VARCHAR(64) NOT NULL,
  hmac_signature VARCHAR(128),
  integrity_algorithm VARCHAR(32) NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_account_id ON reports (account_id);
CREATE INDEX IF NOT EXISTS idx_reports_account_created_at ON reports (account_id, created_at DESC);
`
  }
];
