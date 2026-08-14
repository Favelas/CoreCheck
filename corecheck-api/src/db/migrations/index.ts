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
  },
  {
    id: '002_api_keys.sql',
    sql: `
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY,
  account_id VARCHAR(128) NOT NULL,
  key_hash VARCHAR(64) NOT NULL,
  key_prefix VARCHAR(16) NOT NULL,
  label VARCHAR(256),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_key_hash ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_account_id ON api_keys (account_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active_hash
  ON api_keys (key_hash)
  WHERE revoked_at IS NULL;
`
  }
];
