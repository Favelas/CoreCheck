import type { Pool } from 'pg';
import {
  generateApiKeySecret,
  hashApiKey,
  newApiKeyRecord,
  toPublicApiKey,
  type ApiKeyLookup,
  type ApiKeyPublic,
  type ApiKeyRecord,
  type ApiKeyRepository,
  type CreateApiKeyInput,
  type CreatedApiKey
} from '../store/apiKeys.repository';

interface ApiKeyRow {
  id: string;
  account_id: string;
  key_hash: string;
  key_prefix: string;
  label: string | null;
  created_at: Date | string;
  revoked_at: Date | string | null;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : String(value);
}

function mapRow(row: ApiKeyRow): ApiKeyRecord {
  return {
    id: row.id,
    accountId: row.account_id,
    keyHash: row.key_hash,
    keyPrefix: row.key_prefix,
    label: row.label,
    createdAt: toIso(row.created_at),
    revokedAt: row.revoked_at === null ? null : toIso(row.revoked_at)
  };
}

export class PostgresApiKeyRepository implements ApiKeyRepository {
  constructor(private readonly pool: Pool) {}

  public async findActiveByKeyHash(
    keyHash: string
  ): Promise<ApiKeyLookup | null> {
    const result = await this.pool.query<ApiKeyRow>(
      `SELECT id, account_id, key_hash, key_prefix, label, created_at, revoked_at
       FROM api_keys
       WHERE key_hash = $1 AND revoked_at IS NULL
       LIMIT 1`,
      [keyHash]
    );
    const row = result.rows[0];
    if (!row) {
      return null;
    }
    return { id: row.id, accountId: row.account_id };
  }

  public async create(input: CreateApiKeyInput): Promise<CreatedApiKey> {
    const { apiKey, keyPrefix } = generateApiKeySecret();
    const record = newApiKeyRecord(input, hashApiKey(apiKey), keyPrefix);

    await this.pool.query(
      `INSERT INTO api_keys
        (id, account_id, key_hash, key_prefix, label, created_at, revoked_at)
       VALUES ($1, $2, $3, $4, $5, $6::timestamptz, NULL)`,
      [
        record.id,
        record.accountId,
        record.keyHash,
        record.keyPrefix,
        record.label,
        record.createdAt
      ]
    );

    return { record, apiKey };
  }

  public async listByAccount(
    accountId: string
  ): Promise<readonly ApiKeyPublic[]> {
    const result = await this.pool.query<ApiKeyRow>(
      `SELECT id, account_id, key_hash, key_prefix, label, created_at, revoked_at
       FROM api_keys
       WHERE account_id = $1
       ORDER BY created_at DESC`,
      [accountId]
    );
    return result.rows.map((row) => toPublicApiKey(mapRow(row)));
  }

  public async revoke(id: string, accountId: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE api_keys
       SET revoked_at = NOW()
       WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL`,
      [id, accountId]
    );
    if ((result.rowCount ?? 0) > 0) {
      return true;
    }
    // Ya revocada o inexistente / otro tenant
    const existing = await this.pool.query(
      `SELECT 1 FROM api_keys WHERE id = $1 AND account_id = $2 LIMIT 1`,
      [id, accountId]
    );
    return (existing.rowCount ?? 0) > 0;
  }
}
