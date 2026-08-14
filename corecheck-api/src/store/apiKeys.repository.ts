import { createHash, randomBytes, randomUUID } from 'node:crypto';

export interface ApiKeyRecord {
  readonly id: string;
  readonly accountId: string;
  readonly keyHash: string;
  readonly keyPrefix: string;
  readonly label: string | null;
  readonly createdAt: string;
  readonly revokedAt: string | null;
}

export interface CreateApiKeyInput {
  readonly accountId: string;
  readonly label?: string;
}

export interface CreatedApiKey {
  readonly record: ApiKeyRecord;
  /** Solo se devuelve una vez en create — no se vuelve a leer. */
  readonly apiKey: string;
}

export interface ApiKeyLookup {
  readonly id: string;
  readonly accountId: string;
}

/**
 * Puerto de API keys dinámicas (Slice 2).
 * Almacenamos solo SHA-256 del secreto; el plaintext nunca persiste.
 */
export interface ApiKeyRepository {
  findActiveByKeyHash(keyHash: string): Promise<ApiKeyLookup | null>;
  create(input: CreateApiKeyInput): Promise<CreatedApiKey>;
  listByAccount(accountId: string): Promise<readonly ApiKeyPublic[]>;
  revoke(id: string, accountId: string): Promise<boolean>;
}

export interface ApiKeyPublic {
  readonly id: string;
  readonly accountId: string;
  readonly keyPrefix: string;
  readonly label: string | null;
  readonly createdAt: string;
  readonly revokedAt: string | null;
}

export function hashApiKey(rawKey: string): string {
  return createHash('sha256').update(rawKey, 'utf8').digest('hex');
}

/** Genera `cc_live_<32 hex>` — prefijo visible para soporte. */
export function generateApiKeySecret(): { apiKey: string; keyPrefix: string } {
  const secret = randomBytes(24).toString('hex');
  const apiKey = `cc_live_${secret}`;
  return { apiKey, keyPrefix: apiKey.slice(0, 12) };
}

export function toPublicApiKey(record: ApiKeyRecord): ApiKeyPublic {
  return {
    id: record.id,
    accountId: record.accountId,
    keyPrefix: record.keyPrefix,
    label: record.label,
    createdAt: record.createdAt,
    revokedAt: record.revokedAt
  };
}

export function newApiKeyRecord(
  input: CreateApiKeyInput,
  keyHash: string,
  keyPrefix: string
): ApiKeyRecord {
  return {
    id: randomUUID(),
    accountId: input.accountId,
    keyHash,
    keyPrefix,
    label: input.label?.trim() ? input.label.trim() : null,
    createdAt: new Date().toISOString(),
    revokedAt: null
  };
}
