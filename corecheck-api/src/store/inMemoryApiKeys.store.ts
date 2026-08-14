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
} from './apiKeys.repository';

/**
 * Store en memoria para memory/file y tests.
 * Keys dinámicas no sobreviven restart (usar postgres en staging/prod).
 */
export class InMemoryApiKeyRepository implements ApiKeyRepository {
  private readonly byId = new Map<string, ApiKeyRecord>();

  public async findActiveByKeyHash(
    keyHash: string
  ): Promise<ApiKeyLookup | null> {
    for (const record of this.byId.values()) {
      if (record.keyHash === keyHash && record.revokedAt === null) {
        return { id: record.id, accountId: record.accountId };
      }
    }
    return null;
  }

  public async create(input: CreateApiKeyInput): Promise<CreatedApiKey> {
    const { apiKey, keyPrefix } = generateApiKeySecret();
    const record = newApiKeyRecord(input, hashApiKey(apiKey), keyPrefix);
    this.byId.set(record.id, record);
    return { record, apiKey };
  }

  public async listByAccount(
    accountId: string
  ): Promise<readonly ApiKeyPublic[]> {
    return [...this.byId.values()]
      .filter((r) => r.accountId === accountId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map(toPublicApiKey);
  }

  public async revoke(id: string, accountId: string): Promise<boolean> {
    const current = this.byId.get(id);
    if (!current || current.accountId !== accountId) {
      return false;
    }
    if (current.revokedAt !== null) {
      return true;
    }
    this.byId.set(id, {
      ...current,
      revokedAt: new Date().toISOString()
    });
    return true;
  }

  /** Test helper */
  public clear(): void {
    this.byId.clear();
  }
}
