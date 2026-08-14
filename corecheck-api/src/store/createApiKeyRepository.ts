import type { Pool } from 'pg';
import { createPoolFromEnv } from '../db/pool';
import { PostgresApiKeyRepository } from '../repositories/PostgresApiKeyRepository';
import type { ApiKeyRepository } from './apiKeys.repository';
import { InMemoryApiKeyRepository } from './inMemoryApiKeys.store';
import type { PersistenceMode } from './createRepository';

export interface CreateApiKeyRepositoryOptions {
  readonly mode?: PersistenceMode;
  readonly env?: NodeJS.ProcessEnv;
  readonly pool?: Pool;
  readonly repository?: ApiKeyRepository;
}

/**
 * Keys dinámicas:
 * - postgres → tabla api_keys (hash)
 * - memory/file → InMemory (env bindings siguen siendo el bootstrap)
 */
export function createApiKeyRepositoryFromEnv(
  options: CreateApiKeyRepositoryOptions = {}
): ApiKeyRepository {
  if (options.repository) {
    return options.repository;
  }

  const env = options.env ?? process.env;
  const mode = (options.mode ??
    env['CORECHECK_PERSISTENCE'] ??
    'file') as string;

  if (mode === 'postgres') {
    const pool = options.pool ?? createPoolFromEnv(env);
    return new PostgresApiKeyRepository(pool);
  }

  return new InMemoryApiKeyRepository();
}
