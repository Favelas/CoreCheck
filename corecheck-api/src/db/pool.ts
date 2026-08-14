import { Pool, type PoolConfig } from 'pg';

export interface PostgresEnv {
  readonly DATABASE_URL?: string;
  readonly POSTGRES_HOST?: string;
  readonly POSTGRES_PORT?: string;
  readonly POSTGRES_DB?: string;
  readonly POSTGRES_USER?: string;
  readonly POSTGRES_PASSWORD?: string;
}

/**
 * Construye PoolConfig desde DATABASE_URL o variables discretas.
 */
export function resolvePoolConfig(
  env: NodeJS.ProcessEnv | PostgresEnv = process.env
): PoolConfig {
  const databaseUrl = env['DATABASE_URL'];
  if (typeof databaseUrl === 'string' && databaseUrl.trim() !== '') {
    return { connectionString: databaseUrl.trim() };
  }

  const host = env['POSTGRES_HOST'] ?? '127.0.0.1';
  const port = Number(env['POSTGRES_PORT'] ?? 5432);
  const database = env['POSTGRES_DB'] ?? 'corecheck_api';
  const user = env['POSTGRES_USER'] ?? 'corecheck';
  const password = env['POSTGRES_PASSWORD'] ?? 'corecheck';

  return {
    host,
    port: Number.isFinite(port) ? port : 5432,
    database,
    user,
    password,
    max: 10,
    idleTimeoutMillis: 30_000
  };
}

let sharedPool: Pool | undefined;

/** Pool singleton de proceso (dev/prod). Tests pueden inyectar Pool mock. */
export function createPoolFromEnv(
  env: NodeJS.ProcessEnv = process.env
): Pool {
  return new Pool(resolvePoolConfig(env));
}

export function getSharedPool(env: NodeJS.ProcessEnv = process.env): Pool {
  if (sharedPool === undefined) {
    sharedPool = createPoolFromEnv(env);
  }
  return sharedPool;
}

export async function closeSharedPool(): Promise<void> {
  if (sharedPool !== undefined) {
    await sharedPool.end();
    sharedPool = undefined;
  }
}
