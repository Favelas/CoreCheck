import path from 'node:path';
import type { Pool } from 'pg';
import { createPoolFromEnv } from '../db/pool';
import { PostgresReportsRepository } from '../repositories/PostgresReportsRepository';
import type { ReportsRepository } from './reports.repository';
import { InMemoryReportsStore } from './reports.store';
import { JsonFileReportsStore } from './jsonFileReports.store';

export type PersistenceMode = 'memory' | 'file' | 'postgres';

export interface CreateRepositoryOptions {
  readonly mode?: PersistenceMode;
  readonly dataDir?: string;
  readonly env?: NodeJS.ProcessEnv;
  /** Pool inyectable (tests / migrate). */
  readonly pool?: Pool;
}

/**
 * Factory:
 * - CORECHECK_PERSISTENCE=memory|file|postgres (default: file)
 * - CORECHECK_DATA_DIR (file)
 * - DATABASE_URL o POSTGRES_* (postgres)
 */
export function createReportsRepositoryFromEnv(
  options: CreateRepositoryOptions = {}
): ReportsRepository {
  const env = options.env ?? process.env;
  const mode = (options.mode ??
    env['CORECHECK_PERSISTENCE'] ??
    'file') as string;

  if (mode === 'memory') {
    return new InMemoryReportsStore();
  }

  if (mode === 'file') {
    const dataDir =
      options.dataDir ??
      env['CORECHECK_DATA_DIR'] ??
      path.join(process.cwd(), 'data');
    const filePath = path.join(dataDir, 'reports.json');
    return new JsonFileReportsStore({ filePath });
  }

  if (mode === 'postgres') {
    const pool = options.pool ?? createPoolFromEnv(env);
    return new PostgresReportsRepository(pool);
  }

  throw new Error(
    `CORECHECK_PERSISTENCE inválido: "${mode}". Use memory|file|postgres.`
  );
}
