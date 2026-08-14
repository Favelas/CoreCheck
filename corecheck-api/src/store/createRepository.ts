import path from 'node:path';
import type { ReportsRepository } from './reports.repository';
import { InMemoryReportsStore } from './reports.store';
import { JsonFileReportsStore } from './jsonFileReports.store';

export type PersistenceMode = 'memory' | 'file';

export interface CreateRepositoryOptions {
  readonly mode?: PersistenceMode;
  readonly dataDir?: string;
  readonly env?: NodeJS.ProcessEnv;
}

/**
 * Factory de repositorio según env:
 * - CORECHECK_PERSISTENCE=memory|file (default: file)
 * - CORECHECK_DATA_DIR (default: ./data)
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

  throw new Error(
    `CORECHECK_PERSISTENCE inválido: "${mode}". Use memory|file.`
  );
}
