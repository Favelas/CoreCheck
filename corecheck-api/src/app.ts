import express, { type Express } from 'express';
import { errorHandler } from './middlewares/errorHandler';
import { notFoundHandler } from './middlewares/notFound';
import { requireApiKey } from './middlewares/requireApiKey';
import { healthRouter } from './routes/health.routes';
import { reportsRouter } from './routes/reports.routes';
import {
  bindingsFromApiKeys,
  parseApiKeyBindingsFromEnv,
  type ApiKeyBinding
} from './security/apiKeys';
import { createReportsRepositoryFromEnv } from './store/createRepository';
import { setReportsRepository } from './store/repository.context';
import type { ReportsRepository } from './store/reports.repository';

export interface CreateAppOptions {
  readonly apiKeyBindings?: readonly ApiKeyBinding[];
  readonly apiKeys?: readonly string[];
  /** Inyectar repositorio (tests = memory; prod = file/postgres). */
  readonly repository?: ReportsRepository;
  /** Si no hay repository, fuerza modo memory|file|postgres. */
  readonly persistence?: 'memory' | 'file' | 'postgres';
  readonly dataDir?: string;
}

function resolveBindings(options: CreateAppOptions): ApiKeyBinding[] {
  if (options.apiKeyBindings !== undefined) {
    return [...options.apiKeyBindings];
  }
  if (options.apiKeys !== undefined) {
    return bindingsFromApiKeys(options.apiKeys);
  }
  return parseApiKeyBindingsFromEnv();
}

/**
 * Factory Express: auth + tenant + repository DI.
 */
export function createApp(options: CreateAppOptions = {}): Express {
  const app = express();
  const bindings = resolveBindings(options);

  const repository =
    options.repository ??
    createReportsRepositoryFromEnv({
      ...(options.persistence !== undefined
        ? { mode: options.persistence }
        : {}),
      ...(options.dataDir !== undefined ? { dataDir: options.dataDir } : {})
    });
  setReportsRepository(repository);

  app.use(express.json({ limit: '1mb' }));

  app.use('/', healthRouter);
  app.use('/api', requireApiKey(bindings));
  app.use('/api/reports', reportsRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
