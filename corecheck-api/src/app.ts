import path from 'node:path';
import express, { type Express } from 'express';
import { errorHandler } from './middlewares/errorHandler';
import { notFoundHandler } from './middlewares/notFound';
import { rateLimit } from './middlewares/rateLimit';
import { requestContext } from './middlewares/requestContext';
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

export interface RateLimitConfig {
  readonly windowMs: number;
  readonly max: number;
}

export interface CreateAppOptions {
  readonly apiKeyBindings?: readonly ApiKeyBinding[];
  readonly apiKeys?: readonly string[];
  readonly repository?: ReportsRepository;
  readonly persistence?: 'memory' | 'file' | 'postgres';
  readonly dataDir?: string;
  /** Default prod: 120 req / 60s. Tests pasan un max alto o disableRateLimit. */
  readonly rateLimit?: RateLimitConfig;
  readonly disableRateLimit?: boolean;
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
 * Factory Express: auth + tenant + repository DI + observability.
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
  const persistenceLabel =
    options.persistence ??
    (options.repository ? 'memory' : (process.env['CORECHECK_PERSISTENCE'] ?? 'file'));
  app.set('persistence', persistenceLabel);

  app.use(requestContext());
  app.use(express.json({ limit: '1mb' }));

  app.use('/', healthRouter);

  if (!options.disableRateLimit) {
    const rl = options.rateLimit ?? { windowMs: 60_000, max: 120 };
    app.use('/api', rateLimit(rl));
  }

  app.use('/api', requireApiKey(bindings));
  app.use('/api/reports', reportsRouter);

  // Report Viewer (Fase 4.3): UI estática; datos solo vía /api con API key.
  const viewerDir = path.join(process.cwd(), 'public', 'viewer');
  app.use('/viewer', express.static(viewerDir, { index: 'index.html' }));

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
