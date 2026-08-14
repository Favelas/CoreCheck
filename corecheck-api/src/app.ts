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

export interface CreateAppOptions {
  /** Bindings key → accountId (preferido, Fase 1.2). */
  readonly apiKeyBindings?: readonly ApiKeyBinding[];
  /**
   * Compat Fase 1.1: lista de keys → todas mapean a tenant_default.
   * Ignorado si apiKeyBindings está definido.
   */
  readonly apiKeys?: readonly string[];
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
 * Factory Express: /api/* autenticado + aislado por accountId.
 * GET / health público.
 */
export function createApp(options: CreateAppOptions = {}): Express {
  const app = express();
  const bindings = resolveBindings(options);

  app.use(express.json({ limit: '1mb' }));

  app.use('/', healthRouter);
  app.use('/api', requireApiKey(bindings));
  app.use('/api/reports', reportsRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
