import express, { type Express } from 'express';
import { errorHandler } from './middlewares/errorHandler';
import { notFoundHandler } from './middlewares/notFound';
import { requireApiKey } from './middlewares/requireApiKey';
import { healthRouter } from './routes/health.routes';
import { reportsRouter } from './routes/reports.routes';
import { parseApiKeysFromEnv } from './security/apiKeys';

export interface CreateAppOptions {
  /** Keys válidas; si se omite, se leen de CORECHECK_API_KEY(S). */
  readonly apiKeys?: readonly string[];
}

/**
 * Factory de la app Express (sin listen).
 * /api/* exige API key (fail-closed si no hay keys configuradas → 503).
 * GET / (health) permanece público.
 */
export function createApp(options: CreateAppOptions = {}): Express {
  const app = express();
  const apiKeys = options.apiKeys ?? parseApiKeysFromEnv();

  app.use(express.json({ limit: '1mb' }));

  app.use('/', healthRouter);
  app.use('/api', requireApiKey(apiKeys));
  app.use('/api/reports', reportsRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
