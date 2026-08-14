import express, { type Express } from 'express';
import { errorHandler } from './middlewares/errorHandler';
import { notFoundHandler } from './middlewares/notFound';
import { healthRouter } from './routes/health.routes';
import { reportsRouter } from './routes/reports.routes';

/**
 * Factory de la app Express (sin listen).
 * Permite tests HTTP sin abrir puerto fijo.
 */
export function createApp(): Express {
  const app = express();

  // Límite de body alineado a presupuesto de evidencia CoreCheck (evitar OOM)
  app.use(express.json({ limit: '1mb' }));

  app.use('/', healthRouter);
  app.use('/api/reports', reportsRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
