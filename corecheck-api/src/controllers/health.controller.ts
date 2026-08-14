import type { Request, Response } from 'express';
import { metricsRegistry } from '../observability/metrics';
import type { HealthResponse, MetricsResponse } from '../types/contracts';

export const SERVICE_NAME = 'Corecheck API';
const SERVICE_VERSION = '1.0.0';

function resolvePersistenceLabel(req: Request): string {
  const fromApp = req.app.get('persistence');
  if (typeof fromApp === 'string' && fromApp.length > 0) {
    return fromApp;
  }
  return process.env['CORECHECK_PERSISTENCE'] ?? 'file';
}

/** GET / — health check enriquecido (Fase 4.1) */
export function getHealth(req: Request, res: Response): void {
  const snap = metricsRegistry.snapshot();
  const body: HealthResponse = {
    status: 'ok',
    service: SERVICE_NAME,
    timestamp: new Date().toISOString(),
    uptimeSeconds: snap.uptimeSeconds,
    persistence: resolvePersistenceLabel(req),
    version: SERVICE_VERSION
  };
  res.status(200).json(body);
}

/** GET /metrics — snapshot ops sin PII */
export function getMetrics(_req: Request, res: Response): void {
  const body: MetricsResponse = {
    service: SERVICE_NAME,
    metrics: metricsRegistry.snapshot()
  };
  res.status(200).json(body);
}
