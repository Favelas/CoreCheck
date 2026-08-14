import type { Request, Response } from 'express';
import type { HealthResponse } from '../types/contracts';

export const SERVICE_NAME = 'Corecheck API';

/** GET / — health check */
export function getHealth(_req: Request, res: Response): void {
  const body: HealthResponse = {
    status: 'ok',
    service: SERVICE_NAME,
    timestamp: new Date().toISOString()
  };
  res.status(200).json(body);
}
