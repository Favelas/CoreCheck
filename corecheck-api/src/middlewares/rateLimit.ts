import type { RequestHandler } from 'express';
import { AppError } from '../errors/AppError';

export interface RateLimitOptions {
  readonly windowMs: number;
  readonly max: number;
}

interface Bucket {
  count: number;
  resetAt: number;
}

/**
 * Rate limit en memoria por API key (o IP si aún no hay auth).
 * Fail-open no: 429 con ApiErrorBody.
 */
export function rateLimit(options: RateLimitOptions): RequestHandler {
  const buckets = new Map<string, Bucket>();

  return (req, _res, next) => {
    const key =
      req.header('x-api-key')?.trim() ||
      req.header('authorization')?.trim() ||
      req.ip ||
      'anonymous';

    const now = Date.now();
    let bucket = buckets.get(key);
    if (bucket === undefined || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + options.windowMs };
      buckets.set(key, bucket);
    }

    bucket.count += 1;
    if (bucket.count > options.max) {
      next(
        new AppError(
          'RATE_LIMITED',
          `Rate limit excedido: máx ${options.max} req / ${options.windowMs}ms.`,
          429
        )
      );
      return;
    }

    next();
  };
}
