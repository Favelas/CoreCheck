import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import { metricsRegistry } from '../observability/metrics';

/**
 * Request ID + timing + access log estructurado (sin bodies/secretos).
 */
export function requestContext(): RequestHandler {
  return (req, res, next) => {
    const incoming = req.header('x-request-id');
    const requestId =
      typeof incoming === 'string' && incoming.trim() !== ''
        ? incoming.trim()
        : randomUUID();

    req.requestId = requestId;
    res.setHeader('x-request-id', requestId);

    const started = Date.now();

    res.on('finish', () => {
      const latencyMs = Date.now() - started;
      metricsRegistry.recordRequest(res.statusCode, latencyMs);

      const line = {
        level: res.statusCode >= 500 ? 'error' : 'info',
        msg: 'http_access',
        requestId,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        latencyMs,
        accountId: req.accountId ?? null
      };
      // JSON line — apto para agregadores; no incluye Authorization ni body
      console.log(JSON.stringify(line));
    });

    next();
  };
}
