import type { RequestHandler } from 'express';
import { AppError } from '../errors/AppError';
import {
  extractBearerOrApiKey,
  type ApiKeyBinding
} from '../security/apiKeys';

/**
 * Protege /api/* — valida API key e inyecta req.accountId (tenant isolation).
 */
export function requireApiKey(
  bindings: readonly ApiKeyBinding[]
): RequestHandler {
  const byKey = new Map(bindings.map((b) => [b.key, b.accountId]));

  return (req, _res, next) => {
    if (byKey.size === 0) {
      next(
        new AppError(
          'MISCONFIGURED',
          'El servidor no tiene CORECHECK_API_KEY configurada.',
          503
        )
      );
      return;
    }

    const provided = extractBearerOrApiKey(
      req.header('authorization') ?? undefined,
      req.header('x-api-key') ?? undefined
    );

    if (provided === undefined) {
      next(
        new AppError(
          'UNAUTHORIZED',
          'API key ausente o inválida. Use Authorization: Bearer <key> o X-API-Key.',
          401
        )
      );
      return;
    }

    const accountId = byKey.get(provided);
    if (accountId === undefined) {
      next(
        new AppError(
          'UNAUTHORIZED',
          'API key ausente o inválida. Use Authorization: Bearer <key> o X-API-Key.',
          401
        )
      );
      return;
    }

    req.accountId = accountId;
    next();
  };
}
