import type { RequestHandler } from 'express';
import { AppError } from '../errors/AppError';
import { extractBearerOrApiKey } from '../security/apiKeys';

/**
 * Protege rutas /api/* — requiere API key válida.
 * Headers: Authorization: Bearer <key>  |  X-API-Key: <key>
 */
export function requireApiKey(validKeys: readonly string[]): RequestHandler {
  return (req, _res, next) => {
    if (validKeys.length === 0) {
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

    if (provided === undefined || !validKeys.includes(provided)) {
      next(
        new AppError(
          'UNAUTHORIZED',
          'API key ausente o inválida. Use Authorization: Bearer <key> o X-API-Key.',
          401
        )
      );
      return;
    }

    next();
  };
}
