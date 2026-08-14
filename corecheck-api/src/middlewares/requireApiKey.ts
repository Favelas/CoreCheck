import type { RequestHandler } from 'express';
import { AppError } from '../errors/AppError';
import {
  extractBearerOrApiKey,
  type ApiKeyBinding
} from '../security/apiKeys';
import {
  hashApiKey,
  type ApiKeyRepository
} from '../store/apiKeys.repository';

/**
 * Protege /api/*:
 * 1) Bootstrap env bindings (CORECHECK_API_KEY / KEYS)
 * 2) Keys dinámicas (SHA-256 lookup en ApiKeyRepository)
 *
 * Sin bootstrap env y sin credential → 503 MISCONFIGURED
 * (hace falta al menos una key de arranque para mint/rotate).
 */
export function requireApiKey(
  bindings: readonly ApiKeyBinding[],
  apiKeyRepository: ApiKeyRepository
): RequestHandler {
  const byKey = new Map(bindings.map((b) => [b.key, b.accountId]));

  return (req, _res, next) => {
    void (async () => {
      try {
        const provided = extractBearerOrApiKey(
          req.header('authorization') ?? undefined,
          req.header('x-api-key') ?? undefined
        );

        if (provided === undefined) {
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
          next(
            new AppError(
              'UNAUTHORIZED',
              'API key ausente o inválida. Use Authorization: Bearer <key> o X-API-Key.',
              401
            )
          );
          return;
        }

        const fromEnv = byKey.get(provided);
        if (fromEnv !== undefined) {
          req.accountId = fromEnv;
          next();
          return;
        }

        const lookup = await apiKeyRepository.findActiveByKeyHash(
          hashApiKey(provided)
        );
        if (lookup) {
          req.accountId = lookup.accountId;
          next();
          return;
        }

        next(
          new AppError(
            'UNAUTHORIZED',
            'API key ausente o inválida. Use Authorization: Bearer <key> o X-API-Key.',
            401
          )
        );
      } catch (error) {
        next(error);
      }
    })();
  };
}
