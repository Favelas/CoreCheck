/**
 * Resolución de API keys aceptadas (Fase 1.1).
 * Fuentes: options explícitas (tests) o env CORECHECK_API_KEY / CORECHECK_API_KEYS.
 */
export function parseApiKeysFromEnv(
  env: NodeJS.ProcessEnv = process.env
): string[] {
  const multi = env['CORECHECK_API_KEYS'];
  if (typeof multi === 'string' && multi.trim() !== '') {
    return multi
      .split(',')
      .map((k) => k.trim())
      .filter((k) => k.length > 0);
  }

  const single = env['CORECHECK_API_KEY'];
  if (typeof single === 'string' && single.trim() !== '') {
    return [single.trim()];
  }

  return [];
}

export function extractBearerOrApiKey(
  authorizationHeader: string | undefined,
  apiKeyHeader: string | undefined
): string | undefined {
  if (typeof apiKeyHeader === 'string' && apiKeyHeader.trim() !== '') {
    return apiKeyHeader.trim();
  }

  if (typeof authorizationHeader !== 'string') {
    return undefined;
  }

  const match = /^Bearer\s+(.+)$/i.exec(authorizationHeader.trim());
  if (!match || match[1] === undefined) {
    return undefined;
  }

  const token = match[1].trim();
  return token.length > 0 ? token : undefined;
}
