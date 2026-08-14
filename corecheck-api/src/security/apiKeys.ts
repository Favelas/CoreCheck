/**
 * Resolución de API keys → accountId (Fase 1.1 + 1.2).
 */

export interface ApiKeyBinding {
  readonly key: string;
  readonly accountId: string;
}

const DEFAULT_ACCOUNT_ID = 'tenant_default';

function parseBindingEntry(entry: string): ApiKeyBinding | undefined {
  const trimmed = entry.trim();
  if (trimmed === '') {
    return undefined;
  }

  const separator = trimmed.indexOf(':');
  if (separator === -1) {
    return { key: trimmed, accountId: DEFAULT_ACCOUNT_ID };
  }

  const key = trimmed.slice(0, separator).trim();
  const accountId = trimmed.slice(separator + 1).trim();
  if (key === '' || accountId === '') {
    return undefined;
  }

  return { key, accountId };
}

/**
 * Fuentes:
 * - CORECHECK_API_KEYS=key:accountId,key2:accountId2  (o key sin : → tenant_default)
 * - CORECHECK_API_KEY + opcional CORECHECK_ACCOUNT_ID (default tenant_default)
 */
export function parseApiKeyBindingsFromEnv(
  env: NodeJS.ProcessEnv = process.env
): ApiKeyBinding[] {
  const multi = env['CORECHECK_API_KEYS'];
  if (typeof multi === 'string' && multi.trim() !== '') {
    return multi
      .split(',')
      .map((part) => parseBindingEntry(part))
      .filter((b): b is ApiKeyBinding => b !== undefined);
  }

  const single = env['CORECHECK_API_KEY'];
  if (typeof single === 'string' && single.trim() !== '') {
    const accountFromEnv = env['CORECHECK_ACCOUNT_ID'];
    const accountId =
      typeof accountFromEnv === 'string' && accountFromEnv.trim() !== ''
        ? accountFromEnv.trim()
        : DEFAULT_ACCOUNT_ID;
    return [{ key: single.trim(), accountId }];
  }

  return [];
}

/** @deprecated Prefer parseApiKeyBindingsFromEnv — mantiene compat 1.1. */
export function parseApiKeysFromEnv(
  env: NodeJS.ProcessEnv = process.env
): string[] {
  return parseApiKeyBindingsFromEnv(env).map((b) => b.key);
}

export function bindingsFromApiKeys(
  apiKeys: readonly string[],
  accountId: string = DEFAULT_ACCOUNT_ID
): ApiKeyBinding[] {
  return apiKeys.map((key) => ({ key, accountId }));
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

export { DEFAULT_ACCOUNT_ID };
