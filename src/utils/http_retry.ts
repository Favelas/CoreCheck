/**
 * Exponential backoff + jitter para resiliencia ante WAF / rate-limit.
 * Estados reintentables: 403, 429, 503 (y errores de red transitorios).
 */

export const RETRYABLE_HTTP_STATUSES = new Set([403, 429, 503]);

export interface BackoffOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  /** Inyectable para tests deterministas. */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  onRetry?: (info: {
    attempt: number;
    status?: number;
    delayMs: number;
    error?: string;
  }) => void;
}

export interface RetryOutcome<T> {
  value: T;
  attempts: number;
  lastStatus?: number;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Delay = min(max, base * 2^(attempt-1)) + jitter [0, base). */
export function computeBackoffDelayMs(
  attempt: number,
  baseDelayMs: number,
  maxDelayMs: number,
  random: () => number = Math.random
): number {
  const exp = Math.min(maxDelayMs, baseDelayMs * 2 ** Math.max(0, attempt - 1));
  const jitter = Math.floor(random() * baseDelayMs);
  return Math.min(maxDelayMs, exp + jitter);
}

export function isRetryableStatus(status: number | undefined): boolean {
  return typeof status === 'number' && RETRYABLE_HTTP_STATUSES.has(status);
}

export function isRetryableNetworkMessage(message: string): boolean {
  return /ECONNRESET|ETIMEDOUT|EAI_AGAIN|net::ERR_CONNECTION|429|Too Many Requests|Service Unavailable|Forbidden|WAF/i.test(
    message
  );
}

/**
 * Reintenta `operation` cuando el resultado indica status reintentable o lanza error de red.
 * `getStatus` extrae el código HTTP del valor resuelto.
 */
export async function withExponentialBackoff<T>(
  operation: (attempt: number) => Promise<T>,
  getStatus: (value: T) => number | undefined,
  options: BackoffOptions = {}
): Promise<RetryOutcome<T>> {
  const maxAttempts = Math.max(1, options.maxAttempts ?? 4);
  const baseDelayMs = options.baseDelayMs ?? 400;
  const maxDelayMs = options.maxDelayMs ?? 8_000;
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;

  let lastStatus: number | undefined;
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const value = await operation(attempt);
      lastStatus = getStatus(value);
      if (!isRetryableStatus(lastStatus) || attempt === maxAttempts) {
        return { value, attempts: attempt, lastStatus };
      }
      const delayMs = computeBackoffDelayMs(attempt, baseDelayMs, maxDelayMs, random);
      options.onRetry?.({ attempt, status: lastStatus, delayMs });
      await sleep(delayMs);
    } catch (error) {
      lastError = error;
      const msg = error instanceof Error ? error.message : String(error);
      if (!isRetryableNetworkMessage(msg) || attempt === maxAttempts) {
        throw error;
      }
      const delayMs = computeBackoffDelayMs(attempt, baseDelayMs, maxDelayMs, random);
      options.onRetry?.({ attempt, delayMs, error: msg });
      await sleep(delayMs);
    }
  }

  if (lastError) throw lastError;
  throw new Error(
    `Retry exhausted after ${maxAttempts} attempts (lastStatus=${lastStatus ?? 'n/a'})`
  );
}

export function formatWafNetworkMessage(status: number, url: string, attempts: number): string {
  const label =
    status === 403
      ? 'WAF/Forbidden (403)'
      : status === 429
        ? 'Rate limit (429)'
        : status === 503
          ? 'Service Unavailable (503)'
          : `HTTP ${status}`;
  return (
    `Target unreachable due to ${label} at ${url} after ${attempts} attempt(s). ` +
    `Allowlist GitHub Actions runners / reduce crawl rate / use staging without bot protection.`
  );
}
