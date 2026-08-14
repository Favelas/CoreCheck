import { randomUUID } from 'node:crypto';

export interface ControlPlaneHttpConfig {
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly timeoutMs?: number;
  readonly userAgent?: string;
  /** Inyectable para tests deterministas. */
  readonly fetchImpl?: typeof fetch;
}

export class ControlPlaneHttpError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string,
    public readonly requestId?: string
  ) {
    super(message);
    this.name = 'ControlPlaneHttpError';
  }
}

/**
 * Cliente HTTP compartido Control Plane (license + reports).
 * Inyecta X-API-Key / Bearer y x-request-id de forma consistente.
 */
export class ControlPlaneHttpClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly apiKey?: string;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;

  constructor(config: ControlPlaneHttpConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.timeoutMs = config.timeoutMs ?? 8000;
    this.apiKey = config.apiKey;
    this.userAgent = config.userAgent ?? 'CoreCheck-CLI/1.0';
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  public async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  public async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  public async request<T>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: unknown
  ): Promise<T> {
    const requestId = randomUUID();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers: Record<string, string> = {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': this.userAgent,
        'x-request-id': requestId
      };

      if (this.apiKey) {
        headers.Authorization = `Bearer ${this.apiKey}`;
        headers['X-API-Key'] = this.apiKey;
      }

      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });

      const text = await response.text().catch(() => '');
      if (!response.ok) {
        const parsed = tryParseJson(text);
        const code =
          typeof parsed?.['error'] === 'string'
            ? parsed['error']
            : typeof parsed?.['code'] === 'string'
              ? parsed['code']
              : undefined;
        const detail =
          typeof parsed?.['message'] === 'string'
            ? parsed['message']
            : text.slice(0, 200);
        throw new ControlPlaneHttpError(
          `Control Plane ${method} ${path} → ${response.status}: ${detail}`,
          response.status,
          code,
          requestId
        );
      }

      if (!text) {
        return undefined as T;
      }
      return JSON.parse(text) as T;
    } catch (error) {
      if (error instanceof ControlPlaneHttpError) {
        throw error;
      }
      const message =
        error instanceof Error && error.name === 'AbortError'
          ? `Control Plane timeout after ${this.timeoutMs}ms`
          : error instanceof Error
            ? error.message
            : String(error);
      throw new ControlPlaneHttpError(message, undefined, undefined, requestId);
    } finally {
      clearTimeout(timer);
    }
  }
}

function tryParseJson(text: string): Record<string, unknown> | null {
  if (!text) {
    return null;
  }
  try {
    const value: unknown = JSON.parse(text);
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

/** Resuelve base URL del Control Plane de reportes (Slice 1). */
export function resolveReportsApiBaseUrl(
  explicit?: string,
  env: NodeJS.ProcessEnv = process.env
): string | undefined {
  const candidates = [
    explicit,
    env['CORECHECK_REPORTS_API_URL'],
    env['CORECHECK_UPLOAD_URL'],
    env['CORECHECK_API_URL']
  ];
  for (const raw of candidates) {
    const value = (raw ?? '').trim();
    if (value.length > 0) {
      return value.replace(/\/+$/, '');
    }
  }
  return undefined;
}

export function isUploadEnabled(
  cliFlag: boolean | undefined,
  env: NodeJS.ProcessEnv = process.env
): boolean {
  if (cliFlag === true) {
    return true;
  }
  const raw = (env['CORECHECK_UPLOAD'] ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes';
}
