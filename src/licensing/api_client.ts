import {
  AccountStatusResponse,
  LicenseInfo,
  LicenseValidationRequest,
  QuotaRenewalResponse,
  RevokeAccessResponse,
  SaaSApiConfig,
  UsageTelemetryEvent
} from '../types/license.js';

export class SaaSApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string
  ) {
    super(message);
    this.name = 'SaaSApiError';
  }
}

/**
 * Cliente REST hacia el Control Plane SaaS (Supabase/API gateway).
 * Todos los métodos respetan timeout corto para no bloquear CI.
 */
export class SaaSApiClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly apiKey?: string;

  constructor(config: SaaSApiConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.timeoutMs = config.timeoutMs ?? 4000;
    this.apiKey = config.apiKey;
  }

  public async validateLicense(
    request: LicenseValidationRequest
  ): Promise<LicenseInfo> {
    return this.post<LicenseInfo>('/v1/licenses/validate', {
      ...request,
      apiKey: request.apiKey
    });
  }

  public async getAccountStatus(accountId: string): Promise<AccountStatusResponse> {
    return this.get<AccountStatusResponse>(`/v1/accounts/${encodeURIComponent(accountId)}/status`);
  }

  public async renewMonthlyQuota(accountId: string): Promise<QuotaRenewalResponse> {
    return this.post<QuotaRenewalResponse>(
      `/v1/accounts/${encodeURIComponent(accountId)}/quota/renew`,
      {}
    );
  }

  public async revokeAccess(
    accountId: string,
    reason?: string
  ): Promise<RevokeAccessResponse> {
    return this.post<RevokeAccessResponse>(
      `/v1/accounts/${encodeURIComponent(accountId)}/revoke`,
      { reason }
    );
  }

  public async sendTelemetry(event: UsageTelemetryEvent): Promise<void> {
    await this.post<{ ok: boolean }>('/v1/telemetry/usage', event);
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private async request<T>(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers: Record<string, string> = {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'CoreCheck-CLI/4.0'
      };
      if (this.apiKey) {
        headers.Authorization = `Bearer ${this.apiKey}`;
      }

      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        let code: string | undefined;
        try {
          code = (JSON.parse(text) as { code?: string }).code;
        } catch {
          // ignore
        }
        throw new SaaSApiError(
          `SaaS API ${method} ${path} → ${response.status}: ${text.slice(0, 200)}`,
          response.status,
          code
        );
      }

      return (await response.json()) as T;
    } catch (error) {
      if (error instanceof SaaSApiError) {
        throw error;
      }
      const message =
        error instanceof Error && error.name === 'AbortError'
          ? `SaaS API timeout after ${this.timeoutMs}ms`
          : (error as Error).message;
      throw new SaaSApiError(message);
    } finally {
      clearTimeout(timer);
    }
  }
}
