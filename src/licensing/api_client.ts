import {
  AccountStatusResponse,
  LicenseInfo,
  LicenseValidationRequest,
  QuotaRenewalResponse,
  RevokeAccessResponse,
  SaaSApiConfig,
  UsageTelemetryEvent
} from '../types/license.js';
import {
  ControlPlaneHttpClient,
  ControlPlaneHttpError
} from '../http/control_plane_http.js';

export class SaaSApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string,
    public readonly requestId?: string
  ) {
    super(message);
    this.name = 'SaaSApiError';
  }
}

/**
 * Cliente REST hacia el Control Plane de licencias/telemetría.
 * Comparte capa HTTP (API key + x-request-id) con ReportsClient.
 */
export class SaaSApiClient {
  private readonly http: ControlPlaneHttpClient;

  constructor(config: SaaSApiConfig) {
    this.http = new ControlPlaneHttpClient({
      baseUrl: config.baseUrl,
      timeoutMs: config.timeoutMs ?? 4000,
      userAgent: 'CoreCheck-CLI/4.0',
      ...(config.apiKey ? { apiKey: config.apiKey } : {})
    });
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
    return this.get<AccountStatusResponse>(
      `/v1/accounts/${encodeURIComponent(accountId)}/status`
    );
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
    try {
      return await this.http.get<T>(path);
    } catch (error) {
      throw mapToSaaS(error);
    }
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    try {
      return await this.http.post<T>(path, body);
    } catch (error) {
      throw mapToSaaS(error);
    }
  }
}

function mapToSaaS(error: unknown): SaaSApiError {
  if (error instanceof SaaSApiError) {
    return error;
  }
  if (error instanceof ControlPlaneHttpError) {
    return new SaaSApiError(
      error.message.replace(/^Control Plane/, 'SaaS API'),
      error.status,
      error.code,
      error.requestId
    );
  }
  return new SaaSApiError(
    error instanceof Error ? error.message : String(error)
  );
}
