import {
  ControlPlaneHttpClient,
  ControlPlaneHttpError,
  resolveReportsApiBaseUrl,
  type ControlPlaneHttpConfig
} from '../http/control_plane_http.js';
import type { CreateReportInput } from './report_payload.js';

export class ReportsClientError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string,
    public readonly requestId?: string
  ) {
    super(message);
    this.name = 'ReportsClientError';
  }

  /** Auth fallida — key inválida o ausente en servidor. */
  get isUnauthorized(): boolean {
    return this.status === 401 || this.code === 'UNAUTHORIZED';
  }

  /** Payload rechazado (API usa 400; aceptamos 422 por compat). */
  get isPayloadInvalid(): boolean {
    return (
      this.status === 400 ||
      this.status === 422 ||
      this.code === 'BAD_REQUEST'
    );
  }

  get isRateLimited(): boolean {
    return this.status === 429 || this.code === 'RATE_LIMITED';
  }
}

export interface UploadedReport {
  readonly id: string;
  readonly createdAt: string;
  readonly accountId: string;
  readonly contentHash: string;
  readonly url: string;
}

export interface ReportsClientConfig {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

/**
 * Cliente de ingestión de reportes → corecheck-api POST /api/reports.
 */
export class ReportsClient {
  private readonly http: ControlPlaneHttpClient;

  constructor(config: ReportsClientConfig) {
    const httpConfig: ControlPlaneHttpConfig = {
      baseUrl: config.baseUrl,
      apiKey: config.apiKey,
      timeoutMs: config.timeoutMs ?? 10_000,
      userAgent: 'CoreCheck-CLI-Reports/1.0',
      ...(config.fetchImpl ? { fetchImpl: config.fetchImpl } : {})
    };
    this.http = new ControlPlaneHttpClient(httpConfig);
  }

  public static fromEnv(options?: {
    readonly apiKey?: string;
    readonly baseUrl?: string;
    readonly fetchImpl?: typeof fetch;
  }): ReportsClient {
    const apiKey = (options?.apiKey || process.env['CORECHECK_API_KEY'] || '').trim();
    if (!apiKey) {
      throw new ReportsClientError(
        'API key requerida para upload (--api-key o CORECHECK_API_KEY).',
        401,
        'UNAUTHORIZED'
      );
    }
    const baseUrl = resolveReportsApiBaseUrl(options?.baseUrl);
    if (!baseUrl) {
      throw new ReportsClientError(
        'URL de API de reportes requerida (CORECHECK_REPORTS_API_URL, CORECHECK_UPLOAD_URL o CORECHECK_API_URL).',
        undefined,
        'CONFIG'
      );
    }
    return new ReportsClient({
      baseUrl,
      apiKey,
      ...(options?.fetchImpl ? { fetchImpl: options.fetchImpl } : {})
    });
  }

  public async uploadReport(input: CreateReportInput): Promise<UploadedReport> {
    try {
      const report = await this.http.post<UploadedReport>('/api/reports', input);
      if (!report?.id) {
        throw new ReportsClientError(
          'Respuesta 201 sin id de reporte.',
          201,
          'INVALID_RESPONSE'
        );
      }
      return report;
    } catch (error) {
      throw mapError(error);
    }
  }
}

function mapError(error: unknown): ReportsClientError {
  if (error instanceof ReportsClientError) {
    return error;
  }
  if (error instanceof ControlPlaneHttpError) {
    return new ReportsClientError(
      humanize(error),
      error.status,
      error.code,
      error.requestId
    );
  }
  return new ReportsClientError(
    error instanceof Error ? error.message : String(error)
  );
}

function humanize(error: ControlPlaneHttpError): string {
  if (error.status === 401 || error.code === 'UNAUTHORIZED') {
    return `Upload rechazado (401 Auth): ${error.message}`;
  }
  if (error.status === 429 || error.code === 'RATE_LIMITED') {
    return `Upload rate-limited (429): ${error.message}`;
  }
  if (
    error.status === 400 ||
    error.status === 422 ||
    error.code === 'BAD_REQUEST'
  ) {
    return `Upload payload inválido (${error.status ?? 400}): ${error.message}`;
  }
  return error.message;
}
