import type { AuditReportBundle } from '../types/audit.js';
import { buildCreateReportInput } from './report_payload.js';
import { ReportsClient, ReportsClientError } from './reports_client.js';

export interface UploadAuditReportOptions {
  readonly enabled: boolean;
  /** Si true, propaga el error (caller puede mapear a exit NETWORK). Default soft. */
  readonly strict?: boolean;
  readonly apiKey?: string;
  readonly baseUrl?: string;
  readonly bundle: AuditReportBundle;
  readonly client?: ReportsClient;
  readonly log?: (message: string) => void;
  readonly warn?: (message: string) => void;
}

export interface UploadAuditReportResult {
  readonly attempted: boolean;
  readonly uploaded: boolean;
  readonly reportId?: string;
  readonly accountId?: string;
  readonly contentHash?: string;
  readonly error?: string;
  readonly status?: number;
  readonly code?: string;
}

/**
 * Orquestación Slice 1: upload opcional post-audit (testeable sin Playwright).
 */
export async function maybeUploadAuditReport(
  options: UploadAuditReportOptions
): Promise<UploadAuditReportResult> {
  const log = options.log ?? console.log;
  const warn = options.warn ?? console.warn;

  if (!options.enabled) {
    return { attempted: false, uploaded: false };
  }

  try {
    const client =
      options.client ??
      ReportsClient.fromEnv({
        ...(options.apiKey !== undefined ? { apiKey: options.apiKey } : {}),
        ...(options.baseUrl !== undefined ? { baseUrl: options.baseUrl } : {})
      });

    const payload = buildCreateReportInput(options.bundle);
    const report = await client.uploadReport(payload);

    log(
      `[Upload] Reporte publicado · id=${report.id} · account=${report.accountId} · hash=${report.contentHash.slice(0, 12)}…`
    );
    return {
      attempted: true,
      uploaded: true,
      reportId: report.id,
      accountId: report.accountId,
      contentHash: report.contentHash
    };
  } catch (error) {
    const mapped =
      error instanceof ReportsClientError
        ? error
        : new ReportsClientError(
            error instanceof Error ? error.message : String(error)
          );
    const message = mapped.message;
    warn(`[Upload] Fallo al publicar reporte: ${message}`);

    if (options.strict) {
      throw mapped;
    }

    return {
      attempted: true,
      uploaded: false,
      error: message,
      ...(mapped.status !== undefined ? { status: mapped.status } : {}),
      ...(mapped.code !== undefined ? { code: mapped.code } : {})
    };
  }
}
