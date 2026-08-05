import { createHash, randomUUID } from 'node:crypto';

import { SaaSApiClient } from './api_client.js';
import {
  LicenseInfo,
  UsageTelemetryEvent
} from '../types/license.js';
import { AuditReportBundle, SeverityLevel } from '../types/audit.js';

const ENGINE_VERSION = '4.0.0-saas';

/**
 * Telemetría de uso asíncrona y privacy-preserving.
 * Nunca bloquea ni rompe el pipeline CI si el backend no responde.
 */
export class UsageTelemetry {
  private readonly apiClient: SaaSApiClient | null;
  private readonly enabled: boolean;

  constructor(options?: { apiBaseUrl?: string; timeoutMs?: number; enabled?: boolean }) {
    const disabled =
      options?.enabled === false ||
      process.env.CORECHECK_TELEMETRY === '0' ||
      process.env.CORECHECK_TELEMETRY === 'false';

    this.enabled = !disabled;
    const baseUrl =
      options?.apiBaseUrl ??
      process.env.CORECHECK_API_URL ??
      'https://api.corecheck.app';

    this.apiClient =
      this.enabled && baseUrl
        ? new SaaSApiClient({
            baseUrl,
            timeoutMs: options?.timeoutMs ?? 2500
          })
        : null;
  }

  /**
   * Dispara el envío en background (fire-and-forget con timeout).
   * Retorna inmediatamente; errores solo se loguean a nivel warn.
   */
  public reportAsync(input: {
    license: LicenseInfo;
    targetUrl: string;
    pagesScanned: number;
    durationMs: number;
    bundle: AuditReportBundle;
  }): void {
    if (!this.enabled || !this.apiClient) {
      return;
    }

    const event = this.buildEvent(input);
    void this.sendSafe(event);
  }

  /** Útil para tests: construye el payload sin enviarlo. */
  public buildEvent(input: {
    license: LicenseInfo;
    targetUrl: string;
    pagesScanned: number;
    durationMs: number;
    bundle: AuditReportBundle;
  }): UsageTelemetryEvent {
    const severityCounts = { ...input.bundle.severityCounts } as Record<
      SeverityLevel,
      number
    >;

    return {
      schemaVersion: 1,
      accountId: input.license.accountId,
      tier: input.license.tier,
      runId: randomUUID(),
      targetHostHash: this.hashHost(input.targetUrl),
      pagesScanned: input.pagesScanned,
      durationMs: Math.max(0, Math.round(input.durationMs)),
      findingsBySeverity: {
        CRITICAL: severityCounts.CRITICAL ?? 0,
        HIGH: severityCounts.HIGH ?? 0,
        MEDIUM: severityCounts.MEDIUM ?? 0,
        LOW: severityCounts.LOW ?? 0,
        INFO: severityCounts.INFO ?? 0
      },
      digitalQualityScore: input.bundle.digitalQualityScore,
      gateFailed: input.bundle.gateFailed,
      environment: input.bundle.environment,
      engineVersion: ENGINE_VERSION,
      timestamp: new Date().toISOString()
    };
  }

  private async sendSafe(event: UsageTelemetryEvent): Promise<void> {
    try {
      await this.apiClient!.sendTelemetry(event);
      console.log('[Telemetry] Uso registrado en control plane.');
    } catch (error) {
      console.warn(
        `[Telemetry] Envío omitido (no bloquea CI): ${(error as Error).message}`
      );
    }
  }

  /** Solo hash del hostname — sin paths, query ni credenciales. */
  private hashHost(targetUrl: string): string {
    let host = 'unknown';
    try {
      host = new URL(targetUrl).hostname.toLowerCase();
    } catch {
      host = 'invalid';
    }
    return createHash('sha256').update(host).digest('hex').slice(0, 16);
  }
}
