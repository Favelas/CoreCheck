import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { homedir } from 'node:os';

import { SaaSApiClient, SaaSApiError } from './api_client.js';
import {
  LicenseInfo,
  LicenseModule,
  LicenseValidationCode,
  LicenseValidationRequest,
  LicenseValidationResult,
  SubscriptionTier,
  TIER_DEFAULTS
} from '../types/license.js';

const CACHE_DIR = path.join(homedir(), '.corecheck');
const CACHE_FILE = path.join(CACHE_DIR, 'license-cache.json');

interface LicenseCacheFile {
  version: 1;
  licenses: Record<string, LicenseInfo>;
}

/**
 * Validación remota + fallback offline firmado (HMAC) de API Keys comerciales.
 */
export class LicenseValidator {
  private readonly apiClient: SaaSApiClient | null;
  private readonly offlineSecret: string;

  constructor(options?: {
    apiBaseUrl?: string;
    timeoutMs?: number;
    offlineSecret?: string;
  }) {
    const baseUrl =
      options?.apiBaseUrl ??
      process.env.CORECHECK_API_URL ??
      'https://api.corecheck.app';
    this.offlineSecret =
      options?.offlineSecret ??
      process.env.CORECHECK_LICENSE_SECRET ??
      'corecheck-dev-offline-secret';

    this.apiClient = baseUrl
      ? new SaaSApiClient({
          baseUrl,
          timeoutMs: options?.timeoutMs ?? 4000
        })
      : null;
  }

  public static resolveApiKey(cliKey?: string): string | undefined {
    const key = (cliKey || process.env.CORECHECK_API_KEY || '').trim();
    return key.length > 0 ? key : undefined;
  }

  public async validate(
    request: LicenseValidationRequest
  ): Promise<LicenseValidationResult> {
    if (!request.apiKey) {
      return this.fail('MISSING_KEY', 'API Key requerida (--api-key o CORECHECK_API_KEY).');
    }

    // Dev/local keys for CI without remote control plane.
    if (request.apiKey.startsWith('cc_dev_')) {
      return this.validateDevKey(request);
    }

    let license: LicenseInfo | undefined;
    let offlineFallback = false;

    try {
      if (!this.apiClient) {
        throw new SaaSApiError('SaaS API client not configured');
      }
      license = await this.apiClient.validateLicense(request);
      await this.writeCache(request.apiKey, license);
    } catch (error) {
      const cached = await this.readCache(request.apiKey);
      if (cached && this.verifyOfflineSignature(cached)) {
        license = cached;
        offlineFallback = true;
        console.warn(
          `[License] Validación remota falló (${(error as Error).message}); usando cache offline firmado.`
        );
      } else {
        return this.fail(
          'NETWORK_ERROR',
          `No se pudo validar la licencia y no hay cache offline válido: ${(error as Error).message}`
        );
      }
    }

    return this.evaluateLicense(license, request, offlineFallback);
  }

  public assertModuleAllowed(
    license: LicenseInfo,
    module: LicenseModule
  ): LicenseValidationResult {
    if (!license.entitlements.allowedModules.includes(module)) {
      return this.fail(
        'MODULE_NOT_ALLOWED',
        `El módulo '${module}' no está incluido en el plan ${license.tier}.`,
        license
      );
    }
    return {
      ok: true,
      code: 'OK',
      message: 'Module allowed',
      license,
      effectiveMaxPages: license.entitlements.maxPagesPerRun
    };
  }

  private evaluateLicense(
    license: LicenseInfo,
    request: LicenseValidationRequest,
    offlineFallback: boolean
  ): LicenseValidationResult {
    if (license.status === 'revoked' || license.status === 'canceled') {
      return this.fail('REVOKED', `Cuenta ${license.status}. Contacte a ventas.`, license);
    }
    if (license.status === 'past_due') {
      return this.fail(
        'PAST_DUE',
        'Suscripción morosa. Renueve el pago para continuar.',
        license
      );
    }
    if (license.status === 'quota_exceeded') {
      return this.fail(
        'QUOTA_EXCEEDED',
        'Cuota mensual agotada. Espere renovación o actualice de plan.',
        license
      );
    }

    const expires = Date.parse(license.expiresAt);
    if (!Number.isNaN(expires) && expires < Date.now()) {
      return this.fail('EXPIRED', `Licencia expiró el ${license.expiresAt}.`, license);
    }

    if (license.quota.runsUsed >= license.quota.runsLimit) {
      return this.fail(
        'QUOTA_EXCEEDED',
        `Cuota de ejecuciones agotada (${license.quota.runsUsed}/${license.quota.runsLimit}).`,
        license
      );
    }

    const host = this.extractHost(request.targetUrl);
    const allowed = license.entitlements.allowedDomains;
    if (allowed.length > 0 && host) {
      const okDomain = allowed.some(
        (d) => host === d || host.endsWith(`.${d}`) || d === '*'
      );
      if (!okDomain) {
        return this.fail(
          'DOMAIN_NOT_ALLOWED',
          `Dominio '${host}' no autorizado para esta API Key.`,
          license
        );
      }
    }

    const maxPages = license.entitlements.maxPagesPerRun;
    if (request.requestedPages > maxPages) {
      return this.fail(
        'PAGE_LIMIT_EXCEEDED',
        `Plan ${license.tier} permite máx. ${maxPages} páginas/run (solicitó ${request.requestedPages}).`,
        license,
        maxPages
      );
    }

    for (const mod of request.requestedModules) {
      if (!license.entitlements.allowedModules.includes(mod)) {
        return this.fail(
          'MODULE_NOT_ALLOWED',
          `Módulo '${mod}' no incluido en plan ${license.tier}.`,
          license,
          maxPages
        );
      }
    }

    return {
      ok: true,
      code: 'OK',
      message: offlineFallback
        ? 'Licencia válida (offline cache).'
        : 'Licencia válida.',
      license,
      effectiveMaxPages: maxPages,
      offlineFallback
    };
  }

  private validateDevKey(request: LicenseValidationRequest): LicenseValidationResult {
    const tier = this.parseDevTier(request.apiKey);
    const entitlements = { ...TIER_DEFAULTS[tier] };
    // cc_dev_growth:example.com,app.example.com
    const domainPart = request.apiKey.split(':')[1];
    if (domainPart) {
      entitlements.allowedDomains = domainPart.split(',').map((d) => d.trim()).filter(Boolean);
    }

    const now = new Date();
    const periodEnd = new Date(now);
    periodEnd.setMonth(periodEnd.getMonth() + 1);

    const license: LicenseInfo = {
      apiKeyPrefix: request.apiKey.slice(0, 12),
      accountId: `dev-${tier.toLowerCase()}`,
      organization: 'CoreCheck Dev',
      tier,
      status: 'active',
      entitlements,
      quota: {
        runsUsed: 0,
        runsLimit: entitlements.maxRunsPerMonth,
        pagesUsed: 0,
        pagesLimit: entitlements.maxPagesPerRun * entitlements.maxRunsPerMonth,
        periodStart: now.toISOString(),
        periodEnd: periodEnd.toISOString()
      },
      expiresAt: periodEnd.toISOString(),
      issuedAt: now.toISOString()
    };
    license.signature = this.signLicense(license);

    return this.evaluateLicense(license, request, false);
  }

  private parseDevTier(apiKey: string): SubscriptionTier {
    const lower = apiKey.toLowerCase();
    if (lower.includes('governance')) return 'ENTERPRISE_GOVERNANCE';
    if (lower.includes('enterprise') || lower.includes('core')) return 'ENTERPRISE_CORE';
    return 'GROWTH';
  }

  public signLicense(license: LicenseInfo): string {
    const payload = this.canonicalPayload(license);
    return createHmac('sha256', this.offlineSecret).update(payload).digest('hex');
  }

  public verifyOfflineSignature(license: LicenseInfo): boolean {
    if (!license.signature) return false;
    const expected = this.signLicense({ ...license, signature: undefined });
    try {
      const a = Buffer.from(expected, 'hex');
      const b = Buffer.from(license.signature, 'hex');
      if (a.length !== b.length) return false;
      return timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  private canonicalPayload(license: LicenseInfo): string {
    return JSON.stringify({
      accountId: license.accountId,
      tier: license.tier,
      status: license.status,
      expiresAt: license.expiresAt,
      entitlements: license.entitlements,
      quota: license.quota
    });
  }

  private async readCache(apiKey: string): Promise<LicenseInfo | undefined> {
    try {
      const raw = await fs.readFile(CACHE_FILE, 'utf-8');
      const parsed = JSON.parse(raw) as LicenseCacheFile;
      const keyHash = this.hashKey(apiKey);
      return parsed.licenses[keyHash];
    } catch {
      return undefined;
    }
  }

  private async writeCache(apiKey: string, license: LicenseInfo): Promise<void> {
    try {
      await fs.mkdir(CACHE_DIR, { recursive: true });
      let store: LicenseCacheFile = { version: 1, licenses: {} };
      try {
        store = JSON.parse(await fs.readFile(CACHE_FILE, 'utf-8')) as LicenseCacheFile;
      } catch {
        // fresh
      }
      const signed = { ...license, signature: this.signLicense(license) };
      store.licenses[this.hashKey(apiKey)] = signed;
      await fs.writeFile(CACHE_FILE, JSON.stringify(store, null, 2), 'utf-8');
    } catch {
      // cache best-effort
    }
  }

  private hashKey(apiKey: string): string {
    return createHash('sha256').update(apiKey).digest('hex').slice(0, 32);
  }

  private extractHost(url: string): string | null {
    try {
      return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
    } catch {
      return null;
    }
  }

  private fail(
    code: LicenseValidationCode,
    message: string,
    license?: LicenseInfo,
    effectiveMaxPages?: number
  ): LicenseValidationResult {
    return {
      ok: false,
      code,
      message,
      license,
      effectiveMaxPages
    };
  }
}
