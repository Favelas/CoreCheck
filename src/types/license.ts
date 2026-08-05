/** Tiers comerciales CoreCheck SaaS. */
export type SubscriptionTier = 'GROWTH' | 'ENTERPRISE_CORE' | 'ENTERPRISE_GOVERNANCE';

export type AccountStatus =
  | 'active'
  | 'trial'
  | 'past_due'
  | 'canceled'
  | 'revoked'
  | 'quota_exceeded';

export type LicenseModule =
  | 'pdf_report'
  | 'ticketing'
  | 'active_fuzzing'
  | 'compliance_mapping'
  | 'webhooks'
  | 'multi_domain';

export interface TierEntitlements {
  tier: SubscriptionTier;
  maxPagesPerRun: number;
  maxRunsPerMonth: number;
  allowedModules: LicenseModule[];
  /** Vacío = cualquier dominio (Enterprise Governance). */
  allowedDomains: string[];
}

export interface LicenseQuota {
  runsUsed: number;
  runsLimit: number;
  pagesUsed: number;
  pagesLimit: number;
  periodStart: string;
  periodEnd: string;
}

export interface LicenseInfo {
  apiKeyPrefix: string;
  accountId: string;
  organization: string;
  tier: SubscriptionTier;
  status: AccountStatus;
  entitlements: TierEntitlements;
  quota: LicenseQuota;
  expiresAt: string;
  /** Firma offline / cache token (HMAC). */
  signature?: string;
  issuedAt?: string;
}

export type LicenseValidationCode =
  | 'OK'
  | 'MISSING_KEY'
  | 'INVALID_KEY'
  | 'EXPIRED'
  | 'REVOKED'
  | 'PAST_DUE'
  | 'QUOTA_EXCEEDED'
  | 'DOMAIN_NOT_ALLOWED'
  | 'MODULE_NOT_ALLOWED'
  | 'PAGE_LIMIT_EXCEEDED'
  | 'NETWORK_ERROR';

export interface LicenseValidationRequest {
  apiKey: string;
  targetUrl: string;
  requestedPages: number;
  requestedModules: LicenseModule[];
}

export interface LicenseValidationResult {
  ok: boolean;
  code: LicenseValidationCode;
  message: string;
  license?: LicenseInfo;
  /** maxPages efectivo tras aplicar el plan. */
  effectiveMaxPages?: number;
  /** true si se usó cache offline ante fallo de red. */
  offlineFallback?: boolean;
}

/** Telemetría agregada — sin URLs privadas ni snippets de código. */
export interface UsageTelemetryEvent {
  schemaVersion: 1;
  accountId: string;
  tier: SubscriptionTier;
  runId: string;
  /** Solo hostname hasheado o eTLD+1 sanitizado. */
  targetHostHash: string;
  pagesScanned: number;
  durationMs: number;
  findingsBySeverity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  digitalQualityScore?: number;
  gateFailed: boolean;
  environment?: string;
  engineVersion: string;
  timestamp: string;
}

export interface AccountStatusResponse {
  accountId: string;
  organization: string;
  status: AccountStatus;
  tier: SubscriptionTier;
  quota: LicenseQuota;
  entitlements: TierEntitlements;
  expiresAt: string;
}

export interface QuotaRenewalResponse {
  accountId: string;
  quota: LicenseQuota;
  renewed: boolean;
}

export interface RevokeAccessResponse {
  accountId: string;
  status: AccountStatus;
  revoked: boolean;
  reason?: string;
}

export interface SaaSApiConfig {
  /** Base URL del control plane (ej. https://api.corecheck.app). */
  baseUrl: string;
  /** Timeout de red en ms (telemetría/licencia no deben colgar CI). */
  timeoutMs?: number;
  /** API key del cliente (Bearer). */
  apiKey?: string;
}

/** Defaults de entitlements por tier (fuente de verdad comercial). */
export const TIER_DEFAULTS: Record<SubscriptionTier, TierEntitlements> = {
  GROWTH: {
    tier: 'GROWTH',
    maxPagesPerRun: 10,
    maxRunsPerMonth: 50,
    allowedModules: ['compliance_mapping', 'webhooks'],
    allowedDomains: []
  },
  ENTERPRISE_CORE: {
    tier: 'ENTERPRISE_CORE',
    maxPagesPerRun: 50,
    maxRunsPerMonth: 500,
    allowedModules: [
      'pdf_report',
      'compliance_mapping',
      'webhooks',
      'active_fuzzing',
      'multi_domain'
    ],
    allowedDomains: []
  },
  ENTERPRISE_GOVERNANCE: {
    tier: 'ENTERPRISE_GOVERNANCE',
    maxPagesPerRun: 250,
    maxRunsPerMonth: 5000,
    allowedModules: [
      'pdf_report',
      'ticketing',
      'compliance_mapping',
      'webhooks',
      'active_fuzzing',
      'multi_domain'
    ],
    allowedDomains: []
  }
};
