import {
  AccountStatus,
  AccountStatusResponse,
  LicenseInfo,
  LicenseValidationRequest,
  QuotaRenewalResponse,
  RevokeAccessResponse,
  SubscriptionTier,
  TIER_DEFAULTS,
  UsageTelemetryEvent
} from '../types/license.js';

export interface StoredAccount {
  accountId: string;
  organization: string;
  apiKey: string;
  tier: SubscriptionTier;
  status: AccountStatus;
  expiresAt: string;
  allowedDomains: string[];
  quota: LicenseInfo['quota'];
}

/**
 * Store in-memory del Control Plane (reemplazable por Supabase).
 */
export class ControlPlaneStore {
  private readonly accounts = new Map<string, StoredAccount>();
  private readonly telemetry: UsageTelemetryEvent[] = [];

  constructor() {
    this.seedDemoAccounts();
  }

  public findByApiKey(apiKey: string): StoredAccount | undefined {
    for (const account of this.accounts.values()) {
      if (account.apiKey === apiKey) {
        return account;
      }
    }
    return undefined;
  }

  public getAccount(accountId: string): StoredAccount | undefined {
    return this.accounts.get(accountId);
  }

  public toLicenseInfo(account: StoredAccount): LicenseInfo {
    const entitlements = {
      ...TIER_DEFAULTS[account.tier],
      allowedDomains: account.allowedDomains
    };
    return {
      apiKeyPrefix: account.apiKey.slice(0, 12),
      accountId: account.accountId,
      organization: account.organization,
      tier: account.tier,
      status: account.status,
      entitlements,
      quota: account.quota,
      expiresAt: account.expiresAt,
      issuedAt: new Date().toISOString()
    };
  }

  public validate(request: LicenseValidationRequest): LicenseInfo {
    const account = this.findByApiKey(request.apiKey);
    if (!account) {
      const err = new Error('INVALID_KEY') as Error & { code: string };
      err.code = 'INVALID_KEY';
      throw err;
    }

    if (account.status === 'revoked' || account.status === 'canceled') {
      const err = new Error(account.status.toUpperCase()) as Error & { code: string };
      err.code = 'REVOKED';
      throw err;
    }

    if (account.quota.runsUsed >= account.quota.runsLimit) {
      account.status = 'quota_exceeded';
      const err = new Error('QUOTA_EXCEEDED') as Error & { code: string };
      err.code = 'QUOTA_EXCEEDED';
      throw err;
    }

    // Increment soft usage on successful validation handshake.
    account.quota.runsUsed += 1;
    account.quota.pagesUsed += request.requestedPages;

    return this.toLicenseInfo(account);
  }

  public accountStatus(accountId: string): AccountStatusResponse {
    const account = this.requireAccount(accountId);
    const license = this.toLicenseInfo(account);
    return {
      accountId: account.accountId,
      organization: account.organization,
      status: account.status,
      tier: account.tier,
      quota: account.quota,
      entitlements: license.entitlements,
      expiresAt: account.expiresAt
    };
  }

  public renewQuota(accountId: string): QuotaRenewalResponse {
    const account = this.requireAccount(accountId);
    const tier = TIER_DEFAULTS[account.tier];
    const now = new Date();
    const periodEnd = new Date(now);
    periodEnd.setMonth(periodEnd.getMonth() + 1);

    account.quota = {
      runsUsed: 0,
      runsLimit: tier.maxRunsPerMonth,
      pagesUsed: 0,
      pagesLimit: tier.maxPagesPerRun * tier.maxRunsPerMonth,
      periodStart: now.toISOString(),
      periodEnd: periodEnd.toISOString()
    };
    if (account.status === 'quota_exceeded') {
      account.status = 'active';
    }

    return { accountId, quota: account.quota, renewed: true };
  }

  public revoke(accountId: string, reason?: string): RevokeAccessResponse {
    const account = this.requireAccount(accountId);
    account.status = 'revoked';
    return {
      accountId,
      status: account.status,
      revoked: true,
      reason
    };
  }

  public pushTelemetry(event: UsageTelemetryEvent): void {
    this.telemetry.push(event);
    if (this.telemetry.length > 1000) {
      this.telemetry.shift();
    }
  }

  public listTelemetry(): UsageTelemetryEvent[] {
    return [...this.telemetry];
  }

  private requireAccount(accountId: string): StoredAccount {
    const account = this.accounts.get(accountId);
    if (!account) {
      const err = new Error('ACCOUNT_NOT_FOUND') as Error & { code: string };
      err.code = 'ACCOUNT_NOT_FOUND';
      throw err;
    }
    return account;
  }

  private seedDemoAccounts(): void {
    const now = new Date();
    const periodEnd = new Date(now);
    periodEnd.setMonth(periodEnd.getMonth() + 1);

    const mk = (
      accountId: string,
      organization: string,
      apiKey: string,
      tier: SubscriptionTier,
      domains: string[]
    ): StoredAccount => ({
      accountId,
      organization,
      apiKey,
      tier,
      status: 'active',
      expiresAt: periodEnd.toISOString(),
      allowedDomains: domains,
      quota: {
        runsUsed: 0,
        runsLimit: TIER_DEFAULTS[tier].maxRunsPerMonth,
        pagesUsed: 0,
        pagesLimit:
          TIER_DEFAULTS[tier].maxPagesPerRun * TIER_DEFAULTS[tier].maxRunsPerMonth,
        periodStart: now.toISOString(),
        periodEnd: periodEnd.toISOString()
      }
    });

    const seeds = [
      mk('acc_growth_demo', 'Acme Growth', 'cc_live_growth_demo_key', 'GROWTH', [
        'example.com'
      ]),
      mk(
        'acc_core_demo',
        'Acme Enterprise',
        'cc_live_enterprise_core_demo_key',
        'ENTERPRISE_CORE',
        []
      ),
      mk(
        'acc_gov_demo',
        'Acme Governance',
        'cc_live_enterprise_governance_demo_key',
        'ENTERPRISE_GOVERNANCE',
        []
      )
    ];

    for (const account of seeds) {
      this.accounts.set(account.accountId, account);
    }
  }
}
