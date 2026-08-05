import { AuditFinding, TicketPayload, TicketProvider } from '../types/audit.js';
import { TicketContext, TicketFormatter } from './ticket_formatter.js';

export interface JiraCredentials {
  /** Ej. https://your-domain.atlassian.net (sin slash final). */
  domain: string;
  email: string;
  apiToken: string;
  projectKey: string;
  issueType?: string;
}

export interface AzureDevOpsCredentials {
  organization: string;
  project: string;
  pat: string;
  areaPath?: string;
}

export interface GitLabCredentials {
  baseUrl: string;
  token: string;
  projectId: string | number;
}

export interface TicketSubmitOptions {
  provider: TicketProvider;
  findings: AuditFinding[];
  context?: TicketContext;
  /**
   * dry-run=true (default): no HTTP; solo construye payloads.
   * dry-run=false: POST real si hay credenciales.
   */
  dryRun?: boolean;
  jira?: Partial<JiraCredentials>;
  azure?: Partial<AzureDevOpsCredentials>;
  gitlab?: Partial<GitLabCredentials>;
  /** Timeout por request (ms). */
  timeoutMs?: number;
}

export interface TicketSubmitItemResult {
  ok: boolean;
  dryRun: boolean;
  provider: TicketProvider;
  ruleId: string;
  findingId: string;
  status?: number;
  issueKey?: string;
  issueUrl?: string;
  error?: string;
  payload: TicketPayload;
}

export interface TicketSubmitResult {
  dryRun: boolean;
  provider: TicketProvider;
  submitted: number;
  failed: number;
  skipped: number;
  results: TicketSubmitItemResult[];
}

/**
 * Cliente HTTP de ticketing: Jira Cloud v3, Azure Boards, GitLab.
 * Sin credenciales → siempre dry-run (seguro por defecto).
 */
export class TicketClient {
  private readonly formatter = new TicketFormatter();

  public resolveJiraFromEnv(overrides?: Partial<JiraCredentials>): JiraCredentials | undefined {
    const domain = (
      overrides?.domain ||
      process.env.JIRA_DOMAIN ||
      process.env.JIRA_BASE_URL ||
      ''
    )
      .trim()
      .replace(/\/+$/, '');
    const email = (overrides?.email || process.env.JIRA_EMAIL || '').trim();
    const apiToken = (
      overrides?.apiToken ||
      process.env.JIRA_API_TOKEN ||
      process.env.JIRA_TOKEN ||
      ''
    ).trim();
    const projectKey = (
      overrides?.projectKey ||
      process.env.JIRA_PROJECT_KEY ||
      ''
    ).trim();

    if (!domain || !email || !apiToken || !projectKey) {
      return undefined;
    }

    return {
      domain: domain.startsWith('http') ? domain : `https://${domain}`,
      email,
      apiToken,
      projectKey,
      issueType: overrides?.issueType || process.env.JIRA_ISSUE_TYPE || 'Bug'
    };
  }

  public resolveAzureFromEnv(
    overrides?: Partial<AzureDevOpsCredentials>
  ): AzureDevOpsCredentials | undefined {
    const organization = (
      overrides?.organization ||
      process.env.AZURE_DEVOPS_ORG ||
      process.env.AZURE_ORG ||
      ''
    ).trim();
    const project = (
      overrides?.project ||
      process.env.AZURE_DEVOPS_PROJECT ||
      process.env.AZURE_PROJECT ||
      ''
    ).trim();
    const pat = (
      overrides?.pat ||
      process.env.AZURE_DEVOPS_PAT ||
      process.env.AZURE_PAT ||
      ''
    ).trim();

    if (!organization || !project || !pat) {
      return undefined;
    }

    return {
      organization,
      project,
      pat,
      areaPath:
        overrides?.areaPath ||
        process.env.AZURE_DEVOPS_AREA_PATH ||
        process.env.AZURE_AREA_PATH
    };
  }

  public resolveGitLabFromEnv(
    overrides?: Partial<GitLabCredentials>
  ): GitLabCredentials | undefined {
    const baseUrl = (
      overrides?.baseUrl ||
      process.env.GITLAB_BASE_URL ||
      'https://gitlab.com'
    )
      .trim()
      .replace(/\/+$/, '');
    const token = (
      overrides?.token ||
      process.env.GITLAB_TOKEN ||
      process.env.GITLAB_API_TOKEN ||
      ''
    ).trim();
    const projectId = (
      overrides?.projectId ??
      process.env.GITLAB_PROJECT_ID ??
      ''
    )
      .toString()
      .trim();

    if (!token || !projectId) {
      return undefined;
    }

    return { baseUrl, token, projectId };
  }

  public canSubmit(provider: TicketProvider, options: TicketSubmitOptions): boolean {
    switch (provider) {
      case 'jira':
        return Boolean(this.resolveJiraFromEnv(options.jira));
      case 'azure_boards':
        return Boolean(this.resolveAzureFromEnv(options.azure));
      case 'gitlab':
        return Boolean(this.resolveGitLabFromEnv(options.gitlab));
      default:
        return false;
    }
  }

  public async submit(options: TicketSubmitOptions): Promise<TicketSubmitResult> {
    const provider = options.provider;
    const context: TicketContext = { ...(options.context ?? {}) };
    const dryRunRequested = options.dryRun !== false; // default true
    const hasCreds = this.canSubmit(provider, options);
    const dryRun = dryRunRequested || !hasCreds;

    // Enrich context from credentials when submitting.
    if (!dryRun) {
      if (provider === 'jira') {
        const jira = this.resolveJiraFromEnv(options.jira)!;
        context.projectKey = context.projectKey ?? jira.projectKey;
      } else if (provider === 'azure_boards') {
        const azure = this.resolveAzureFromEnv(options.azure)!;
        context.areaPath = context.areaPath ?? azure.areaPath ?? azure.project;
      } else if (provider === 'gitlab') {
        const gitlab = this.resolveGitLabFromEnv(options.gitlab)!;
        context.gitlabProjectId = context.gitlabProjectId ?? gitlab.projectId;
      }
    }

    const payloads = this.formatter.formatBatch(provider, options.findings, context);
    const results: TicketSubmitItemResult[] = [];

    for (let i = 0; i < options.findings.length; i++) {
      const finding = options.findings[i];
      const payload = payloads[i];

      if (dryRun) {
        results.push({
          ok: true,
          dryRun: true,
          provider,
          ruleId: finding.ruleId,
          findingId: finding.id,
          payload,
          issueKey: undefined,
          error: hasCreds
            ? 'dry-run: HTTP no ejecutado (--ticket-submit para enviar)'
            : 'dry-run: credenciales no configuradas'
        });
        continue;
      }

      try {
        const sent = await this.postPayload(provider, payload, options);
        results.push({
          ok: sent.ok,
          dryRun: false,
          provider,
          ruleId: finding.ruleId,
          findingId: finding.id,
          status: sent.status,
          issueKey: sent.issueKey,
          issueUrl: sent.issueUrl,
          error: sent.error,
          payload
        });
      } catch (error) {
        results.push({
          ok: false,
          dryRun: false,
          provider,
          ruleId: finding.ruleId,
          findingId: finding.id,
          error: (error as Error).message,
          payload
        });
      }
    }

    return {
      dryRun,
      provider,
      submitted: results.filter((r) => r.ok && !r.dryRun).length,
      failed: results.filter((r) => !r.ok && !r.dryRun).length,
      skipped: results.filter((r) => r.dryRun).length,
      results
    };
  }

  private async postPayload(
    provider: TicketProvider,
    payload: TicketPayload,
    options: TicketSubmitOptions
  ): Promise<{
    ok: boolean;
    status?: number;
    issueKey?: string;
    issueUrl?: string;
    error?: string;
  }> {
    const timeoutMs = options.timeoutMs ?? 15000;

    if (provider === 'jira') {
      const jira = this.resolveJiraFromEnv(options.jira)!;
      const url = `${jira.domain}${payload.path}`;
      const auth = Buffer.from(`${jira.email}:${jira.apiToken}`).toString('base64');

      // Override issue type if configured.
      const body = structuredClone(payload.body) as {
        fields?: { issuetype?: { name?: string }; project?: { key?: string } };
      };
      if (body.fields) {
        body.fields.project = { key: jira.projectKey };
        body.fields.issuetype = { name: jira.issueType ?? 'Bug' };
      }

      const response = await this.fetchWithTimeout(
        url,
        {
          method: 'POST',
          headers: {
            ...payload.headers,
            Authorization: `Basic ${auth}`
          },
          body: JSON.stringify(body)
        },
        timeoutMs
      );

      const text = await response.text().catch(() => '');
      let parsed: { key?: string; id?: string; self?: string } = {};
      try {
        parsed = JSON.parse(text) as typeof parsed;
      } catch {
        /* non-json */
      }

      if (!response.ok) {
        return {
          ok: false,
          status: response.status,
          error: text.slice(0, 800) || response.statusText
        };
      }

      const issueKey = parsed.key;
      const issueUrl = issueKey
        ? `${jira.domain}/browse/${issueKey}`
        : parsed.self;

      return { ok: true, status: response.status, issueKey, issueUrl };
    }

    if (provider === 'azure_boards') {
      const azure = this.resolveAzureFromEnv(options.azure)!;
      const url =
        `https://dev.azure.com/${encodeURIComponent(azure.organization)}/` +
        `${encodeURIComponent(azure.project)}${payload.path}`;
      const auth = Buffer.from(`:${azure.pat}`).toString('base64');

      // Azure expects a JSON Patch array, not { operations: [...] }.
      const ops =
        (payload.body as { operations?: unknown[] }).operations ?? payload.body;

      const response = await this.fetchWithTimeout(
        url,
        {
          method: 'POST',
          headers: {
            ...payload.headers,
            Authorization: `Basic ${auth}`
          },
          body: JSON.stringify(ops)
        },
        timeoutMs
      );

      const text = await response.text().catch(() => '');
      let parsed: { id?: number; url?: string; _links?: { html?: { href?: string } } } =
        {};
      try {
        parsed = JSON.parse(text) as typeof parsed;
      } catch {
        /* ignore */
      }

      if (!response.ok) {
        return {
          ok: false,
          status: response.status,
          error: text.slice(0, 800) || response.statusText
        };
      }

      return {
        ok: true,
        status: response.status,
        issueKey: parsed.id !== undefined ? String(parsed.id) : undefined,
        issueUrl: parsed._links?.html?.href ?? parsed.url
      };
    }

    // gitlab
    const gitlab = this.resolveGitLabFromEnv(options.gitlab)!;
    const projectId = encodeURIComponent(String(gitlab.projectId));
    const url = `${gitlab.baseUrl}/api/v4/projects/${projectId}/issues`;

    const response = await this.fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: {
          ...payload.headers,
          'PRIVATE-TOKEN': gitlab.token
        },
        body: JSON.stringify(payload.body)
      },
      timeoutMs
    );

    const text = await response.text().catch(() => '');
    let parsed: { iid?: number; web_url?: string } = {};
    try {
      parsed = JSON.parse(text) as typeof parsed;
    } catch {
      /* ignore */
    }

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: text.slice(0, 800) || response.statusText
      };
    }

    return {
      ok: true,
      status: response.status,
      issueKey: parsed.iid !== undefined ? String(parsed.iid) : undefined,
      issueUrl: parsed.web_url
    };
  }

  private async fetchWithTimeout(
    url: string,
    init: RequestInit,
    timeoutMs: number
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }
}

export async function submitTickets(
  options: TicketSubmitOptions
): Promise<TicketSubmitResult> {
  return new TicketClient().submit(options);
}
