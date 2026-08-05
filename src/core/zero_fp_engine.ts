import { Page, Response } from 'playwright';

import { AuditFinding, SeverityLevel } from '../types/audit.js';

const REVALIDATE_SEVERITIES = new Set<SeverityLevel>(['CRITICAL', 'HIGH']);

const ACTIVE_SECURITY_RULES = new Set<string>([
  'SEC-XSS-ACTIVE-INJECTION',
  'SEC-SQLI-SPECIAL-CHARS',
  'SEC-UNHANDLED-EXCEPTION'
]);

/**
 * Motor Zero-FP: segunda pasada pasiva/activa sobre hallazgos críticos
 * para subir confidence a HIGH o descartar falsos positivos.
 */
export class ZeroFPEngine {
  constructor(
    private readonly page: Page,
    private readonly timeoutMs = 15000
  ) {}

  public async revalidate(findings: AuditFinding[]): Promise<AuditFinding[]> {
    const kept: AuditFinding[] = [];
    let confirmed = 0;
    let discarded = 0;
    let skipped = 0;

    for (const finding of findings) {
      if (!this.needsRevalidation(finding)) {
        kept.push({
          ...finding,
          confidence: finding.confidence ?? 'MEDIUM',
          revalidated: false
        });
        skipped++;
        continue;
      }

      const pageUrl = finding.evidence.url;
      if (!pageUrl) {
        kept.push({ ...finding, confidence: 'LOW', revalidated: true });
        continue;
      }

      try {
        const ok = await this.confirmFinding(finding, pageUrl);
        if (ok) {
          kept.push({ ...finding, confidence: 'HIGH', revalidated: true });
          confirmed++;
        } else if (ACTIVE_SECURITY_RULES.has(finding.ruleId)) {
          // Activos no confirmados → descartar (presupuesto Zero-FP).
          discarded++;
          console.log(
            `[ZeroFP] Descartado FP: ${finding.ruleId} @ ${pageUrl} (${finding.evidence.selector ?? 'n/a'})`
          );
        } else {
          kept.push({ ...finding, confidence: 'LOW', revalidated: true });
          discarded++;
          console.log(`[ZeroFP] Confidence LOW: ${finding.ruleId} @ ${pageUrl}`);
        }
      } catch (error) {
        kept.push({ ...finding, confidence: 'LOW', revalidated: true });
        console.warn(
          `[ZeroFP] Re-check falló para ${finding.ruleId}: ${(error as Error).message}`
        );
      }
    }

    console.log(
      `[ZeroFP] Revalidación: ${confirmed} HIGH, ${discarded} LOW/descartados, ${skipped} sin re-check`
    );
    return kept;
  }

  private needsRevalidation(finding: AuditFinding): boolean {
    if (!REVALIDATE_SEVERITIES.has(finding.severity)) {
      return false;
    }
    if (ACTIVE_SECURITY_RULES.has(finding.ruleId)) {
      return true;
    }
    if (finding.ruleId.startsWith('SEC-')) {
      return true;
    }
    return finding.category === 'SECURITY' || finding.ruleType === 'SECURITY_FINDING';
  }

  private async confirmFinding(finding: AuditFinding, pageUrl: string): Promise<boolean> {
    switch (finding.ruleId) {
      case 'SEC-XSS-ACTIVE-INJECTION':
        return this.confirmXss(finding, pageUrl);
      case 'SEC-UNHANDLED-EXCEPTION':
        return this.confirmServer500(finding, pageUrl);
      case 'SEC-SQLI-SPECIAL-CHARS':
        return this.confirmSqliSignal(finding, pageUrl);
      case 'SEC-HDR-CSP-MISSING':
        return this.confirmMissingHeader(pageUrl, 'content-security-policy');
      case 'SEC-HDR-HSTS-MISSING':
        return this.confirmMissingHeader(pageUrl, 'strict-transport-security');
      case 'SEC-HDR-CLICKJACKING':
        return this.confirmClickjacking(pageUrl);
      case 'SEC-HDR-NOSNIFF-MISSING':
        return this.confirmMissingHeader(pageUrl, 'x-content-type-options', 'nosniff');
      default:
        return this.confirmPassiveDomOrNetwork(finding, pageUrl);
    }
  }

  private async navigate(pageUrl: string): Promise<Response | null> {
    return this.page.goto(pageUrl, {
      waitUntil: 'domcontentloaded',
      timeout: this.timeoutMs
    });
  }

  private async confirmXss(finding: AuditFinding, pageUrl: string): Promise<boolean> {
    const selector = finding.evidence.selector;
    const payload = finding.evidence.requestPayload;
    if (!selector || !payload) {
      return false;
    }

    await this.navigate(pageUrl);
    await this.page
      .evaluate(() => {
        (window as unknown as { __corecheck_xss?: boolean }).__corecheck_xss = false;
      })
      .catch(() => {});

    const input = this.page.locator(selector).first();
    if (!(await input.count())) {
      return false;
    }

    await input.fill('').catch(() => {});
    await input.fill(payload).catch(() => false);
    await input.dispatchEvent('input').catch(() => {});
    await input.dispatchEvent('change').catch(() => {});
    await this.page.waitForTimeout(400);

    return this.page
      .evaluate(
        () => (window as unknown as { __corecheck_xss?: boolean }).__corecheck_xss === true
      )
      .catch(() => false);
  }

  private async confirmServer500(finding: AuditFinding, pageUrl: string): Promise<boolean> {
    const selector = finding.evidence.selector;
    const payload = finding.evidence.requestPayload;
    if (!selector || !payload) {
      return finding.evidence.responseStatus !== undefined && finding.evidence.responseStatus >= 500;
    }

    await this.navigate(pageUrl);
    let saw500 = false;
    const onResponse = (response: Response) => {
      if (response.status() >= 500) {
        saw500 = true;
      }
    };
    this.page.on('response', onResponse);

    try {
      const input = this.page.locator(selector).first();
      if (!(await input.count())) {
        return false;
      }
      await input.fill(payload).catch(() => {});
      await input.dispatchEvent('input').catch(() => {});
      await input.press('Tab').catch(() => {});
      await this.page.waitForTimeout(500);
      return saw500;
    } finally {
      this.page.off('response', onResponse);
    }
  }

  private async confirmSqliSignal(finding: AuditFinding, pageUrl: string): Promise<boolean> {
    // SQLi se confirma si el payload sigue reflejado o provoca 5xx / error SQL en DOM.
    const selector = finding.evidence.selector;
    const payload = finding.evidence.requestPayload;
    if (!selector || !payload) {
      return false;
    }

    await this.navigate(pageUrl);
    let saw500 = false;
    const onResponse = (response: Response) => {
      if (response.status() >= 500) {
        saw500 = true;
      }
    };
    this.page.on('response', onResponse);

    try {
      const input = this.page.locator(selector).first();
      if (!(await input.count())) {
        return false;
      }
      await input.fill(payload).catch(() => {});
      await input.dispatchEvent('input').catch(() => {});
      await input.press('Tab').catch(() => {});
      await this.page.waitForTimeout(400);

      const bodyText = await this.page.locator('body').innerText().catch(() => '');
      const sqlError =
        /sql syntax|mysql|sqlite|postgresql|ora-\d+|unclosed quotation|odbc/i.test(bodyText);
      const reflected = bodyText.includes(payload.trim());
      return saw500 || sqlError || reflected;
    } finally {
      this.page.off('response', onResponse);
    }
  }

  private async confirmMissingHeader(
    pageUrl: string,
    headerName: string,
    expectedValue?: string
  ): Promise<boolean> {
    const response = await this.navigate(pageUrl);
    if (!response) {
      return false;
    }
    const headers = response.headers();
    const value = headers[headerName.toLowerCase()];
    if (!value) {
      return true;
    }
    if (expectedValue) {
      return !value.toLowerCase().includes(expectedValue.toLowerCase());
    }
    return false;
  }

  private async confirmClickjacking(pageUrl: string): Promise<boolean> {
    const response = await this.navigate(pageUrl);
    if (!response) {
      return false;
    }
    const headers = response.headers();
    const xfo = headers['x-frame-options'];
    const csp = headers['content-security-policy'] ?? '';
    const hasFrameAncestors = /frame-ancestors/i.test(csp);
    return !xfo && !hasFrameAncestors;
  }

  private async confirmPassiveDomOrNetwork(
    finding: AuditFinding,
    pageUrl: string
  ): Promise<boolean> {
    await this.navigate(pageUrl);

    if (finding.evidence.selector) {
      const count = await this.page.locator(finding.evidence.selector).count().catch(() => 0);
      if (count > 0) {
        return true;
      }
    }

    if (finding.evidence.snippet) {
      const html = await this.page.content().catch(() => '');
      const needle = finding.evidence.snippet.slice(0, 120);
      if (needle && html.includes(needle)) {
        return true;
      }
    }

    // Hallazgos solo de cabecera/red sin selector: conservar evidencia original como MEDIUM→no confirmado estricto.
    return false;
  }
}
