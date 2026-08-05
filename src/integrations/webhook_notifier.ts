import { createHmac } from 'node:crypto';

import {
  AuditReportBundle,
  SeverityLevel,
  WebhookNotifyOptions
} from '../types/audit.js';

export interface WebhookNotifyResult {
  ok: boolean;
  status?: number;
  channel: 'slack' | 'teams' | 'generic';
  dryRun?: boolean;
  signed?: boolean;
  error?: string;
}

/**
 * Notificador CI/CD para Slack Incoming Webhooks, Microsoft Teams
 * y webhooks genéricos JSON (Zapier/n8n) con firma HMAC opcional.
 */
export class WebhookNotifier {
  public async notify(options: WebhookNotifyOptions): Promise<WebhookNotifyResult> {
    const channel = options.channel ?? this.inferChannel(options.webhookUrl);
    const secret =
      options.signingSecret?.trim() ||
      process.env.CORECHECK_WEBHOOK_SECRET?.trim() ||
      '';
    const dryRun = options.dryRun === true;

    const payload = this.buildPayload(channel, options.bundle);
    const body = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'CoreCheck-Webhook/1.0',
      'X-CoreCheck-Timestamp': timestamp,
      'X-CoreCheck-Event': String(payload.event ?? 'corecheck_audit')
    };

    let signed = false;
    if (secret) {
      headers['X-CoreCheck-Signature'] = `sha256=${this.signPayload(secret, timestamp, body)}`;
      signed = true;
    }

    if (dryRun) {
      return { ok: true, channel, dryRun: true, signed };
    }

    try {
      const response = await fetch(options.webhookUrl, {
        method: 'POST',
        headers,
        body
      });

      if (!response.ok) {
        const errBody = await response.text().catch(() => '');
        return {
          ok: false,
          status: response.status,
          channel,
          signed,
          error: errBody.slice(0, 500) || response.statusText
        };
      }

      return { ok: true, status: response.status, channel, signed };
    } catch (error) {
      return {
        ok: false,
        channel,
        signed,
        error: (error as Error).message
      };
    }
  }

  /** HMAC-SHA256(timestamp + '.' + body) — compatible con Zapier/n8n verify. */
  public signPayload(secret: string, timestamp: string, body: string): string {
    return createHmac('sha256', secret)
      .update(`${timestamp}.${body}`, 'utf8')
      .digest('hex');
  }

  public inferChannel(webhookUrl: string): 'slack' | 'teams' | 'generic' {
    const url = webhookUrl.toLowerCase();
    if (url.includes('hooks.slack.com')) {
      return 'slack';
    }
    if (url.includes('webhook.office.com') || url.includes('logic.azure.com')) {
      return 'teams';
    }
    return 'generic';
  }

  public buildPayload(
    channel: 'slack' | 'teams' | 'generic',
    bundle: AuditReportBundle
  ): Record<string, unknown> {
    switch (channel) {
      case 'slack':
        return this.buildSlackPayload(bundle);
      case 'teams':
        return this.buildTeamsPayload(bundle);
      default:
        return this.buildGenericPayload(bundle);
    }
  }

  private buildSlackPayload(bundle: AuditReportBundle): Record<string, unknown> {
    const gateEmoji = bundle.gateFailed ? ':x:' : ':white_check_mark:';
    const sevLine = this.severityLine(bundle);
    const dimLine = bundle.dimensions
      .map((d) => `${d.dimension}:${d.score}`)
      .join(' · ');

    return {
      event: bundle.gateFailed ? 'quality_gate_failed' : 'quality_gate_passed',
      text: `CoreCheck ${bundle.gateFailed ? 'GATE FAIL' : 'GATE PASS'} — ${bundle.target}`,
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `CoreCheck Audit ${bundle.gateFailed ? 'FAILED' : 'PASSED'}`
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Target*\n${bundle.target}` },
            {
              type: 'mrkdwn',
              text: `*Score*\n${bundle.digitalQualityScore}/100`
            },
            {
              type: 'mrkdwn',
              text: `*Gate (${bundle.failOn})*\n${gateEmoji} ${bundle.gateFailed ? 'FAIL' : 'PASS'}`
            },
            {
              type: 'mrkdwn',
              text: `*Findings*\n${bundle.findings.length}`
            }
          ]
        },
        {
          type: 'section',
          text: { type: 'mrkdwn', text: `*Severity*\n${sevLine}` }
        },
        {
          type: 'section',
          text: { type: 'mrkdwn', text: `*Dimensions*\n${dimLine}` }
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              text:
                `Compliance mapped: ${bundle.compliance.mappedFindingCount} · ${bundle.timestamp}` +
                (bundle.attestation
                  ? ` · Hash ${bundle.attestation.attestationHash.slice(0, 12)}`
                  : '')
            }
          ]
        }
      ]
    };
  }

  private buildTeamsPayload(bundle: AuditReportBundle): Record<string, unknown> {
    const themeColor = bundle.gateFailed ? 'B91C1C' : '15803D';
    const facts = [
      { name: 'Target', value: bundle.target },
      { name: 'Digital Quality Score', value: String(bundle.digitalQualityScore) },
      {
        name: `Quality Gate (${bundle.failOn})`,
        value: bundle.gateFailed ? 'FAIL' : 'PASS'
      },
      { name: 'Total findings', value: String(bundle.findings.length) },
      { name: 'Severity', value: this.severityLine(bundle) }
    ];

    if (bundle.attestation?.attestationHash) {
      facts.push({
        name: 'Attestation Hash',
        value: bundle.attestation.attestationHash.slice(0, 32) + '…'
      });
    }

    for (const dim of bundle.dimensions) {
      facts.push({
        name: dim.dimension,
        value: `score ${dim.score} · ${dim.count} findings`
      });
    }

    return {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor,
      summary: `CoreCheck ${bundle.gateFailed ? 'GATE FAIL' : 'GATE PASS'}`,
      title: `CoreCheck Audit — ${bundle.gateFailed ? 'GATE FAIL' : 'GATE PASS'}`,
      sections: [
        {
          activityTitle: bundle.target,
          activitySubtitle: bundle.timestamp,
          facts
        }
      ]
    };
  }

  private buildGenericPayload(bundle: AuditReportBundle): Record<string, unknown> {
    return {
      source: 'corecheck',
      event: bundle.gateFailed ? 'quality_gate_failed' : 'quality_gate_passed',
      target: bundle.target,
      timestamp: bundle.timestamp,
      digitalQualityScore: bundle.digitalQualityScore,
      gateFailed: bundle.gateFailed,
      failOn: bundle.failOn,
      findingsTotal: bundle.findings.length,
      severityCounts: bundle.severityCounts,
      attestationHash: bundle.attestation?.attestationHash ?? null,
      dimensions: bundle.dimensions.map((d) => ({
        dimension: d.dimension,
        score: d.score,
        count: d.count
      })),
      compliance: {
        mappedFindingCount: bundle.compliance.mappedFindingCount,
        frameworks: bundle.compliance.frameworks.map((f) => ({
          framework: f.framework,
          gapCount: f.gapCount,
          relatedFindings: f.relatedFindings
        }))
      },
      topFindings: bundle.findings
        .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
        .slice(0, 10)
        .map((f) => ({
          ruleId: f.ruleId,
          severity: f.severity,
          title: f.title,
          url: f.evidence.url,
          evidence: f.evidence.snippet?.slice(0, 512)
        }))
    };
  }

  private severityLine(bundle: AuditReportBundle): string {
    const order: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    return order
      .map((s) => `${s}=${bundle.severityCounts[s] ?? 0}`)
      .join(' · ');
  }
}

export async function notifyWebhook(
  options: WebhookNotifyOptions
): Promise<WebhookNotifyResult> {
  return new WebhookNotifier().notify(options);
}
