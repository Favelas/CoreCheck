import {
  AuditReportBundle,
  SeverityLevel,
  WebhookNotifyOptions
} from '../types/audit.js';

export interface WebhookNotifyResult {
  ok: boolean;
  status?: number;
  channel: 'slack' | 'teams' | 'generic';
  error?: string;
}

/**
 * Notificador CI/CD para Slack Incoming Webhooks, Microsoft Teams
 * y webhooks genéricos JSON.
 */
export class WebhookNotifier {
  public async notify(options: WebhookNotifyOptions): Promise<WebhookNotifyResult> {
    const channel =
      options.channel ?? this.inferChannel(options.webhookUrl);
    const payload = this.buildPayload(channel, options.bundle);

    try {
      const response = await fetch(options.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const body = await response.text().catch(() => '');
        return {
          ok: false,
          status: response.status,
          channel,
          error: body.slice(0, 500) || response.statusText
        };
      }

      return { ok: true, status: response.status, channel };
    } catch (error) {
      return {
        ok: false,
        channel,
        error: (error as Error).message
      };
    }
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
              text: `Compliance mapped: ${bundle.compliance.mappedFindingCount} · ${bundle.timestamp}`
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
          url: f.evidence.url
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
