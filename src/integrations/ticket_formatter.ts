import { AuditFinding, TicketPayload, TicketProvider } from '../types/audit.js';

export interface TicketContext {
  projectKey?: string;
  areaPath?: string;
  gitlabProjectId?: string | number;
  labels?: string[];
  assignee?: string;
}

/**
 * Generadores de payloads listos para APIs de ticketing (sin side-effects HTTP).
 * El caller/CI decide autenticación y POST.
 */
export class TicketFormatter {
  public format(
    provider: TicketProvider,
    finding: AuditFinding,
    context: TicketContext = {}
  ): TicketPayload {
    switch (provider) {
      case 'jira':
        return this.toJira(finding, context);
      case 'azure_boards':
        return this.toAzureBoards(finding, context);
      case 'gitlab':
        return this.toGitLab(finding, context);
      default: {
        const _exhaustive: never = provider;
        throw new Error(`Unsupported ticket provider: ${_exhaustive}`);
      }
    }
  }

  public formatBatch(
    provider: TicketProvider,
    findings: AuditFinding[],
    context: TicketContext = {}
  ): TicketPayload[] {
    return findings.map((f) => this.format(provider, f, context));
  }

  private toJira(finding: AuditFinding, context: TicketContext): TicketPayload {
    const projectKey = context.projectKey ?? 'SEC';
    const labels = [
      'corecheck',
      finding.severity.toLowerCase(),
      ...(finding.category ? [finding.category.toLowerCase()] : []),
      ...(context.labels ?? [])
    ];

    return {
      provider: 'jira',
      method: 'POST',
      path: '/rest/api/3/issue',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: {
        fields: {
          project: { key: projectKey },
          summary: `[CoreCheck][${finding.severity}] ${finding.title}`.slice(0, 255),
          description: {
            type: 'doc',
            version: 1,
            content: [
              {
                type: 'paragraph',
                content: [{ type: 'text', text: finding.description }]
              },
              {
                type: 'paragraph',
                content: [
                  {
                    type: 'text',
                    text: `Rule: ${finding.ruleId}`
                  }
                ]
              },
              {
                type: 'paragraph',
                content: [
                  {
                    type: 'text',
                    text: `URL: ${finding.evidence.url ?? 'n/a'} | Selector: ${finding.evidence.selector ?? 'n/a'}`
                  }
                ]
              },
              {
                type: 'paragraph',
                content: [
                  {
                    type: 'text',
                    text: `Remediation: ${finding.remediation.explanation}`
                  }
                ]
              },
              ...(finding.cvss
                ? [
                    {
                      type: 'paragraph' as const,
                      content: [
                        {
                          type: 'text' as const,
                          text: `CVSS ${finding.cvss.version}: ${finding.cvss.baseScore} (${finding.cvss.vector})`
                        }
                      ]
                    }
                  ]
                : [])
            ]
          },
          issuetype: { name: 'Bug' },
          labels,
          priority: {
            name: this.jiraPriority(finding.severity)
          }
        }
      }
    };
  }

  private toAzureBoards(finding: AuditFinding, context: TicketContext): TicketPayload {
    const areaPath = context.areaPath ?? 'Security';
    return {
      provider: 'azure_boards',
      method: 'POST',
      path: '/_apis/wit/workitems/$Bug?api-version=7.1',
      headers: {
        'Content-Type': 'application/json-patch+json'
      },
      body: {
        operations: [
          {
            op: 'add',
            path: '/fields/System.Title',
            value: `[CoreCheck][${finding.severity}] ${finding.title}`.slice(0, 255)
          },
          {
            op: 'add',
            path: '/fields/System.Description',
            value: this.htmlDescription(finding)
          },
          {
            op: 'add',
            path: '/fields/Microsoft.VSTS.Common.Priority',
            value: this.azurePriority(finding.severity)
          },
          {
            op: 'add',
            path: '/fields/System.AreaPath',
            value: areaPath
          },
          {
            op: 'add',
            path: '/fields/System.Tags',
            value: ['corecheck', finding.severity, finding.ruleId]
              .concat(context.labels ?? [])
              .join('; ')
          }
        ]
      }
    };
  }

  private toGitLab(finding: AuditFinding, context: TicketContext): TicketPayload {
    const projectId = context.gitlabProjectId ?? ':id';
    const labels = [
      'corecheck',
      finding.severity.toLowerCase(),
      finding.ruleId,
      ...(context.labels ?? [])
    ].join(',');

    return {
      provider: 'gitlab',
      method: 'POST',
      path: `/api/v4/projects/${encodeURIComponent(String(projectId))}/issues`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: {
        title: `[CoreCheck][${finding.severity}] ${finding.title}`.slice(0, 255),
        description: this.markdownDescription(finding),
        labels,
        ...(context.assignee ? { assignee_id: context.assignee } : {}),
        confidential: finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
      }
    };
  }

  private htmlDescription(finding: AuditFinding): string {
    const parts = [
      `<p><b>${this.escape(finding.description)}</b></p>`,
      `<p>Rule: <code>${this.escape(finding.ruleId)}</code></p>`,
      `<p>URL: ${this.escape(finding.evidence.url ?? 'n/a')}<br/>Selector: <code>${this.escape(finding.evidence.selector ?? 'n/a')}</code></p>`,
      finding.evidence.snippet
        ? `<pre>${this.escape(finding.evidence.snippet.slice(0, 1024))}</pre>`
        : '',
      `<p><b>Remediation:</b> ${this.escape(finding.remediation.explanation)}</p>`,
      finding.cvss
        ? `<p>CVSS ${finding.cvss.version}: ${finding.cvss.baseScore} — <code>${this.escape(finding.cvss.vector)}</code></p>`
        : ''
    ];
    return parts.filter(Boolean).join('\n');
  }

  private markdownDescription(finding: AuditFinding): string {
    return [
      finding.description,
      '',
      `**Rule:** \`${finding.ruleId}\``,
      `**URL:** ${finding.evidence.url ?? 'n/a'}`,
      `**Selector:** \`${finding.evidence.selector ?? 'n/a'}\``,
      finding.evidence.snippet
        ? `\n\`\`\`\n${finding.evidence.snippet.slice(0, 1024)}\n\`\`\``
        : '',
      '',
      `**Remediation:** ${finding.remediation.explanation}`,
      finding.cvss
        ? `**CVSS ${finding.cvss.version}:** ${finding.cvss.baseScore} (\`${finding.cvss.vector}\`)`
        : '',
      finding.standards.iso27001?.length
        ? `**ISO 27001:** ${finding.standards.iso27001.join(', ')}`
        : ''
    ]
      .filter(Boolean)
      .join('\n');
  }

  private jiraPriority(severity: AuditFinding['severity']): string {
    switch (severity) {
      case 'CRITICAL':
        return 'Highest';
      case 'HIGH':
        return 'High';
      case 'MEDIUM':
        return 'Medium';
      case 'LOW':
        return 'Low';
      default:
        return 'Lowest';
    }
  }

  private azurePriority(severity: AuditFinding['severity']): number {
    switch (severity) {
      case 'CRITICAL':
        return 1;
      case 'HIGH':
        return 2;
      case 'MEDIUM':
        return 3;
      default:
        return 4;
    }
  }

  private escape(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}

export function buildTicketPayloads(
  provider: TicketProvider,
  findings: AuditFinding[],
  context?: TicketContext
): TicketPayload[] {
  return new TicketFormatter().formatBatch(provider, findings, context);
}
