import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import { AuditFinding, AuditReportBundle, SeverityLevel } from '../types/audit.js';

function mapSeverityToSarifLevel(severity: SeverityLevel): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
    default:
      return 'note';
  }
}

function mapSeverityToSecuritySeverity(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'info';
  }
}

function buildTags(finding: AuditFinding): string[] {
  const tags = new Set<string>();
  tags.add('corecheck');
  if (finding.category) tags.add(finding.category.toLowerCase());
  if (finding.ruleType) tags.add(finding.ruleType.toLowerCase());
  for (const t of finding.standards.owasp ?? []) tags.add(t);
  for (const t of finding.standards.wcag ?? []) tags.add(t);
  for (const t of finding.standards.cwe ?? []) tags.add(t);
  for (const t of finding.standards.iso27001 ?? []) tags.add(`iso27001/${t}`);
  for (const t of finding.standards.soc2 ?? []) tags.add(`soc2/${t}`);
  for (const t of finding.standards.pciDss ?? []) tags.add(`pci-dss/${t}`);
  for (const t of finding.standards.ada ?? []) tags.add(`ada/${t}`);
  for (const t of finding.standards.en301549 ?? []) tags.add(`en301549/${t}`);
  return [...tags];
}

function buildHelpMarkdown(finding: AuditFinding): string {
  const standards: string[] = [];
  if (finding.standards.owasp?.length) {
    standards.push(`* **OWASP:** ${finding.standards.owasp.join(', ')}`);
  }
  if (finding.standards.wcag?.length) {
    standards.push(`* **WCAG:** ${finding.standards.wcag.join(', ')}`);
  }
  if (finding.standards.cwe?.length) {
    standards.push(`* **CWE:** ${finding.standards.cwe.join(', ')}`);
  }
  if (finding.standards.iso27001?.length) {
    standards.push(`* **ISO 27001:** ${finding.standards.iso27001.join(', ')}`);
  }
  if (finding.standards.soc2?.length) {
    standards.push(`* **SOC 2:** ${finding.standards.soc2.join(', ')}`);
  }
  if (finding.standards.pciDss?.length) {
    standards.push(`* **PCI-DSS:** ${finding.standards.pciDss.join(', ')}`);
  }
  if (finding.standards.ada?.length) {
    standards.push(`* **ADA:** ${finding.standards.ada.join(', ')}`);
  }
  if (finding.standards.en301549?.length) {
    standards.push(`* **EN 301 549:** ${finding.standards.en301549.join(', ')}`);
  }
  if (finding.cvss) {
    standards.push(
      `* **CVSS ${finding.cvss.version}:** ${finding.cvss.baseScore} (\`${finding.cvss.vector}\`)`
    );
  }

  return [
    `### Remediation`,
    finding.remediation.explanation,
    '',
    '### Standards / Compliance',
    standards.length > 0 ? standards.join('\n') : '_No mapped standards_',
    finding.remediation.codeAfter
      ? `\n### Suggested fix\n\`\`\`\n${finding.remediation.codeAfter}\n\`\`\``
      : ''
  ]
    .filter(Boolean)
    .join('\n');
}

function buildLocations(finding: AuditFinding): Array<Record<string, unknown>> {
  const primaryUri =
    finding.evidence.url ||
    (finding.evidence.selector ? `dom://${finding.evidence.selector}` : 'about:blank');

  const locations: Array<Record<string, unknown>> = [
    {
      physicalLocation: {
        artifactLocation: {
          uri: primaryUri,
          uriBaseId: finding.evidence.url ? '%SRCROOT%' : undefined
        },
        region: {
          startLine: 1,
          snippet: {
            text: (finding.evidence.snippet || finding.title).slice(0, 2048)
          }
        }
      },
      logicalLocations: finding.evidence.selector
        ? [
            {
              fullyQualifiedName: finding.evidence.selector,
              kind: 'element'
            }
          ]
        : undefined
    }
  ];

  for (const loc of finding.evidence.locations ?? []) {
    if (!loc.url && !loc.selector) continue;
    locations.push({
      physicalLocation: {
        artifactLocation: {
          uri: loc.url || primaryUri
        },
        region: {
          startLine: 1,
          snippet: {
            text: (loc.snippet || '').slice(0, 512)
          }
        }
      },
      logicalLocations: loc.selector
        ? [{ fullyQualifiedName: loc.selector, kind: 'element' }]
        : undefined
    });
  }

  return locations;
}

export interface SarifExportOptions {
  findings: AuditFinding[];
  outputPath: string;
  bundle?: AuditReportBundle;
}

/**
 * Exportador SARIF 2.1.0 enriquecido para GitHub Code Scanning
 * y GitLab Security Dashboards (security-severity + compliance tags).
 */
export async function exportToSarif(
  findings: AuditFinding[],
  outputPath: string,
  bundle?: AuditReportBundle
): Promise<void> {
  const uniqueRuleIds = Array.from(new Set(findings.map((f) => f.ruleId)));

  const rules = uniqueRuleIds.map((ruleId) => {
    const finding = findings.find((f) => f.ruleId === ruleId)!;
    return {
      id: ruleId,
      name: finding.title.replace(/\s+/g, ''),
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description },
      helpUri: 'https://github.com/corecheck/engine',
      help: {
        text: `${finding.remediation.explanation}`,
        markdown: buildHelpMarkdown(finding)
      },
      defaultConfiguration: {
        level: mapSeverityToSarifLevel(finding.severity)
      },
      properties: {
        tags: buildTags(finding),
        precision: finding.confidence === 'HIGH' ? 'very-high' : 'high',
        'security-severity': mapSeverityToSecuritySeverity(finding.severity),
        problem: {
          severity: mapSeverityToSecuritySeverity(finding.severity)
        }
      }
    };
  });

  const sarifLog = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tccs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CoreCheck DevSecOps Engine',
            version: '3.0.0-enterprise',
            informationUri: 'https://github.com/corecheck/engine',
            rules
          }
        },
        invocations: [
          {
            executionSuccessful: !(bundle?.gateFailed ?? false),
            endTimeUtc: bundle?.timestamp ?? new Date().toISOString()
          }
        ],
        results: findings.map((finding) => {
          const ruleIndex = uniqueRuleIds.indexOf(finding.ruleId);
          return {
            ruleId: finding.ruleId,
            ruleIndex: ruleIndex >= 0 ? ruleIndex : 0,
            level: mapSeverityToSarifLevel(finding.severity),
            message: {
              text: `${finding.title}: ${finding.description}`
            },
            locations: buildLocations(finding),
            partialFingerprints: {
              primaryLocationLineHash: `${finding.ruleId}|${finding.evidence.url ?? ''}|${finding.evidence.selector ?? ''}`
            },
            properties: {
              category: finding.category,
              ruleType: finding.ruleType,
              confidence: finding.confidence,
              revalidated: finding.revalidated ?? false,
              'security-severity': mapSeverityToSecuritySeverity(finding.severity),
              cvss: finding.cvss,
              evidence: finding.evidence,
              remediation: finding.remediation,
              compliance: {
                iso27001: finding.standards.iso27001 ?? [],
                soc2: finding.standards.soc2 ?? [],
                pciDss: finding.standards.pciDss ?? [],
                wcag: finding.standards.wcag ?? [],
                ada: finding.standards.ada ?? [],
                en301549: finding.standards.en301549 ?? [],
                owasp: finding.standards.owasp ?? [],
                cwe: finding.standards.cwe ?? []
              }
            }
          };
        }),
        properties: bundle
          ? {
              digitalQualityScore: bundle.digitalQualityScore,
              maxCvssScore: bundle.maxCvssScore,
              severityCounts: bundle.severityCounts,
              dimensions: bundle.dimensions,
              compliance: bundle.compliance,
              gateFailed: bundle.gateFailed,
              failOn: bundle.failOn,
              environment: bundle.environment,
              suppressedCount: bundle.suppressedCount,
              scannedPages: bundle.scannedPages,
              attestation: bundle.attestation
                ? {
                    attestationHash: bundle.attestation.attestationHash,
                    auditHash: bundle.attestation.auditHash,
                    algorithm: bundle.attestation.algorithm,
                    hmacSignature: bundle.attestation.hmacSignature ?? null,
                    cliVersion: bundle.attestation.cliVersion,
                    signedAtUtc: bundle.attestation.signedAtUtc,
                    verificationUrl: bundle.attestation.verificationUrl,
                    dashboardUrl: bundle.attestation.dashboardUrl
                  }
                : undefined
            }
          : undefined
      }
    ]
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(sarifLog, null, 2), 'utf-8');
}
