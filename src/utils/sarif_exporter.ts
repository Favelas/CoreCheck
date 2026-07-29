import * as fs from 'fs/promises';
import * as path from 'path';
import { AuditFinding, SeverityLevel } from '../types/audit';

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

export async function exportToSarif(findings: AuditFinding[], outputPath: string): Promise<void> {
  const sarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tccs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CoreCheck DevSecOps Engine',
            version: '2.0.0-enterprise',
            informationUri: 'https://github.com/corecheck/engine',
            rules: Array.from(new Set(findings.map((f) => f.ruleId))).map((ruleId) => {
              const finding = findings.find((f) => f.ruleId === ruleId)!;
              return {
                id: ruleId,
                name: finding.title,
                shortDescription: { text: finding.title },
                fullDescription: { text: finding.description },
                help: {
                  text: `${finding.remediation.explanation}\n\nOWASP: ${finding.standards.owasp?.join(', ') || 'N/A'}\nWCAG: ${finding.standards.wcag?.join(', ') || 'N/A'}`,
                  markdown: `### Remediation\n${finding.remediation.explanation}\n\n**Standards:**\n* **OWASP:** ${finding.standards.owasp?.join(', ') || 'N/A'}\n* **WCAG:** ${finding.standards.wcag?.join(', ') || 'N/A'}`
                },
                properties: {
                  tags: [...(finding.standards.owasp || []), ...(finding.standards.wcag || [])],
                  precision: 'high'
                }
              };
            })
          }
        },
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: mapSeverityToSarifLevel(finding.severity),
          message: {
            text: `${finding.title}: ${finding.description}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.evidence.selector ? `DOM://${finding.evidence.selector}` : 'DOM://unknown'
                },
                region: {
                  snippet: {
                    text: finding.evidence.snippet || ''
                  }
                }
              }
            }
          ],
          properties: {
            evidence: finding.evidence,
            remediation: finding.remediation
          }
        }))
      }
    ]
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(sarifLog, null, 2), 'utf-8');
}