import * as fs from 'node:fs';
import * as path from 'node:path';
import { AuditFinding, SeverityLevel } from '../types/audit.js';

const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function severityIcon(severity: SeverityLevel): string {
  if (severity === 'CRITICAL' || severity === 'HIGH') return '🔴';
  if (severity === 'MEDIUM') return '🟡';
  return '🔵';
}

/**
 * Reporter Markdown orientado a comentarios de PR / Quality Gate en CI.
 * Mantiene el contenido compacto para no saturar el diff del Pull Request.
 */
export function generateMarkdownReport(findings: AuditFinding[], outputPath: string): void {
  const summary = Object.fromEntries(
    SEVERITY_ORDER.map((level) => [level, findings.filter((f) => f.severity === level).length])
  ) as Record<SeverityLevel, number>;

  const lines: string[] = [
    '## CoreCheck Security Audit Report',
    '',
    `| Severidad | Cantidad |`,
    `| :--- | ---: |`,
    ...SEVERITY_ORDER.map((level) => `| ${severityIcon(level)} ${level} | ${summary[level]} |`),
    '',
    `**Total de hallazgos:** ${findings.length}`,
    ''
  ];

  if (findings.length === 0) {
    lines.push('✅ No se detectaron hallazgos en esta ejecución.');
  } else {
    lines.push('| Severidad | Regla | Título | Ubicación |');
    lines.push('| :--- | :--- | :--- | :--- |');

    for (const finding of findings) {
      const selector = finding.evidence?.selector
        ? `\`${finding.evidence.selector}\``
        : finding.evidence?.locations?.[0]?.selector
          ? `\`${finding.evidence.locations[0].selector}\``
          : 'N/A';
      const safeTitle = finding.title.replace(/\|/g, '\\|');
      lines.push(
        `| ${severityIcon(finding.severity)} ${finding.severity} | \`${finding.ruleId}\` | ${safeTitle} | ${selector} |`
      );
    }

    lines.push('', '### Remediación prioritaria', '');

    const priorityFindings = findings
      .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      .slice(0, 10);

    if (priorityFindings.length === 0) {
      lines.push('_No hay hallazgos CRITICAL/HIGH en esta corrida._');
    } else {
      for (const finding of priorityFindings) {
        lines.push(`#### \`${finding.ruleId}\` — ${finding.title}`);
        lines.push('');
        lines.push(finding.remediation.explanation);
        if (finding.remediation.codeAfter) {
          lines.push('');
          lines.push('```');
          lines.push(finding.remediation.codeAfter);
          lines.push('```');
        }
        lines.push('');
      }
    }
  }

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(outputPath, `${lines.join('\n')}\n`, 'utf-8');
}
