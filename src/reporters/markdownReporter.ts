import * as fs from 'node:fs';
import * as path from 'node:path';

import { AuditFinding, AuditReportBundle, SeverityLevel } from '../types/audit.js';

const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function severityIcon(severity: SeverityLevel): string {
  if (severity === 'CRITICAL' || severity === 'HIGH') return '🔴';
  if (severity === 'MEDIUM') return '🟡';
  return '🔵';
}

/**
 * Reporter Markdown orientado a comentarios de PR / Quality Gate en CI.
 * Incluye Digital Quality Score, resumen CVSS y Compliance Gaps del bundle ejecutivo.
 */
export function generateMarkdownReport(bundle: AuditReportBundle, outputPath: string): void {
  const findings = bundle.findings;
  const summary = bundle.severityCounts;
  const gateLabel = bundle.gateFailed ? 'FAIL' : 'PASS';

  const lines: string[] = [
    '## CoreCheck Security Audit Report',
    '',
    `| Campo | Valor |`,
    `| :--- | :--- |`,
    `| Target | \`${bundle.target}\` |`,
    `| Environment | ${bundle.environment ?? 'prod'} |`,
    `| Gate (${bundle.failOn}) | **${gateLabel}** |`,
    `| Digital Quality Score | **${bundle.digitalQualityScore.toFixed(1)}**/100 |`,
    `| Max CVSS | ${bundle.maxCvssScore > 0 ? bundle.maxCvssScore.toFixed(1) : '—'} |`,
    `| Páginas | ${bundle.scannedPages.length} |`,
    `| Compliance-mapped | ${bundle.compliance.mappedFindingCount} |`,
    ...(bundle.suppressedCount
      ? [`| Baseline suppressions | ${bundle.suppressedCount} |`]
      : []),
    '',
    '### Severidad',
    '',
    `| Severidad | Cantidad |`,
    `| :--- | ---: |`,
    ...SEVERITY_ORDER.map(
      (level) => `| ${severityIcon(level)} ${level} | ${summary[level] ?? 0} |`
    ),
    '',
    `**Total de hallazgos:** ${findings.length}`,
    ''
  ];

  if (bundle.dimensions.length > 0) {
    lines.push('### Dimensiones', '');
    lines.push('| Dimensión | Score | Hallazgos |');
    lines.push('| :--- | ---: | ---: |');
    for (const d of bundle.dimensions) {
      lines.push(`| ${d.dimension} | ${d.score.toFixed(0)} | ${d.count} |`);
    }
    lines.push('');
  }

  const cvssTop = findings
    .filter((f) => f.cvss)
    .sort((a, b) => (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0))
    .slice(0, 5);

  lines.push('### Resumen CVSS', '');
  if (cvssTop.length === 0) {
    lines.push('_Sin hallazgos calibrados con CVSS._', '');
  } else {
    lines.push('| Regla | CVSS | Versión | Vector |');
    lines.push('| :--- | ---: | :---: | :--- |');
    for (const f of cvssTop) {
      const c = f.cvss!;
      lines.push(
        `| \`${f.ruleId}\` | ${c.baseScore.toFixed(1)} | ${c.version} | \`${c.vector}\` |`
      );
    }
    lines.push('');
  }

  const gapFrameworks = bundle.compliance.frameworks.filter((fw) => fw.gapCount > 0);
  lines.push('### Compliance Gaps', '');
  if (gapFrameworks.length === 0) {
    lines.push('_Sin gaps de compliance en esta corrida._', '');
  } else {
    lines.push('| Framework | Related | Gaps | Controles (muestra) |');
    lines.push('| :--- | ---: | ---: | :--- |');
    for (const fw of gapFrameworks) {
      const sample = fw.controls
        .filter((c) => c.status === 'GAP' || c.status === 'PARTIAL')
        .slice(0, 4)
        .map((c) => `\`${c.controlId}\``)
        .join(', ');
      lines.push(
        `| ${fw.framework} | ${fw.relatedFindings} | ${fw.gapCount} | ${sample || '—'} |`
      );
    }
    lines.push('');
  }

  if (findings.length === 0) {
    lines.push('✅ No se detectaron hallazgos en esta ejecución.');
  } else {
    lines.push('### Hallazgos', '');
    lines.push('| Severidad | Regla | Título | Ubicación |');
    lines.push('| :--- | :--- | :--- | :--- |');

    for (const finding of findings) {
      const selector = finding.evidence?.selector
        ? `\`${finding.evidence.selector}\``
        : finding.evidence?.locations?.[0]?.selector
          ? `\`${finding.evidence.locations[0].selector}\``
          : 'N/A';
      const safeTitle = finding.title.replace(/\|/g, '\\|');
      const cvssHint = finding.cvss ? ` (CVSS ${finding.cvss.baseScore})` : '';
      lines.push(
        `| ${severityIcon(finding.severity)} ${finding.severity}${cvssHint} | \`${finding.ruleId}\` | ${safeTitle} | ${selector} |`
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

/** @deprecated Prefer generateMarkdownReport(bundle, path). */
export function generateMarkdownReportFromFindings(
  findings: AuditFinding[],
  outputPath: string
): void {
  generateMarkdownReport(
    {
      target: 'unknown',
      timestamp: new Date().toISOString(),
      scannedPages: [],
      findings,
      digitalQualityScore: 0,
      maxCvssScore: 0,
      severityCounts: {
        CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
        HIGH: findings.filter((f) => f.severity === 'HIGH').length,
        MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
        LOW: findings.filter((f) => f.severity === 'LOW').length,
        INFO: findings.filter((f) => f.severity === 'INFO').length
      },
      dimensions: [],
      compliance: { frameworks: [], mappedFindingCount: 0 },
      gateFailed: false,
      failOn: 'HIGH'
    },
    outputPath
  );
}
