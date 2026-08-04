import * as fs from 'node:fs';
import * as path from 'node:path';
import { AuditFinding } from '../types/audit.js';

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function generateHtmlReport(findings: AuditFinding[], outputPath: string): void {
  const summary = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: findings.filter(f => f.severity === 'INFO').length,
  };

  const rowsHtml = findings.map(f => `
    <tr class="severity-${f.severity.toLowerCase()}">
      <td><strong>${escapeHtml(f.severity)}</strong></td>
      <td>${escapeHtml(f.ruleId)}</td>
      <td>
        <strong>${escapeHtml(f.title)}</strong><br/>
        <small>${escapeHtml(f.description)}</small>
      </td>
      <td>
        ${f.evidence?.selector ? `<code>${escapeHtml(f.evidence.selector)}</code><br/>` : ''}
        ${f.evidence?.snippet ? `<pre><code>${escapeHtml(f.evidence.snippet)}</code></pre>` : ''}
        ${f.evidence?.artifactPath ? `<small>Artefacto: <em>${escapeHtml(f.evidence.artifactPath)}</em></small>` : ''}
      </td>
      <td>
        <p>${escapeHtml(f.remediation.explanation)}</p>
        ${f.remediation.codeAfter ? `<pre><code>${escapeHtml(f.remediation.codeAfter)}</code></pre>` : ''}
      </td>
    </tr>
  `).join('');

  const htmlContent = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Reporte de Auditoría de Seguridad</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #f8f9fa; color: #212529; }
    h1 { border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }
    .summary-box { display: flex; gap: 15px; margin-bottom: 20px; }
    .badge { padding: 8px 12px; border-radius: 4px; font-weight: bold; color: #fff; }
    .bg-critical { background-color: #d9534f; }
    .bg-high { background-color: #f0ad4e; }
    .bg-medium { background-color: #0275d8; }
    .bg-low { background-color: #5bc0de; }
    .bg-info { background-color: #6c757d; }
    table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    th, td { padding: 12px; border: 1px solid #dee2e6; text-align: left; vertical-align: top; }
    th { background: #e9ecef; }
    pre { background: #272822; color: #f8f8f2; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
    code { font-family: monospace; background: #e9ecef; padding: 2px 4px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>Resultado de Auditoría Automática</h1>
  <div class="summary-box">
    <div class="badge bg-critical">CRITICAL: ${summary.CRITICAL}</div>
    <div class="badge bg-high">HIGH: ${summary.HIGH}</div>
    <div class="badge bg-medium">MEDIUM: ${summary.MEDIUM}</div>
    <div class="badge bg-low">LOW: ${summary.LOW}</div>
    <div class="badge bg-info">INFO: ${summary.INFO}</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severidad</th>
        <th>Regla</th>
        <th>Detalle</th>
        <th>Evidencia</th>
        <th>Remediación</th>
      </tr>
    </thead>
    <tbody>
      ${rowsHtml || '<tr><td colspan="5">No se detectaron hallazgos.</td></tr>'}
    </tbody>
  </table>
</body>
</html>`;

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(outputPath, htmlContent, 'utf-8');
}