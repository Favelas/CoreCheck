import * as fs from 'node:fs';
import * as path from 'node:path';

import { formatAffectedPages } from '../core/finding_consolidator.js';
import { AuditFinding, AuditReportBundle, SeverityLevel } from '../types/audit.js';

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function affectedPagesHtml(finding: AuditFinding): string {
  const urls = [
    ...new Set(
      [
        ...(finding.evidence.locations?.map((l) => l.url).filter(Boolean) as string[]),
        ...(finding.evidence.url ? [finding.evidence.url] : [])
      ].filter(Boolean)
    )
  ];
  if (urls.length <= 1) {
    return finding.evidence?.url
      ? `<div><a href="${escapeHtml(finding.evidence.url)}">${escapeHtml(finding.evidence.url)}</a></div>`
      : '';
  }

  const summary = escapeHtml(formatAffectedPages(finding));
  const items = urls
    .map((u) => {
      let label = u;
      try {
        const parsed = new URL(u);
        label = parsed.pathname + parsed.search || '/';
      } catch {
        /* keep full */
      }
      return `<li><a href="${escapeHtml(u)}">${escapeHtml(label)}</a></li>`;
    })
    .join('');

  return `<details class="affected-pages" open>
    <summary>${summary}</summary>
    <ul>${items}</ul>
  </details>`;
}

/**
 * Reporter HTML ejecutivo: Digital Quality Score, CVSS, Compliance Gaps + tabla de hallazgos.
 * Hallazgos site-level consolidan URLs afectadas en un bloque colapsable.
 */
export function generateHtmlReport(bundle: AuditReportBundle, outputPath: string): void {
  const findings = bundle.findings;
  const summary = bundle.severityCounts;

  const gapFrameworks = bundle.compliance.frameworks.filter((fw) => fw.gapCount > 0);
  const cvssFindings = findings
    .filter((f) => f.cvss)
    .sort((a, b) => (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0))
    .slice(0, 5);

  const dimensionsHtml = bundle.dimensions
    .map(
      (d) => `
      <div class="dim-card">
        <div class="dim-name">${escapeHtml(d.dimension)}</div>
        <div class="dim-score">${d.score.toFixed(0)}</div>
        <div class="dim-meta">${d.count} hallazgo(s)</div>
      </div>`
    )
    .join('');

  const complianceHtml =
    gapFrameworks.length === 0
      ? '<p class="ok">Sin gaps de compliance detectados en esta corrida.</p>'
      : `<table class="compact">
        <thead><tr><th>Framework</th><th>Related</th><th>Gaps</th><th>Controles</th></tr></thead>
        <tbody>
          ${gapFrameworks
            .map((fw) => {
              const gapControls = fw.controls
                .filter((c) => c.status === 'GAP' || c.status === 'PARTIAL')
                .slice(0, 6)
                .map((c) => `${escapeHtml(c.controlId)} (${c.status})`)
                .join(', ');
              return `<tr>
                <td><strong>${escapeHtml(fw.framework)}</strong></td>
                <td>${fw.relatedFindings}</td>
                <td class="gap">${fw.gapCount}</td>
                <td><small>${gapControls || '—'}</small></td>
              </tr>`;
            })
            .join('')}
        </tbody>
      </table>`;

  const cvssHtml =
    cvssFindings.length === 0
      ? '<p class="muted">Sin hallazgos calibrados con CVSS en esta corrida.</p>'
      : `<ul class="cvss-list">
          ${cvssFindings
            .map((f) => {
              const score = f.cvss!;
              return `<li>
                <strong>[${escapeHtml(f.severity)}]</strong>
                <code>${escapeHtml(f.ruleId)}</code>
                — CVSS ${score.baseScore.toFixed(1)} (${escapeHtml(score.version)})
                <br/><small>${escapeHtml(score.vector)}</small>
                <br/>${escapeHtml(f.title)}
              </li>`;
            })
            .join('')}
        </ul>`;

  const rowsHtml = findings
    .map((f) => {
      const multiPage =
        (f.evidence.locations?.filter((l) => l.url).length ?? 0) > 1 ||
        (f.id.startsWith('SITE-') && (f.evidence.locations?.length ?? 0) > 0);
      const snippetForDisplay =
        multiPage && f.evidence.snippet?.startsWith('Affected pages')
          ? ''
          : f.evidence?.snippet
            ? `<pre><code>${escapeHtml(f.evidence.snippet)}</code></pre>`
            : '';

      return `
    <tr class="severity-${f.severity.toLowerCase()}">
      <td><strong>${escapeHtml(f.severity)}</strong>
        ${f.cvss ? `<br/><small>CVSS ${f.cvss.baseScore.toFixed(1)}</small>` : ''}
      </td>
      <td>${escapeHtml(f.ruleId)}
        ${f.category ? `<br/><small>${escapeHtml(f.category)}</small>` : ''}
        ${multiPage ? `<br/><span class="scope-badge">SITE</span>` : ''}
      </td>
      <td>
        <strong>${escapeHtml(f.title)}</strong><br/>
        <small>${escapeHtml(f.description)}</small>
      </td>
      <td>
        ${affectedPagesHtml(f)}
        ${f.evidence?.selector ? `<code>${escapeHtml(f.evidence.selector)}</code><br/>` : ''}
        ${snippetForDisplay}
        ${f.evidence?.artifactPath ? `<small>Artefacto: <em>${escapeHtml(f.evidence.artifactPath)}</em></small>` : ''}
      </td>
      <td>
        <p>${escapeHtml(f.remediation.explanation)}</p>
        ${f.remediation.codeAfter ? `<pre><code>${escapeHtml(f.remediation.codeAfter)}</code></pre>` : ''}
      </td>
    </tr>`;
    })
    .join('');

  const gateClass = bundle.gateFailed ? 'gate-fail' : 'gate-pass';
  const gateLabel = bundle.gateFailed ? 'FAIL' : 'PASS';

  const htmlContent = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>CoreCheck — Reporte Ejecutivo</title>
  ${
    bundle.attestation
      ? `<meta name="corecheck-attestation-hash" content="${escapeHtml(bundle.attestation.attestationHash)}" />
  <meta name="corecheck-attestation-alg" content="${escapeHtml(bundle.attestation.algorithm)}" />
  <meta name="corecheck-cli-version" content="${escapeHtml(bundle.attestation.cliVersion)}" />`
      : ''
  }
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }
    h1, h2 { margin: 0 0 12px; }
    h2 { margin-top: 28px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-size: 1.1rem; }
    .meta { color: #475569; font-size: 0.9rem; margin-bottom: 16px; }
    .hero { display: flex; flex-wrap: wrap; gap: 16px; align-items: stretch; margin-bottom: 20px; }
    .score-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px 20px; min-width: 180px; }
    .score-value { font-size: 2.4rem; font-weight: 700; line-height: 1; }
    .score-label { color: #64748b; font-size: 0.8rem; margin-top: 4px; }
    .${gateClass} { font-weight: 700; }
    .gate-pass { color: #15803d; }
    .gate-fail { color: #b91c1c; }
    .summary-box { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0 20px; }
    .badge { padding: 8px 12px; border-radius: 4px; font-weight: bold; color: #fff; font-size: 0.85rem; }
    .bg-critical { background-color: #dc2626; }
    .bg-high { background-color: #ea580c; }
    .bg-medium { background-color: #2563eb; }
    .bg-low { background-color: #0891b2; }
    .bg-info { background-color: #64748b; }
    .dims { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 10px; margin-bottom: 8px; }
    .dim-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; text-align: center; }
    .dim-name { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; }
    .dim-score { font-size: 1.4rem; font-weight: 700; }
    .dim-meta { font-size: 0.75rem; color: #94a3b8; }
    table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.06); margin-top: 8px; }
    th, td { padding: 10px 12px; border: 1px solid #e2e8f0; text-align: left; vertical-align: top; }
    th { background: #f1f5f9; font-size: 0.85rem; }
    table.compact td, table.compact th { font-size: 0.85rem; }
    .gap { color: #b91c1c; font-weight: 600; }
    .ok { color: #15803d; }
    .muted { color: #64748b; }
    .cvss-list { margin: 0; padding-left: 18px; }
    .cvss-list li { margin-bottom: 10px; }
    pre { background: #0f172a; color: #e2e8f0; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 12px; max-width: 420px; }
    code { font-family: ui-monospace, monospace; background: #e2e8f0; padding: 1px 4px; border-radius: 3px; font-size: 0.85em; }
    .scope-badge { display: inline-block; background: #0ea5e9; color: #fff; font-size: 0.65rem; font-weight: 700; padding: 2px 6px; border-radius: 3px; letter-spacing: 0.04em; }
    details.affected-pages { margin: 4px 0 8px; font-size: 0.8rem; }
    details.affected-pages summary { cursor: pointer; color: #0369a1; font-weight: 600; }
    details.affected-pages ul { margin: 6px 0 0; padding-left: 18px; }
    details.affected-pages a { color: #0369a1; word-break: break-all; }
  </style>
</head>
<body>
  <h1 id="attestation">CoreCheck — Reporte Ejecutivo</h1>
  <div class="meta">
    <div><strong>Target:</strong> ${escapeHtml(bundle.target)}</div>
    <div><strong>Generado:</strong> ${escapeHtml(bundle.timestamp)}</div>
    ${
      bundle.attestation
        ? `<div><strong>Attestation Hash:</strong> <code>${escapeHtml(bundle.attestation.attestationHash)}</code></div>
    <div><strong>Algorithm:</strong> ${escapeHtml(bundle.attestation.algorithm)}
      · <strong>CLI:</strong> v${escapeHtml(bundle.attestation.cliVersion)}
      · <strong>Signed (UTC):</strong> ${escapeHtml(bundle.attestation.signedAtUtc)}</div>
    ${
      bundle.attestation.hmacSignature
        ? `<div><strong>HMAC:</strong> <code>${escapeHtml(bundle.attestation.hmacSignature)}</code></div>`
        : ''
    }
    <div><strong>License:</strong> ${escapeHtml(bundle.attestation.licenseTier ?? 'N/A')}
      ${bundle.attestation.organization ? ` · ${escapeHtml(bundle.attestation.organization)}` : ''}</div>`
        : ''
    }
    <div><strong>Páginas:</strong> ${bundle.scannedPages.length}
      · <strong>Entorno:</strong> ${escapeHtml(bundle.environment ?? 'prod')}
      · <strong>Gate (${escapeHtml(bundle.failOn)}):</strong> <span class="${gateClass}">${gateLabel}</span>
      ${bundle.suppressedCount ? ` · <strong>Suppressions:</strong> ${bundle.suppressedCount}` : ''}
    </div>
    <div class="muted">Contadores de severidad = vulnerabilidades únicas (site-level deduplicado).</div>
  </div>

  <div class="hero">
    <div class="score-card">
      <div class="score-value">${bundle.digitalQualityScore.toFixed(1)}</div>
      <div class="score-label">Digital Quality Score (0–100, CVSS-adjusted)</div>
    </div>
    <div class="score-card">
      <div class="score-value">${bundle.maxCvssScore > 0 ? bundle.maxCvssScore.toFixed(1) : '—'}</div>
      <div class="score-label">Max CVSS base score</div>
    </div>
    <div class="score-card">
      <div class="score-value">${bundle.compliance.mappedFindingCount}</div>
      <div class="score-label">Compliance-mapped findings</div>
    </div>
  </div>

  <h2>Severidad</h2>
  <div class="summary-box">
    ${SEVERITY_ORDER.map(
      (sev) =>
        `<div class="badge bg-${sev.toLowerCase()}">${sev}: ${summary[sev] ?? 0}</div>`
    ).join('')}
  </div>

  <h2>Seis dimensiones</h2>
  <div class="dims">${dimensionsHtml}</div>

  <h2>Resumen CVSS</h2>
  ${cvssHtml}

  <h2>Compliance Gaps</h2>
  ${complianceHtml}

  <h2>Hallazgos (${findings.length})</h2>
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

/** @deprecated Prefer generateHtmlReport(bundle, path). Kept for callers legacy. */
export function generateHtmlReportFromFindings(
  findings: AuditFinding[],
  outputPath: string
): void {
  generateHtmlReport(
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
