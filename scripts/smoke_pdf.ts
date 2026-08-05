/**
 * Smoke test: regenerate Enterprise PDF + local interactive dashboard
 * inside the same audit-results/<run>/ folder as findings.json.
 *
 * Usage: npx tsx scripts/smoke_pdf.ts [path-to-findings.json]
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

import { generateHtmlReport } from '../src/reporters/htmlReporter.js';
import {
  buildAttestation,
  generatePdfReport
} from '../src/reporters/pdf_reporter.js';
import { AuditReportBundle } from '../src/types/audit.js';

const input =
  process.argv[2] ??
  path.join(
    'audit-results',
    'travel-app-isaacromerops-projects.vercel.app_2026-08-05_11-23-15',
    'findings.json'
  );

const runDir = path.resolve(path.dirname(input));
const raw = JSON.parse(fs.readFileSync(input, 'utf-8')) as AuditReportBundle & {
  license?: { tier?: string; organization?: string; accountId?: string };
};

const bundle: AuditReportBundle = {
  target: raw.target,
  timestamp: raw.timestamp,
  scannedPages: raw.scannedPages ?? [],
  findings: raw.findings ?? [],
  digitalQualityScore: raw.digitalQualityScore ?? 0,
  maxCvssScore: raw.maxCvssScore ?? 0,
  severityCounts: raw.severityCounts ?? {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  },
  dimensions: raw.dimensions ?? [],
  compliance: raw.compliance ?? { frameworks: [], mappedFindingCount: 0 },
  gateFailed: raw.gateFailed ?? false,
  failOn: raw.failOn ?? 'HIGH',
  environment: raw.environment,
  suppressedCount: raw.suppressedCount
};

const interactivePath = path.join(runDir, 'interactive-dashboard.html');
bundle.attestation = buildAttestation(bundle, {
  licenseTier: raw.license?.tier ?? 'ENTERPRISE_GOVERNANCE',
  organization: raw.license?.organization ?? 'CoreCheck Dev',
  accountId: raw.license?.accountId,
  localDashboardPath: interactivePath
});

generateHtmlReport(bundle, interactivePath);

const out = path.join(runDir, 'executive-report.pdf');
await generatePdfReport(bundle, out);

const stat = fs.statSync(out);
console.log(`OK PDF: ${out}`);
console.log(`Size: ${(stat.size / 1024).toFixed(1)} KB`);
console.log(`Dashboard HTML: ${interactivePath}`);
console.log(`Dashboard URL: ${bundle.attestation.dashboardUrl}`);
console.log(`Audit Hash: ${bundle.attestation.auditHash}`);
console.log(`Gate: ${bundle.gateFailed ? 'FAILED' : 'PASSED'}`);
console.log(`Score: ${bundle.digitalQualityScore} · Findings: ${bundle.findings.length}`);
