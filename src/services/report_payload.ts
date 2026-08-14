import type { AuditReportBundle, SeverityLevel } from '../types/audit.js';

/** Contrato alineado a corecheck-api CreateReportInput (sin acoplar packages). */
export interface CreateReportInput {
  readonly url: string;
  readonly failOn?: SeverityLevel;
  readonly findingsCount?: number;
  readonly summary?: string;
  readonly findings?: ReadonlyArray<UploadedFinding>;
  readonly metrics?: ReadonlyArray<UploadedMetric>;
  readonly [key: string]: unknown;
}

export interface UploadedFinding {
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly severity: SeverityLevel;
  readonly description: string;
  readonly url?: string;
  readonly selector?: string;
}

export interface UploadedMetric {
  readonly dimension: string;
  readonly score: number;
  readonly maxScore: number;
}

const MAX_FINDINGS = 100;
const MAX_DESCRIPTION_CHARS = 500;

/**
 * Mapea el bundle CLI → payload ingerible por POST /api/reports.
 * Respeta presupuesto: top N findings, descriptions truncadas; sin secretos.
 */
export function buildCreateReportInput(
  bundle: AuditReportBundle,
  options?: { readonly maxFindings?: number }
): CreateReportInput {
  const maxFindings = options?.maxFindings ?? MAX_FINDINGS;
  const findings = bundle.findings.slice(0, maxFindings).map((f) => {
    const mapped: UploadedFinding = {
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      description: truncate(f.description, MAX_DESCRIPTION_CHARS)
    };
    const pageUrl = f.evidence.url;
    if (pageUrl) {
      return { ...mapped, url: pageUrl, ...(f.evidence.selector ? { selector: f.evidence.selector } : {}) };
    }
    if (f.evidence.selector) {
      return { ...mapped, selector: f.evidence.selector };
    }
    return mapped;
  });

  const critical = bundle.severityCounts.CRITICAL ?? 0;
  const high = bundle.severityCounts.HIGH ?? 0;
  const summary = [
    `gate=${bundle.gateFailed ? 'FAIL' : 'PASS'}`,
    `failOn=${bundle.failOn}`,
    `score=${bundle.digitalQualityScore}`,
    `findings=${bundle.findings.length}`,
    `critical=${critical}`,
    `high=${high}`,
    `pages=${bundle.scannedPages.length}`
  ].join(' · ');

  return {
    url: bundle.target,
    failOn: bundle.failOn,
    findingsCount: bundle.findings.length,
    summary,
    findings,
    metrics: bundle.dimensions.map((d) => ({
      dimension: d.dimension,
      score: d.score,
      maxScore: 100
    })),
    timestamp: bundle.timestamp,
    gateFailed: bundle.gateFailed,
    digitalQualityScore: bundle.digitalQualityScore,
    maxCvssScore: bundle.maxCvssScore,
    severityCounts: bundle.severityCounts,
    scannedPages: bundle.scannedPages,
    environment: bundle.environment,
    suppressedCount: bundle.suppressedCount ?? 0,
    findingsTruncated: bundle.findings.length > maxFindings
  };
}

function truncate(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max - 1)}…`;
}
