import type {
  AuditFinding,
  AuditReportBundle,
  SeverityLevel
} from '../src/types/audit.ts';

export function sampleFinding(
  overrides: Partial<AuditFinding> & Pick<AuditFinding, 'ruleId' | 'severity'>
): AuditFinding {
  return {
    id: overrides.id ?? `f-${overrides.ruleId}`,
    ruleId: overrides.ruleId,
    title: overrides.title ?? `${overrides.ruleId} finding`,
    severity: overrides.severity,
    description: overrides.description ?? 'fixture finding',
    category: overrides.category,
    ruleType: overrides.ruleType,
    confidence: overrides.confidence ?? 'HIGH',
    evidence: {
      url: overrides.evidence?.url ?? 'https://example.com/',
      selector: overrides.evidence?.selector,
      snippet: overrides.evidence?.snippet ?? '<div>fixture</div>',
      ...overrides.evidence
    },
    remediation: {
      explanation: overrides.remediation?.explanation ?? 'Fix the issue',
      codeBefore: overrides.remediation?.codeBefore ?? '',
      codeAfter: overrides.remediation?.codeAfter ?? ''
    },
    standards: overrides.standards ?? {},
    cvss: overrides.cvss,
    revalidated: overrides.revalidated
  };
}

export function emptySeverityCounts(): Record<SeverityLevel, number> {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

export function sampleBundle(
  overrides: Partial<AuditReportBundle> = {}
): AuditReportBundle {
  const findings = overrides.findings ?? [];
  const severityCounts = { ...emptySeverityCounts() };
  for (const f of findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
  }

  return {
    target: overrides.target ?? 'https://example.com/',
    timestamp: overrides.timestamp ?? '2026-08-06T12:00:00.000Z',
    scannedPages: overrides.scannedPages ?? ['https://example.com/'],
    findings,
    digitalQualityScore: overrides.digitalQualityScore ?? 92,
    maxCvssScore: overrides.maxCvssScore ?? 0,
    severityCounts: overrides.severityCounts ?? severityCounts,
    dimensions: overrides.dimensions ?? [],
    compliance: overrides.compliance ?? {
      frameworks: [],
      mappedFindingCount: findings.length
    },
    gateFailed: overrides.gateFailed ?? false,
    failOn: overrides.failOn ?? 'HIGH',
    environment: overrides.environment ?? 'staging',
    suppressedCount: overrides.suppressedCount ?? 0,
    attestation: overrides.attestation
  };
}
