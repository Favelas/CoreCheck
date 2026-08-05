import {
  AuditDimension,
  AuditFinding,
  AuditReportBundle,
  ComplianceControlMapping,
  ComplianceFramework,
  ComplianceSummary,
  DimensionBreakdown,
  FrameworkComplianceSummary,
  RuleCategory,
  SeverityLevel
} from '../types/audit.js';

interface ControlDef {
  controlId: string;
  controlTitle: string;
  /** Categorías / prefijos de ruleId que activan el control. */
  match: (finding: AuditFinding) => boolean;
}

const SEVERITY_PENALTY: Record<SeverityLevel, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 1
};

const ISO27001_CONTROLS: ControlDef[] = [
  {
    controlId: 'A.8.24',
    controlTitle: 'Use of cryptography / transport security',
    match: (f) =>
      /HSTS|TLS|HTTPS|CRYPTO|SECURE|COOKIE/i.test(f.ruleId) ||
      f.category === 'PRIVACY' ||
      f.ruleId.includes('HDR')
  },
  {
    controlId: 'A.8.25',
    controlTitle: 'Secure development life cycle',
    match: (f) =>
      f.category === 'SECURITY' ||
      f.ruleId.startsWith('SEC-') ||
      f.ruleId.includes('XSS') ||
      f.ruleId.includes('SQLI')
  },
  {
    controlId: 'A.8.26',
    controlTitle: 'Application security requirements',
    match: (f) =>
      f.ruleId.startsWith('SEC-') ||
      f.ruleId.startsWith('NET-') ||
      f.category === 'NETWORK'
  },
  {
    controlId: 'A.5.34',
    controlTitle: 'Privacy and protection of PII',
    match: (f) => f.category === 'PRIVACY' || f.ruleId.startsWith('PRIV-')
  },
  {
    controlId: 'A.8.9',
    controlTitle: 'Configuration management',
    match: (f) =>
      f.ruleId.includes('HDR') ||
      f.ruleId.includes('GENERATOR') ||
      f.ruleId.includes('CSP')
  }
];

const SOC2_CONTROLS: ControlDef[] = [
  {
    controlId: 'CC6.1',
    controlTitle: 'Logical access — security controls',
    match: (f) => f.category === 'SECURITY' || f.ruleId.startsWith('SEC-')
  },
  {
    controlId: 'CC6.6',
    controlTitle: 'Boundary protection / network security',
    match: (f) => f.category === 'NETWORK' || f.ruleId.startsWith('NET-')
  },
  {
    controlId: 'CC7.1',
    controlTitle: 'Detection of security events',
    match: (f) =>
      f.ruleId.includes('500') ||
      f.ruleId.includes('UNHANDLED') ||
      f.severity === 'CRITICAL'
  },
  {
    controlId: 'C1.1',
    controlTitle: 'Confidentiality — encryption in transit',
    match: (f) =>
      /HSTS|MIXED|TLS|SECURE|COOKIE/i.test(f.ruleId) || f.category === 'PRIVACY'
  },
  {
    controlId: 'C1.2',
    controlTitle: 'Confidentiality — disposal / data leakage',
    match: (f) =>
      f.ruleId.includes('LEAK') ||
      f.ruleId.includes('STORAGE') ||
      f.category === 'PRIVACY'
  }
];

const PCI_DSS_CONTROLS: ControlDef[] = [
  {
    controlId: '6.2.4',
    controlTitle: 'Software engineering — injection / XSS protections',
    match: (f) =>
      /XSS|SQLI|INJECTION|FUZZ/i.test(f.ruleId) || f.ruleId.startsWith('SEC-')
  },
  {
    controlId: '6.4.1',
    controlTitle: 'Public-facing web apps — automated technical assessment',
    match: (f) => f.category === 'SECURITY' || f.ruleId.startsWith('SEC-')
  },
  {
    controlId: '6.4.2',
    controlTitle: 'Web application firewall / HTTP security controls',
    match: (f) => f.ruleId.includes('HDR') || f.ruleId.includes('CSP')
  },
  {
    controlId: '4.2.1',
    controlTitle: 'Strong cryptography for transmission of CHD',
    match: (f) =>
      /HSTS|MIXED|TLS|HTTPS/i.test(f.ruleId) || f.category === 'NETWORK'
  },
  {
    controlId: '8.3.2',
    controlTitle: 'Strong authentication / session management',
    match: (f) =>
      f.ruleId.includes('COOKIE') ||
      f.ruleId.includes('CSRF') ||
      f.category === 'PRIVACY'
  }
];

const WCAG_ADA_CONTROLS: ControlDef[] = [
  {
    controlId: 'WCAG-2.2-AA',
    controlTitle: 'WCAG 2.1/2.2 Level AA conformance',
    match: (f) =>
      f.category === 'A11Y' ||
      f.ruleType === 'A11Y_VIOLATION' ||
      f.ruleId.startsWith('A11Y-')
  },
  {
    controlId: 'ADA-Title-II/III',
    controlTitle: 'ADA effective communication / accessible web content',
    match: (f) =>
      f.category === 'A11Y' ||
      f.ruleType === 'A11Y_VIOLATION' ||
      f.ruleId.startsWith('A11Y-')
  }
];

/** EN 301 549 — requisitos de accesibilidad TIC (UE) alineados a WCAG. */
const EN_301_549_CONTROLS: ControlDef[] = [
  {
    controlId: '9.1',
    controlTitle: 'EN 301 549 §9.1 Perceivable (WCAG Perceivable)',
    match: (f) =>
      f.category === 'A11Y' ||
      f.ruleType === 'A11Y_VIOLATION' ||
      f.ruleId.startsWith('A11Y-')
  },
  {
    controlId: '9.2',
    controlTitle: 'EN 301 549 §9.2 Operable',
    match: (f) =>
      f.category === 'A11Y' ||
      f.ruleType === 'A11Y_VIOLATION' ||
      f.ruleId.startsWith('A11Y-')
  },
  {
    controlId: '9.3',
    controlTitle: 'EN 301 549 §9.3 Understandable',
    match: (f) =>
      f.category === 'A11Y' ||
      f.ruleType === 'A11Y_VIOLATION' ||
      f.ruleId.startsWith('A11Y-')
  },
  {
    controlId: '9.4',
    controlTitle: 'EN 301 549 §9.4 Robust',
    match: (f) =>
      f.category === 'A11Y' ||
      f.ruleType === 'A11Y_VIOLATION' ||
      f.ruleId.startsWith('A11Y-')
  }
];

/**
 * Mapea hallazgos revalidados a ISO 27001, SOC 2, PCI-DSS v4.0,
 * EN 301 549 & WCAG/ADA y produce el bundle ejecutivo consolidado.
 */
export class ComplianceMapper {
  public enrichFindings(findings: AuditFinding[]): AuditFinding[] {
    return findings.map((finding) => {
      const iso27001 = this.matchControls(finding, ISO27001_CONTROLS).map((c) => c.controlId);
      const soc2 = this.matchControls(finding, SOC2_CONTROLS).map((c) => c.controlId);
      const pciDss = this.matchControls(finding, PCI_DSS_CONTROLS).map((c) => c.controlId);
      const ada = this.matchControls(finding, WCAG_ADA_CONTROLS)
        .filter((c) => c.controlId.startsWith('ADA'))
        .map((c) => c.controlId);
      const en301549 = this.matchControls(finding, EN_301_549_CONTROLS).map(
        (c) => c.controlId
      );

      const wcagExtra =
        finding.category === 'A11Y' || finding.ruleType === 'A11Y_VIOLATION'
          ? ['WCAG 2.1 AA', 'WCAG 2.2 AA']
          : [];

      return {
        ...finding,
        standards: {
          ...finding.standards,
          iso27001: this.mergeUnique(finding.standards.iso27001, iso27001),
          soc2: this.mergeUnique(finding.standards.soc2, soc2),
          pciDss: this.mergeUnique(finding.standards.pciDss, pciDss),
          ada: this.mergeUnique(finding.standards.ada, ada),
          en301549: this.mergeUnique(finding.standards.en301549, en301549),
          wcag: this.mergeUnique(finding.standards.wcag, wcagExtra)
        }
      };
    });
  }

  public buildComplianceSummary(findings: AuditFinding[]): ComplianceSummary {
    const frameworks: FrameworkComplianceSummary[] = [
      this.summarizeFramework('ISO27001', findings, ISO27001_CONTROLS),
      this.summarizeFramework('SOC2', findings, SOC2_CONTROLS),
      this.summarizeFramework('PCI_DSS', findings, PCI_DSS_CONTROLS),
      this.summarizeFramework('WCAG', findings, [WCAG_ADA_CONTROLS[0]]),
      this.summarizeFramework('ADA', findings, [WCAG_ADA_CONTROLS[1]]),
      this.summarizeFramework('EN_301_549', findings, EN_301_549_CONTROLS)
    ];

    const mappedFindingCount = findings.filter(
      (f) =>
        (f.standards.iso27001?.length ?? 0) > 0 ||
        (f.standards.soc2?.length ?? 0) > 0 ||
        (f.standards.pciDss?.length ?? 0) > 0 ||
        (f.standards.wcag?.length ?? 0) > 0 ||
        (f.standards.ada?.length ?? 0) > 0 ||
        (f.standards.en301549?.length ?? 0) > 0
    ).length;

    return { frameworks, mappedFindingCount };
  }

  public buildReportBundle(input: {
    target: string;
    scannedPages: string[];
    findings: AuditFinding[];
    failOn: SeverityLevel;
    gateFailed: boolean;
    timestamp?: string;
    environment?: AuditReportBundle['environment'];
    suppressedCount?: number;
    maxCvssScore?: number;
    cvssPenalty?: number;
  }): AuditReportBundle {
    const enriched = this.enrichFindings(input.findings);
    const severityCounts = this.countBySeverity(enriched);
    const dimensions = this.buildDimensions(enriched);
    let digitalQualityScore = this.computeGlobalScore(dimensions);

    const cvssPenalty = input.cvssPenalty ?? 0;
    if (cvssPenalty > 0) {
      digitalQualityScore = Math.max(
        0,
        Math.round((digitalQualityScore - cvssPenalty) * 10) / 10
      );
    }

    const compliance = this.buildComplianceSummary(enriched);

    return {
      target: input.target,
      timestamp: input.timestamp ?? new Date().toISOString(),
      scannedPages: input.scannedPages,
      findings: enriched,
      digitalQualityScore,
      maxCvssScore: input.maxCvssScore ?? 0,
      severityCounts,
      dimensions,
      compliance,
      gateFailed: input.gateFailed,
      failOn: input.failOn,
      environment: input.environment,
      suppressedCount: input.suppressedCount ?? 0
    };
  }

  public resolveDimension(finding: AuditFinding): AuditDimension {
    const category = finding.category;
    if (category === 'A11Y' || finding.ruleType === 'A11Y_VIOLATION' || finding.ruleId.startsWith('A11Y-')) {
      return 'ACCESSIBILITY';
    }
    if (category === 'NETWORK' || finding.ruleId.startsWith('NET-')) {
      return 'NETWORK';
    }
    if (category === 'PERFORMANCE' || finding.ruleId.startsWith('PERF-')) {
      return 'PERFORMANCE';
    }
    if (category === 'SEO' || finding.ruleId.startsWith('SEO-')) {
      return 'SEO';
    }
    if (category === 'PRIVACY' || finding.ruleId.startsWith('PRIV-')) {
      return 'PRIVACY';
    }
    if (category === 'SECURITY' || finding.ruleId.startsWith('SEC-')) {
      return 'SECURITY';
    }
    // Default: security bucket for uncategorized SecOps findings
    return this.inferFromRuleId(finding.ruleId, category);
  }

  private inferFromRuleId(ruleId: string, category?: RuleCategory): AuditDimension {
    if (category === 'QUALITY') {
      return 'SECURITY';
    }
    if (ruleId.includes('META') || ruleId.includes('GENERATOR')) {
      return 'SECURITY';
    }
    return 'SECURITY';
  }

  private buildDimensions(findings: AuditFinding[]): DimensionBreakdown[] {
    const dims: AuditDimension[] = [
      'SECURITY',
      'ACCESSIBILITY',
      'NETWORK',
      'PERFORMANCE',
      'SEO',
      'PRIVACY'
    ];

    return dims.map((dimension) => {
      const subset = findings.filter((f) => this.resolveDimension(f) === dimension);
      const bySeverity = this.countBySeverity(subset);
      const penalty = subset.reduce(
        (acc, f) => acc + (SEVERITY_PENALTY[f.severity] ?? 0),
        0
      );
      const score = Math.max(0, Math.min(100, 100 - penalty));
      return {
        dimension,
        count: subset.length,
        score,
        bySeverity
      };
    });
  }

  private computeGlobalScore(dimensions: DimensionBreakdown[]): number {
    if (dimensions.length === 0) {
      return 100;
    }
    const avg =
      dimensions.reduce((acc, d) => acc + d.score, 0) / dimensions.length;
    return Math.round(avg * 10) / 10;
  }

  private countBySeverity(findings: AuditFinding[]): Record<SeverityLevel, number> {
    const counts: Record<SeverityLevel, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    return counts;
  }

  private matchControls(finding: AuditFinding, controls: ControlDef[]): ControlDef[] {
    return controls.filter((c) => c.match(finding));
  }

  private summarizeFramework(
    framework: ComplianceFramework,
    findings: AuditFinding[],
    controls: ControlDef[]
  ): FrameworkComplianceSummary {
    const mappings: ComplianceControlMapping[] = controls.map((control) => {
      const related = findings.filter((f) => control.match(f));
      const hasCritical = related.some(
        (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
      );
      const status: ComplianceControlMapping['status'] =
        related.length === 0 ? 'COVERED' : hasCritical ? 'GAP' : 'PARTIAL';

      return {
        framework,
        controlId: control.controlId,
        controlTitle: control.controlTitle,
        status,
        relatedFindingIds: related.map((f) => f.id)
      };
    });

    const relatedFindings = new Set(mappings.flatMap((m) => m.relatedFindingIds)).size;
    const gapCount = mappings.filter((m) => m.status === 'GAP').length;

    return {
      framework,
      relatedFindings,
      gapCount,
      controls: mappings
    };
  }

  private mergeUnique(
    existing: string[] | undefined,
    incoming: string[]
  ): string[] | undefined {
    const merged = [...new Set([...(existing ?? []), ...incoming])];
    return merged.length > 0 ? merged : existing;
  }
}
