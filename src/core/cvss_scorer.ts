import {
  AuditFinding,
  CvssScore,
  CvssVersion,
  SeverityLevel
} from '../types/audit.js';

interface CvssProfile {
  /** CVSS v3.1 vector string. */
  v31: string;
  /** CVSS v4.0 vector string. */
  v40: string;
  /** Base score v3.1 (fuente de calibración primaria). */
  baseScore: number;
}

/**
 * Perfiles CVSS por familia de regla DAST/Security.
 * Vectores simplificados pero válidos en forma para reporting ejecutivo.
 */
const RULE_PROFILES: Array<{ test: RegExp; profile: CvssProfile }> = [
  {
    test: /XSS|INJECTION/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N',
      baseScore: 6.1
    }
  },
  {
    test: /SQLI/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      baseScore: 9.8
    }
  },
  {
    test: /UNHANDLED|SERVER-500|500/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N',
      baseScore: 7.5
    }
  },
  {
    test: /CSP-MISSING|CLICKJACKING/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
      v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
      baseScore: 5.4
    }
  },
  {
    test: /HSTS|MIXED-CONTENT|NOSNIFF/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
      v40: 'CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      baseScore: 5.9
    }
  },
  {
    test: /COOKIE|CSRF|INSECURE/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
      v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
      baseScore: 6.5
    }
  },
  {
    test: /LEAK|GENERATOR|STORAGE/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      baseScore: 5.3
    }
  },
  {
    test: /NAV-RENDER-FAILED|SEC-NAV/i,
    profile: {
      v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N',
      baseScore: 7.5
    }
  }
];

const DEFAULT_BY_SEVERITY: Record<SeverityLevel, CvssProfile> = {
  CRITICAL: {
    v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    baseScore: 9.8
  },
  HIGH: {
    v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
    baseScore: 8.2
  },
  MEDIUM: {
    v31: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    v40: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
    baseScore: 6.5
  },
  LOW: {
    v31: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
    v40: 'CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
    baseScore: 3.7
  },
  INFO: {
    v31: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',
    v40: 'CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
    baseScore: 0
  }
};

/**
 * Motor de calibración CVSS v3.1 / v4.0 para hallazgos Security/DAST.
 * Ajusta severidad del hallazgo y aporta penalización al score global.
 */
export class CvssScorer {
  constructor(private readonly preferredVersion: CvssVersion = '3.1') {}

  public isSecurityFinding(finding: AuditFinding): boolean {
    if (finding.category === 'SECURITY') return true;
    if (finding.ruleType === 'SECURITY_FINDING') return true;
    if (finding.ruleId.startsWith('SEC-')) return true;
    if (finding.ruleId.startsWith('NET-') && /COOKIE|MIXED|HDR/i.test(finding.ruleId)) {
      return true;
    }
    if (finding.category === 'PRIVACY' && /COOKIE|INSECURE/i.test(finding.ruleId)) {
      return true;
    }
    return false;
  }

  public scoreFinding(finding: AuditFinding): CvssScore | undefined {
    if (!this.isSecurityFinding(finding)) {
      return undefined;
    }

    const profile =
      RULE_PROFILES.find((p) => p.test.test(finding.ruleId))?.profile ??
      DEFAULT_BY_SEVERITY[finding.severity];

    const baseScore = profile.baseScore;
    const severity = this.scoreToSeverity(baseScore);
    const vector = this.preferredVersion === '4.0' ? profile.v40 : profile.v31;

    return {
      version: this.preferredVersion,
      vector,
      baseScore,
      severity
    };
  }

  /** Enriquece hallazgos con CVSS y recalibra severidad cuando CVSS es más estricto. */
  public enrichFindings(findings: AuditFinding[]): AuditFinding[] {
    return findings.map((finding) => {
      const cvss = this.scoreFinding(finding);
      if (!cvss) {
        return finding;
      }

      const calibratedSeverity = this.maxSeverity(finding.severity, cvss.severity);
      return {
        ...finding,
        severity: calibratedSeverity,
        cvss
      };
    });
  }

  /** Penalización 0–40 sobre el score global a partir del max CVSS. */
  public globalScorePenalty(findings: AuditFinding[]): {
    maxCvssScore: number;
    penalty: number;
  } {
    const scores = findings
      .map((f) => f.cvss?.baseScore ?? 0)
      .filter((s) => s > 0);
    const maxCvssScore = scores.length > 0 ? Math.max(...scores) : 0;
    // Map 0–10 CVSS → 0–40 penalty on 0–100 quality score.
    const penalty = Math.round((maxCvssScore / 10) * 40 * 10) / 10;
    return { maxCvssScore, penalty };
  }

  public scoreToSeverity(baseScore: number): Exclude<SeverityLevel, 'INFO'> {
    if (baseScore >= 9.0) return 'CRITICAL';
    if (baseScore >= 7.0) return 'HIGH';
    if (baseScore >= 4.0) return 'MEDIUM';
    return 'LOW';
  }

  private severityRank(severity: SeverityLevel): number {
    switch (severity) {
      case 'CRITICAL':
        return 4;
      case 'HIGH':
        return 3;
      case 'MEDIUM':
        return 2;
      case 'LOW':
        return 1;
      default:
        return 0;
    }
  }

  private maxSeverity(a: SeverityLevel, b: SeverityLevel): SeverityLevel {
    return this.severityRank(a) >= this.severityRank(b) ? a : b;
  }
}
