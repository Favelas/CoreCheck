export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type OutputFormat = 'json' | 'sarif' | 'html' | 'markdown';

export interface FindingLocation {
  selector?: string;
  snippet?: string;
  /** Subpágina exacta donde se observó la ocurrencia. */
  url?: string;
}

export interface AuditFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: {
    /** URL de la subpágina auditada (superficie multi-page). */
    url?: string;
    selector?: string;
    snippet?: string;
    requestPayload?: string;
    responseStatus?: number;
    responseHeaders?: Record<string, string>;
    screenshotPath?: string;
    artifactPath?: string;
    locations?: FindingLocation[];
  };
  remediation: {
    explanation: string;
    codeBefore?: string;
    codeAfter?: string;
  };
  standards: {
    owasp?: string[];
    wcag?: string[];
    cwe?: string[];
  };
}

export interface AuditExecutionOptions {
  targetUrl: string;
  storageStatePath?: string;
  concurrency?: number;
  timeoutMs?: number;
  maxRetries?: number;
  outputFormats?: OutputFormat[];
  activeFuzzing?: boolean;
  /** Directorio de artefactos (evidencia + reportes). Lo define la CLI / CI. */
  outputDir?: string;
  /** Profundidad máxima BFS del crawler (0 = solo la URL inicial). */
  maxDepth?: number;
  /** Tope de páginas a descubrir/auditar. */
  maxPages?: number;
  /** Si true, solo se siguen enlaces del mismo origin que targetUrl. */
  sameOriginOnly?: boolean;
}

/** Resultado consolidado de una corrida multi-página. */
export interface AuditRunResult {
  findings: AuditFinding[];
  scannedPages: string[];
}
