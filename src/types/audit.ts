export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type OutputFormat = 'json' | 'sarif' | 'html' | 'markdown';

/** Categoría funcional del hallazgo (Security / A11y / Network). */
export type RuleCategory = 'SECURITY' | 'A11Y' | 'NETWORK' | 'QUALITY';

/** Tipo tipado de regla; WCAG real usa A11Y_VIOLATION. */
export type RuleType =
  | 'A11Y_VIOLATION'
  | 'NETWORK_HTTP_ERROR'
  | 'NETWORK_MIXED_CONTENT'
  | 'NETWORK_COOKIE_FLAGS'
  | 'SECURITY_FINDING';

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
  /** Categoría del hallazgo (p.ej. A11y para violaciones WCAG). */
  category?: RuleCategory;
  /** Tipo de regla (p.ej. A11Y_VIOLATION). */
  ruleType?: RuleType;
  /** Confianza tras re-validación Zero-FP (HIGH = confirmado). */
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  /** True si el hallazgo pasó por el motor de re-validación. */
  revalidated?: boolean;
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
    /** Etiquetas WCAG 2.1 / 2.2 AA (y criterios), p.ej. `WCAG 2.2 AA`, `1.4.3`. */
    wcag?: string[];
    cwe?: string[];
  };
}

export interface AuditAuthConfig {
  loginUrl?: string;
  username?: string;
  password?: string;
  customHeaders?: Record<string, string>;
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
  /** Autenticación previa al crawling (form login y/o headers). */
  authConfig?: AuditAuthConfig;
}

/** Resultado consolidado de una corrida multi-página. */
export interface AuditRunResult {
  findings: AuditFinding[];
  scannedPages: string[];
}
