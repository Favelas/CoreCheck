export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type OutputFormat = 'json' | 'sarif' | 'html' | 'markdown' | 'pdf';
export type AuditEnvironment = 'prod' | 'staging' | 'dev';

/** Categoría funcional del hallazgo (Security / A11y / Network / Digital Quality / Infra). */
export type RuleCategory =
  | 'SECURITY'
  | 'A11Y'
  | 'NETWORK'
  | 'QUALITY'
  | 'PERFORMANCE'
  | 'SEO'
  | 'PRIVACY'
  | 'INFRA';

/** Dimensiones ejecutivas del Quality Score (Fase 3). */
export type AuditDimension =
  | 'SECURITY'
  | 'ACCESSIBILITY'
  | 'NETWORK'
  | 'PERFORMANCE'
  | 'SEO'
  | 'PRIVACY';

/** Tipo tipado de regla; WCAG real usa A11Y_VIOLATION. */
export type RuleType =
  | 'A11Y_VIOLATION'
  | 'NETWORK_HTTP_ERROR'
  | 'NETWORK_MIXED_CONTENT'
  | 'NETWORK_COOKIE_FLAGS'
  | 'SECURITY_FINDING'
  | 'SECURITY_HEADER'
  | 'PERF_WEB_VITAL'
  | 'PERF_ASSET_OPTIMIZATION'
  | 'SEO_META_TAG'
  | 'SEO_STRUCTURE'
  | 'SEO_GEO'
  | 'SEO_LLM_READINESS'
  | 'PRIVACY_COOKIE'
  | 'PRIVACY_CONSENT'
  | 'PRIVACY_POLICY_LINK'
  /** Fallo de infraestructura del motor (inspector crash, degradación controlada). */
  | 'INFRA_FAILURE';

/** Marcos normativos soportados por el compliance mapper. */
export type ComplianceFramework =
  | 'ISO27001'
  | 'SOC2'
  | 'PCI_DSS'
  | 'WCAG'
  | 'ADA'
  | 'EN_301_549';

export type CvssVersion = '3.1' | '4.0';

export interface FindingLocation {
  selector?: string;
  snippet?: string;
  /** Subpágina exacta donde se observó la ocurrencia. */
  url?: string;
}

export interface CvssScore {
  version: CvssVersion;
  vector: string;
  baseScore: number;
  /** CRITICAL | HIGH | MEDIUM | LOW derivado del baseScore. */
  severity: Exclude<SeverityLevel, 'INFO'>;
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
  /** Calibración CVSS v3.1 / v4.0 (hallazgos security/DAST). */
  cvss?: CvssScore;
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
    /** Controles ISO/IEC 27001:2022 relacionados. */
    iso27001?: string[];
    /** Criterios SOC 2 Trust Services Criteria. */
    soc2?: string[];
    /** Requisitos PCI-DSS v4.0. */
    pciDss?: string[];
    /** Referencias ADA Title II/III / Section 508. */
    ada?: string[];
    /** Cláusulas EN 301 549 (accesibilidad UE). */
    en301549?: string[];
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
  /** Entorno para políticas diferenciadas. */
  environment?: AuditEnvironment;
  /** Ruta a baseline JSON o .corecheckignore. */
  baselinePath?: string;
  /** API Key comercial (también vía CORECHECK_API_KEY). */
  apiKey?: string;
}

/** Resultado consolidado de una corrida multi-página. */
export interface AuditRunResult {
  findings: AuditFinding[];
  scannedPages: string[];
}

export interface ComplianceControlMapping {
  framework: ComplianceFramework;
  controlId: string;
  controlTitle: string;
  /** GAP = hallazgo demuestra incumplimiento; COVERED = control referenciado sin gap severo. */
  status: 'GAP' | 'PARTIAL' | 'COVERED';
  relatedFindingIds: string[];
}

export interface FrameworkComplianceSummary {
  framework: ComplianceFramework;
  relatedFindings: number;
  gapCount: number;
  controls: ComplianceControlMapping[];
}

export interface ComplianceSummary {
  frameworks: FrameworkComplianceSummary[];
  mappedFindingCount: number;
}

export interface DimensionBreakdown {
  dimension: AuditDimension;
  count: number;
  /** Score 0–100 (100 = sin hallazgos ponderados). */
  score: number;
  bySeverity: Partial<Record<SeverityLevel, number>>;
}

export interface PolicyEvaluationResult {
  environment: AuditEnvironment;
  failOn: SeverityLevel;
  gateFailed: boolean;
  suppressedCount: number;
  activeFindings: AuditFinding[];
  suppressedFindings: AuditFinding[];
}

export interface BaselineEntry {
  ruleId: string;
  /** Selector/URL opcionales para fingerprint más preciso. */
  selector?: string;
  url?: string;
  reason?: string;
}

export interface CoreCheckBaseline {
  version: number;
  accepted: BaselineEntry[];
}

export type TicketProvider = 'jira' | 'azure_boards' | 'gitlab';

export interface TicketPayload {
  provider: TicketProvider;
  method: 'POST';
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

/** Bundle ejecutivo consolidado (JSON / PDF / Webhook / SARIF properties). */
export interface AuditReportBundle {
  target: string;
  timestamp: string;
  scannedPages: string[];
  findings: AuditFinding[];
  /** Score global de calidad digital 0–100 (ajustado por CVSS). */
  digitalQualityScore: number;
  /** Max CVSS base score observado (0 si no aplica). */
  maxCvssScore: number;
  severityCounts: Record<SeverityLevel, number>;
  dimensions: DimensionBreakdown[];
  compliance: ComplianceSummary;
  gateFailed: boolean;
  failOn: SeverityLevel;
  environment?: AuditEnvironment;
  suppressedCount?: number;
  /** Metadatos de attestation / verificación del informe oficial. */
  attestation?: AuditAttestation;
}

/** Attestation del informe PDF / Dashboard Web interactivo. */
export interface AuditAttestation {
  /**
   * Hash de verificación primario (SHA-256 del payload canónico).
   * Alias histórico: `auditHash` (mismo valor).
   */
  attestationHash: string;
  /** @deprecated Prefer `attestationHash`. Mantenido por compatibilidad. */
  auditHash: string;
  /** Algoritmo usado: SHA-256 o HMAC-SHA256 si hay secret. */
  algorithm: 'SHA-256' | 'HMAC-SHA256';
  /** Firma HMAC-SHA256 (hex) cuando CORECHECK_ATTESTATION_SECRET está definido. */
  hmacSignature?: string;
  /** Versión del CLI embebida en el payload. */
  cliVersion: string;
  /** Timestamp UTC firmado (= timestamp del bundle, determinista). */
  signedAtUtc: string;
  /** Tier comercial (ej. ENTERPRISE_GOVERNANCE). */
  licenseTier?: string;
  organization?: string;
  accountId?: string;
  /** URL del Dashboard Web interactivo de esta auditoría. */
  dashboardUrl: string;
  /** URL corta de verificación / attestation. */
  verificationUrl: string;
  /** Payload estructurado embebido en el QR del PDF. */
  qrPayload?: string;
  /** Flag de fuzzing activo incluido en el payload canónico (verify offline). */
  activeFuzzing?: boolean;
}

export interface WebhookNotifyOptions {
  webhookUrl: string;
  bundle: AuditReportBundle;
  /** Canal destino inferido o forzado. */
  channel?: 'slack' | 'teams' | 'generic';
  /** Secret HMAC (env CORECHECK_WEBHOOK_SECRET). Firma X-CoreCheck-Signature. */
  signingSecret?: string;
  /** Si true, no envía HTTP (solo construye/firma en memoria). */
  dryRun?: boolean;
}
