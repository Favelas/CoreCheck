/**
 * Contratos de dominio CoreCheck API (Fase C — paso 1/2).
 * Única fuente de verdad de tipos; aún no cableada a runtime JS.
 * HTTP envelope y errores se tipan aquí para migrar controllers sin reinventar shapes.
 */

/** Severidad alineada al Quality Gate del CLI CoreCheck. */
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Hallazgo / vulnerabilidad consolidada ingerible por la API. */
export interface Vulnerability {
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly severity: SeverityLevel;
  readonly description: string;
  readonly url?: string;
  readonly selector?: string;
}

/** Métricas agregadas del audit (score dimensional). */
export interface MetricScore {
  readonly dimension: string;
  readonly score: number;
  readonly maxScore: number;
}

/**
 * Payload de negocio que el cliente puede enviar en POST /api/reports.
 * Prohibido: id, createdAt (los asigna el servidor).
 */
export interface CreateReportInput {
  readonly url: string;
  readonly failOn?: SeverityLevel;
  readonly findingsCount?: number;
  readonly summary?: string;
  readonly findings?: ReadonlyArray<Vulnerability>;
  readonly metrics?: ReadonlyArray<MetricScore>;
  readonly [key: string]: unknown;
}

/**
 * Representación persistida de un reporte (respuesta 201 / GET by id).
 * El servidor es dueño de id, createdAt, accountId e integridad.
 */
export interface CoreCheckReport extends CreateReportInput {
  readonly id: string;
  readonly createdAt: string;
  readonly accountId: string;
  readonly contentHash: string;
  readonly integrityAlgorithm: 'SHA-256' | 'HMAC-SHA256';
  readonly hmacSignature?: string;
}

/** Respuesta de POST/GET …/verify */
export interface ReportVerifyResponse {
  readonly valid: boolean;
  readonly algorithm: 'SHA-256' | 'HMAC-SHA256';
  readonly contentHash: string;
  readonly hashMatches: boolean;
  readonly hmacVerified: boolean | null;
  readonly message: string;
}

/** Envelope de listado — lista vacía es 200, no 404. */
export interface ReportListEnvelope {
  readonly total: number;
  readonly data: ReadonlyArray<CoreCheckReport>;
}

/** Contrato estable de error HTTP (errorHandler). */
export interface ApiErrorBody {
  readonly error: string;
  readonly message: string;
}

/** Health check GET /. */
export interface HealthResponse {
  readonly status: 'ok';
  readonly service: string;
  readonly timestamp: string;
  readonly uptimeSeconds: number;
  readonly persistence: string;
  readonly version: string;
}

/** GET /metrics — sin PII. */
export interface MetricsResponse {
  readonly service: string;
  readonly metrics: {
    readonly startedAt: string;
    readonly uptimeSeconds: number;
    readonly requestsTotal: number;
    readonly requestsByStatus: Readonly<Record<string, number>>;
    readonly errors5xx: number;
    readonly rateLimited: number;
    readonly avgLatencyMs: number;
  };
}

/** Punto de serie temporal (Slice 3 dashboard). */
export interface TrendPoint {
  readonly id: string;
  readonly createdAt: string;
  readonly url: string;
  readonly digitalQualityScore: number | null;
  readonly findingsCount: number;
  readonly gateFailed: boolean | null;
  readonly failOn: SeverityLevel | null;
  readonly severityCounts: Partial<Record<SeverityLevel, number>>;
}

export interface TrendsResponse {
  readonly totalRuns: number;
  readonly urlFilter: string | null;
  readonly gateFailRate: number;
  readonly avgScore: number | null;
  readonly scoreDelta: number | null;
  readonly latest: TrendPoint | null;
  readonly previous: TrendPoint | null;
  readonly series: ReadonlyArray<TrendPoint>;
}

export interface FindingRef {
  readonly ruleId: string;
  readonly severity: SeverityLevel;
  readonly title: string;
}

export interface ReportDiffResponse {
  readonly baseId: string;
  readonly targetId: string;
  readonly baseCreatedAt: string;
  readonly targetCreatedAt: string;
  readonly url: string;
  readonly scoreDelta: number | null;
  readonly findingsCountDelta: number;
  readonly added: ReadonlyArray<FindingRef>;
  readonly removed: ReadonlyArray<FindingRef>;
  readonly unchangedCount: number;
  readonly regression: boolean;
}
