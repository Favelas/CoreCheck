import type {
  CoreCheckReport,
  SeverityLevel,
  Vulnerability
} from '../types/contracts';

export interface ReportListFilters {
  readonly url?: string;
  readonly failOn?: SeverityLevel;
  readonly gateFailed?: boolean;
  readonly since?: string;
  readonly q?: string;
  readonly limit?: number;
}

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
  readonly series: readonly TrendPoint[];
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
  readonly added: readonly FindingRef[];
  readonly removed: readonly FindingRef[];
  readonly unchangedCount: number;
  readonly regression: boolean;
}

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

export function parseGateFailedParam(
  raw: string | undefined
): boolean | undefined {
  if (raw === undefined || raw === '') {
    return undefined;
  }
  const v = raw.trim().toLowerCase();
  if (v === '1' || v === 'true' || v === 'yes') {
    return true;
  }
  if (v === '0' || v === 'false' || v === 'no') {
    return false;
  }
  return undefined;
}

export function filterReports(
  reports: readonly CoreCheckReport[],
  filters: ReportListFilters
): CoreCheckReport[] {
  let data = [...reports];

  if (filters.url) {
    const needle = filters.url.trim().toLowerCase();
    data = data.filter((r) => r.url.toLowerCase().includes(needle));
  }

  if (filters.failOn) {
    data = data.filter((r) => r.failOn === filters.failOn);
  }

  if (filters.gateFailed !== undefined) {
    data = data.filter((r) => Boolean(r['gateFailed']) === filters.gateFailed);
  }

  if (filters.since) {
    const sinceMs = Date.parse(filters.since);
    if (!Number.isNaN(sinceMs)) {
      data = data.filter((r) => Date.parse(r.createdAt) >= sinceMs);
    }
  }

  if (filters.q) {
    const q = filters.q.trim().toLowerCase();
    data = data.filter((r) => {
      const summary = String(r.summary ?? '').toLowerCase();
      return (
        r.url.toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q) ||
        summary.includes(q)
      );
    });
  }

  data.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));

  if (filters.limit !== undefined && filters.limit > 0) {
    data = data.slice(0, filters.limit);
  }

  return data;
}

export function toTrendPoint(report: CoreCheckReport): TrendPoint {
  const findingsCount =
    typeof report.findingsCount === 'number'
      ? report.findingsCount
      : Array.isArray(report.findings)
        ? report.findings.length
        : 0;

  const scoreRaw = report['digitalQualityScore'];
  const digitalQualityScore =
    typeof scoreRaw === 'number' && Number.isFinite(scoreRaw) ? scoreRaw : null;

  const gateRaw = report['gateFailed'];
  const gateFailed = typeof gateRaw === 'boolean' ? gateRaw : null;

  const countsRaw = report['severityCounts'];
  const severityCounts: Partial<Record<SeverityLevel, number>> =
    countsRaw !== null && typeof countsRaw === 'object' && !Array.isArray(countsRaw)
      ? (countsRaw as Partial<Record<SeverityLevel, number>>)
      : countSeverities(report.findings);

  return {
    id: report.id,
    createdAt: report.createdAt,
    url: report.url,
    digitalQualityScore,
    findingsCount,
    gateFailed,
    failOn: report.failOn ?? null,
    severityCounts
  };
}

function countSeverities(
  findings: ReadonlyArray<Vulnerability> | undefined
): Partial<Record<SeverityLevel, number>> {
  const out: Partial<Record<SeverityLevel, number>> = {};
  if (!findings) {
    return out;
  }
  for (const f of findings) {
    out[f.severity] = (out[f.severity] ?? 0) + 1;
  }
  return out;
}

export function buildTrends(
  reports: readonly CoreCheckReport[],
  options?: { readonly url?: string; readonly limit?: number }
): TrendsResponse {
  const filtered = filterReports(reports, {
    ...(options?.url ? { url: options.url } : {}),
    limit: options?.limit ?? 50
  });

  // series chronological ascending for charts
  const chronological = [...filtered].sort((a, b) =>
    a.createdAt < b.createdAt ? -1 : 1
  );
  const series = chronological.map(toTrendPoint);

  const scored = series
    .map((p) => p.digitalQualityScore)
    .filter((s): s is number => s !== null);
  const avgScore =
    scored.length === 0
      ? null
      : Math.round((scored.reduce((a, b) => a + b, 0) / scored.length) * 10) /
        10;

  const gateKnown = series.filter((p) => p.gateFailed !== null);
  const fails = gateKnown.filter((p) => p.gateFailed === true).length;
  const gateFailRate =
    gateKnown.length === 0
      ? 0
      : Math.round((fails / gateKnown.length) * 1000) / 1000;

  const latest = series.length > 0 ? series[series.length - 1]! : null;
  const previous = series.length > 1 ? series[series.length - 2]! : null;

  let scoreDelta: number | null = null;
  if (
    latest?.digitalQualityScore !== null &&
    latest?.digitalQualityScore !== undefined &&
    previous?.digitalQualityScore !== null &&
    previous?.digitalQualityScore !== undefined
  ) {
    scoreDelta =
      Math.round(
        (latest.digitalQualityScore - previous.digitalQualityScore) * 10
      ) / 10;
  }

  return {
    totalRuns: series.length,
    urlFilter: options?.url ?? null,
    gateFailRate,
    avgScore,
    scoreDelta,
    latest,
    previous,
    series
  };
}

function findingKey(f: Vulnerability): string {
  return `${f.ruleId}::${f.severity}`;
}

function toFindingRef(f: Vulnerability): FindingRef {
  return {
    ruleId: f.ruleId,
    severity: f.severity,
    title: f.title
  };
}

export function diffReports(
  base: CoreCheckReport,
  target: CoreCheckReport
): ReportDiffResponse {
  const baseFindings = base.findings ?? [];
  const targetFindings = target.findings ?? [];

  const baseMap = new Map(baseFindings.map((f) => [findingKey(f), f]));
  const targetMap = new Map(targetFindings.map((f) => [findingKey(f), f]));

  const added: FindingRef[] = [];
  const removed: FindingRef[] = [];
  let unchangedCount = 0;

  for (const [key, f] of targetMap) {
    if (!baseMap.has(key)) {
      added.push(toFindingRef(f));
    } else {
      unchangedCount += 1;
    }
  }
  for (const [key, f] of baseMap) {
    if (!targetMap.has(key)) {
      removed.push(toFindingRef(f));
    }
  }

  added.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  );
  removed.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  );

  const baseScore =
    typeof base['digitalQualityScore'] === 'number'
      ? (base['digitalQualityScore'] as number)
      : null;
  const targetScore =
    typeof target['digitalQualityScore'] === 'number'
      ? (target['digitalQualityScore'] as number)
      : null;
  const scoreDelta =
    baseScore !== null && targetScore !== null
      ? Math.round((targetScore - baseScore) * 10) / 10
      : null;

  const regression =
    added.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH') ||
    (scoreDelta !== null && scoreDelta < -5);

  return {
    baseId: base.id,
    targetId: target.id,
    baseCreatedAt: base.createdAt,
    targetCreatedAt: target.createdAt,
    url: target.url,
    scoreDelta,
    findingsCountDelta: targetFindings.length - baseFindings.length,
    added,
    removed,
    unchangedCount,
    regression
  };
}

/** Últimos 2 runs del mismo url (o global) para diff automático. */
export function resolveDiffPair(
  reports: readonly CoreCheckReport[],
  options: {
    readonly baseId?: string;
    readonly targetId?: string;
    readonly url?: string;
  }
): { base: CoreCheckReport; target: CoreCheckReport } | { error: string } {
  if (options.baseId && options.targetId) {
    const base = reports.find((r) => r.id === options.baseId);
    const target = reports.find((r) => r.id === options.targetId);
    if (!base || !target) {
      return { error: 'baseId o targetId no encontrados en este tenant.' };
    }
    return { base, target };
  }

  const scoped = filterReports(reports, {
    ...(options.url ? { url: options.url } : {}),
    limit: 2
  });

  if (scoped.length < 2) {
    return {
      error:
        'Se necesitan al menos 2 reportes (mismo url o tenant) para calcular diff.'
    };
  }

  // filterReports sorts newest first → [0]=target (newer), [1]=base (older)
  return { base: scoped[1]!, target: scoped[0]! };
}
