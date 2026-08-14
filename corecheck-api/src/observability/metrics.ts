/**
 * Métricas in-process (Fase 4.1) — sin PII; aptas para scrape/ops.
 */
export interface MetricsSnapshot {
  readonly startedAt: string;
  readonly uptimeSeconds: number;
  readonly requestsTotal: number;
  readonly requestsByStatus: Readonly<Record<string, number>>;
  readonly errors5xx: number;
  readonly rateLimited: number;
  readonly avgLatencyMs: number;
}

class MetricsRegistry {
  private readonly startedAtMs = Date.now();
  private readonly startedAtIso = new Date(this.startedAtMs).toISOString();
  private requestsTotal = 0;
  private errors5xx = 0;
  private rateLimited = 0;
  private latencySumMs = 0;
  private readonly byStatus = new Map<string, number>();

  recordRequest(statusCode: number, latencyMs: number): void {
    this.requestsTotal += 1;
    this.latencySumMs += Math.max(0, latencyMs);
    const key = String(statusCode);
    this.byStatus.set(key, (this.byStatus.get(key) ?? 0) + 1);
    if (statusCode >= 500) {
      this.errors5xx += 1;
    }
    if (statusCode === 429) {
      this.rateLimited += 1;
    }
  }

  snapshot(): MetricsSnapshot {
    const requestsByStatus: Record<string, number> = {};
    for (const [code, count] of this.byStatus.entries()) {
      requestsByStatus[code] = count;
    }

    return {
      startedAt: this.startedAtIso,
      uptimeSeconds: Math.floor((Date.now() - this.startedAtMs) / 1000),
      requestsTotal: this.requestsTotal,
      requestsByStatus,
      errors5xx: this.errors5xx,
      rateLimited: this.rateLimited,
      avgLatencyMs:
        this.requestsTotal === 0
          ? 0
          : Math.round((this.latencySumMs / this.requestsTotal) * 100) / 100
    };
  }

  reset(): void {
    this.requestsTotal = 0;
    this.errors5xx = 0;
    this.rateLimited = 0;
    this.latencySumMs = 0;
    this.byStatus.clear();
  }
}

export const metricsRegistry = new MetricsRegistry();
