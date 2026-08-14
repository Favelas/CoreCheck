import { randomUUID } from 'node:crypto';
import type {
  CoreCheckReport,
  CreateReportInput,
  ReportListEnvelope,
  Vulnerability
} from '../types/contracts';

/**
 * Capa de datos en memoria (Fase C.2).
 * - Controllers no mutan el array directamente.
 * - Tipado con CoreCheckReport / Vulnerability (contratos de dominio).
 * - Intercambiable por Postgres/SQLite sin cambiar rutas HTTP.
 */
export class ReportsStore {
  private _reports: CoreCheckReport[] = [];

  /**
   * Persiste un reporte. El servidor asigna id y createdAt.
   * Si vienen findings, se clonan para no compartir referencias mutables.
   */
  create(payload: CreateReportInput): CoreCheckReport {
    const report: CoreCheckReport = {
      ...payload,
      ...(payload.findings !== undefined
        ? { findings: this.cloneFindings(payload.findings) }
        : {}),
      id: randomUUID(),
      createdAt: new Date().toISOString()
    };

    this._reports.push(report);
    return report;
  }

  list(): ReportListEnvelope {
    return {
      total: this._reports.length,
      data: this._reports
    };
  }

  findById(id: string): CoreCheckReport | undefined {
    return this._reports.find((item) => item.id === id);
  }

  /** Vacía el almacén — solo para tests (aislamiento entre casos). */
  clear(): void {
    this._reports = [];
  }

  private cloneFindings(
    findings: ReadonlyArray<Vulnerability>
  ): ReadonlyArray<Vulnerability> {
    return findings.map((finding) => ({ ...finding }));
  }
}

/** Singleton de proceso — una sola fuente de verdad mientras corre Node. */
export const reportsStore = new ReportsStore();
