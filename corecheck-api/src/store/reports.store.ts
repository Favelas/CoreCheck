import { randomUUID } from 'node:crypto';
import type {
  CoreCheckReport,
  CreateReportInput,
  ReportListEnvelope,
  Vulnerability
} from '../types/contracts';

/**
 * Persistencia en memoria con aislamiento por accountId (Fase 1.2).
 */
export class ReportsStore {
  private _reports: CoreCheckReport[] = [];

  /**
   * Alias enterprise: saveReport(payload, accountId).
   * El servidor asigna id, createdAt y accountId (no confía en el cliente).
   */
  saveReport(payload: CreateReportInput, accountId: string): CoreCheckReport {
    return this.create(payload, accountId);
  }

  create(payload: CreateReportInput, accountId: string): CoreCheckReport {
    const report: CoreCheckReport = {
      ...payload,
      ...(payload.findings !== undefined
        ? { findings: this.cloneFindings(payload.findings) }
        : {}),
      id: randomUUID(),
      createdAt: new Date().toISOString(),
      accountId
    };

    this._reports.push(report);
    return report;
  }

  /** Alias: getAllReports(accountId) */
  getAllReports(accountId: string): ReportListEnvelope {
    return this.list(accountId);
  }

  list(accountId: string): ReportListEnvelope {
    const data = this._reports.filter((item) => item.accountId === accountId);
    return {
      total: data.length,
      data
    };
  }

  /** Alias: getReportById(id, accountId) — sin match de tenant → undefined (404). */
  getReportById(id: string, accountId: string): CoreCheckReport | undefined {
    return this.findById(id, accountId);
  }

  findById(id: string, accountId: string): CoreCheckReport | undefined {
    const report = this._reports.find((item) => item.id === id);
    if (!report || report.accountId !== accountId) {
      return undefined;
    }
    return report;
  }

  clear(): void {
    this._reports = [];
  }

  private cloneFindings(
    findings: ReadonlyArray<Vulnerability>
  ): ReadonlyArray<Vulnerability> {
    return findings.map((finding) => ({ ...finding }));
  }
}

export const reportsStore = new ReportsStore();
