import { randomUUID } from 'node:crypto';
import type {
  CoreCheckReport,
  CreateReportInput,
  ReportListEnvelope,
  Vulnerability
} from '../types/contracts';
import {
  resolveReportHmacSecret,
  sealReportIntegrity
} from '../security/reportIntegrity';

/**
 * Persistencia en memoria con aislamiento por accountId + sello de integridad.
 */
export class ReportsStore {
  private _reports: CoreCheckReport[] = [];

  saveReport(payload: CreateReportInput, accountId: string): CoreCheckReport {
    return this.create(payload, accountId);
  }

  create(payload: CreateReportInput, accountId: string): CoreCheckReport {
    const draft = {
      ...payload,
      ...(payload.findings !== undefined
        ? { findings: this.cloneFindings(payload.findings) }
        : {}),
      id: randomUUID(),
      createdAt: new Date().toISOString(),
      accountId
    };

    const report = sealReportIntegrity(draft, resolveReportHmacSecret());
    this._reports.push(report);
    return report;
  }

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

  /**
   * Mutación controlada solo para tests de integridad (no expuesto por HTTP).
   * Simula tampering at-rest.
   */
  __dangerouslyReplaceForTests(report: CoreCheckReport): void {
    const idx = this._reports.findIndex((item) => item.id === report.id);
    if (idx >= 0) {
      this._reports[idx] = report;
    }
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
