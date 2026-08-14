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
import type {
  ReportsRepository,
  ReportsRepositoryTestHooks
} from './reports.repository';

/**
 * Persistencia en memoria — default para tests (determinista, sin I/O).
 */
export class InMemoryReportsStore
  implements ReportsRepository, ReportsRepositoryTestHooks
{
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

/** Singleton de memoria (tests / fallback). */
export const reportsStore = new InMemoryReportsStore();

/** @deprecated Alias de compat — preferir InMemoryReportsStore. */
export { InMemoryReportsStore as ReportsStore };
