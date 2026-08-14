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

  async saveReport(
    payload: CreateReportInput,
    accountId: string
  ): Promise<CoreCheckReport> {
    return this.create(payload, accountId);
  }

  async create(
    payload: CreateReportInput,
    accountId: string
  ): Promise<CoreCheckReport> {
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

  async getAllReports(accountId: string): Promise<ReportListEnvelope> {
    const data = this._reports.filter((item) => item.accountId === accountId);
    return {
      total: data.length,
      data
    };
  }

  async getReportById(
    id: string,
    accountId: string
  ): Promise<CoreCheckReport | undefined> {
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

  async clear(): Promise<void> {
    this._reports = [];
  }

  async purgeOlderThan(olderThanIso: string): Promise<number> {
    const before = this._reports.length;
    this._reports = this._reports.filter(
      (item) => item.createdAt >= olderThanIso
    );
    return before - this._reports.length;
  }

  private cloneFindings(
    findings: ReadonlyArray<Vulnerability>
  ): ReadonlyArray<Vulnerability> {
    return findings.map((finding) => ({ ...finding }));
  }
}

export const reportsStore = new InMemoryReportsStore();
export { InMemoryReportsStore as ReportsStore };
