import fs from 'node:fs';
import path from 'node:path';
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
import type { ReportsRepository } from './reports.repository';

const STORE_VERSION = 1 as const;

interface ReportsFileDocument {
  readonly version: typeof STORE_VERSION;
  reports: CoreCheckReport[];
}

export interface JsonFileReportsStoreOptions {
  readonly filePath: string;
}

/**
 * Persistencia durable en JSON (Fase 3.1).
 */
export class JsonFileReportsStore implements ReportsRepository {
  private readonly filePath: string;
  private _reports: CoreCheckReport[] = [];

  constructor(options: JsonFileReportsStoreOptions) {
    this.filePath = path.resolve(options.filePath);
    this.loadFromDisk();
  }

  async saveReport(
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
    this.persistToDisk();
    return report;
  }

  async getAllReports(accountId: string): Promise<ReportListEnvelope> {
    const data = this._reports.filter((item) => item.accountId === accountId);
    return { total: data.length, data };
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

  async clear(): Promise<void> {
    this._reports = [];
    this.persistToDisk();
  }

  async purgeOlderThan(olderThanIso: string): Promise<number> {
    const before = this._reports.length;
    this._reports = this._reports.filter(
      (item) => item.createdAt >= olderThanIso
    );
    const removed = before - this._reports.length;
    if (removed > 0) {
      this.persistToDisk();
    }
    return removed;
  }

  private loadFromDisk(): void {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    if (!fs.existsSync(this.filePath)) {
      this._reports = [];
      this.persistToDisk();
      return;
    }

    const raw = fs.readFileSync(this.filePath, 'utf8');
    if (raw.trim() === '') {
      this._reports = [];
      return;
    }

    const parsed = JSON.parse(raw) as ReportsFileDocument;
    if (parsed.version !== STORE_VERSION || !Array.isArray(parsed.reports)) {
      throw new Error(
        `Formato inválido en ${this.filePath}: se esperaba version=${STORE_VERSION}`
      );
    }

    this._reports = parsed.reports;
  }

  private persistToDisk(): void {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const document: ReportsFileDocument = {
      version: STORE_VERSION,
      reports: this._reports
    };
    const serialized = `${JSON.stringify(document, null, 2)}\n`;
    const tmpPath = `${this.filePath}.${process.pid}.tmp`;

    fs.writeFileSync(tmpPath, serialized, 'utf8');
    try {
      if (fs.existsSync(this.filePath)) {
        fs.unlinkSync(this.filePath);
      }
      fs.renameSync(tmpPath, this.filePath);
    } catch {
      fs.writeFileSync(this.filePath, serialized, 'utf8');
      try {
        fs.unlinkSync(tmpPath);
      } catch {
        /* ignore */
      }
    }
  }

  private cloneFindings(
    findings: ReadonlyArray<Vulnerability>
  ): ReadonlyArray<Vulnerability> {
    return findings.map((finding) => ({ ...finding }));
  }
}
