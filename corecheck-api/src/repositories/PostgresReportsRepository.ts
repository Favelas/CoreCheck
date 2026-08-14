import type { Pool, QueryResultRow } from 'pg';
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
import type { ReportsRepository } from '../store/reports.repository';

export interface ReportRow extends QueryResultRow {
  id: string;
  account_id: string;
  url: string;
  content_hash: string;
  hmac_signature: string | null;
  integrity_algorithm: string;
  payload: CoreCheckReport | string;
  created_at: Date | string;
}

/**
 * Adaptador Postgres (Fase 3.2) — aislamiento account_id + payload JSONB.
 */
export class PostgresReportsRepository implements ReportsRepository {
  constructor(private readonly pool: Pool) {}

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

    await this.pool.query(
      `INSERT INTO reports (
         id, account_id, url, content_hash, hmac_signature,
         integrity_algorithm, payload, created_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`,
      [
        report.id,
        report.accountId,
        report.url,
        report.contentHash,
        report.hmacSignature ?? null,
        report.integrityAlgorithm,
        JSON.stringify(report),
        report.createdAt
      ]
    );

    return report;
  }

  async getAllReports(accountId: string): Promise<ReportListEnvelope> {
    const result = await this.pool.query<ReportRow>(
      `SELECT * FROM reports
       WHERE account_id = $1
       ORDER BY created_at DESC`,
      [accountId]
    );

    const data = result.rows.map((row) => this.mapRow(row));
    return { total: data.length, data };
  }

  async getReportById(
    id: string,
    accountId: string
  ): Promise<CoreCheckReport | undefined> {
    const result = await this.pool.query<ReportRow>(
      `SELECT * FROM reports
       WHERE id = $1 AND account_id = $2
       LIMIT 1`,
      [id, accountId]
    );

    const row = result.rows[0];
    return row === undefined ? undefined : this.mapRow(row);
  }

  async clear(): Promise<void> {
    await this.pool.query('DELETE FROM reports');
  }

  async purgeOlderThan(olderThanIso: string): Promise<number> {
    const result = await this.pool.query(
      'DELETE FROM reports WHERE created_at < $1::timestamptz',
      [olderThanIso]
    );
    return result.rowCount ?? 0;
  }

  private mapRow(row: ReportRow): CoreCheckReport {
    const payload =
      typeof row.payload === 'string'
        ? (JSON.parse(row.payload) as CoreCheckReport)
        : row.payload;

    return {
      ...payload,
      id: row.id,
      accountId: row.account_id,
      url: row.url,
      contentHash: row.content_hash,
      integrityAlgorithm:
        row.integrity_algorithm === 'HMAC-SHA256' ? 'HMAC-SHA256' : 'SHA-256',
      ...(row.hmac_signature
        ? { hmacSignature: row.hmac_signature }
        : {}),
      createdAt:
        typeof row.created_at === 'string'
          ? row.created_at
          : row.created_at.toISOString()
    };
  }

  private cloneFindings(
    findings: ReadonlyArray<Vulnerability>
  ): ReadonlyArray<Vulnerability> {
    return findings.map((finding) => ({ ...finding }));
  }
}
