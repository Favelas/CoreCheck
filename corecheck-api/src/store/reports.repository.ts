import type {
  CoreCheckReport,
  CreateReportInput,
  ReportListEnvelope
} from '../types/contracts';

/**
 * Puerto de persistencia (Fase 3) — async para soportar Postgres sin bloquear el event loop.
 * InMemory / JsonFile / Postgres implementan el mismo contrato.
 */
export interface ReportsRepository {
  saveReport(
    payload: CreateReportInput,
    accountId: string
  ): Promise<CoreCheckReport>;
  getAllReports(accountId: string): Promise<ReportListEnvelope>;
  getReportById(
    id: string,
    accountId: string
  ): Promise<CoreCheckReport | undefined>;
  clear(): Promise<void>;
  /** Borra reportes con createdAt < olderThanIso. Retorna cantidad eliminada. */
  purgeOlderThan(olderThanIso: string): Promise<number>;
}

/** Extensión solo para tests de integridad (tampering). */
export interface ReportsRepositoryTestHooks {
  __dangerouslyReplaceForTests?(report: CoreCheckReport): void | Promise<void>;
}
