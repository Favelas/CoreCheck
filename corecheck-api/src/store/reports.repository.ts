import type {
  CoreCheckReport,
  CreateReportInput,
  ReportListEnvelope
} from '../types/contracts';

/**
 * Puerto de persistencia (Fase 3).
 * InMemory / JsonFile / (futuro) Postgres implementan el mismo contrato.
 */
export interface ReportsRepository {
  saveReport(payload: CreateReportInput, accountId: string): CoreCheckReport;
  getAllReports(accountId: string): ReportListEnvelope;
  getReportById(id: string, accountId: string): CoreCheckReport | undefined;
  clear(): void;
}

/** Extensión solo para tests de integridad (tampering). */
export interface ReportsRepositoryTestHooks {
  __dangerouslyReplaceForTests?(report: CoreCheckReport): void;
}
