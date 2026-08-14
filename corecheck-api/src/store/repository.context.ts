import type { ReportsRepository } from './reports.repository';

/**
 * Contexto de proceso — createApp() fija el repositorio activo.
 * Controllers no importan una implementación concreta (DIP).
 */
let activeRepository: ReportsRepository | undefined;

export function setReportsRepository(repository: ReportsRepository): void {
  activeRepository = repository;
}

export function getReportsRepository(): ReportsRepository {
  if (activeRepository === undefined) {
    throw new Error(
      'ReportsRepository no configurado. Llame a createApp() o setReportsRepository().'
    );
  }
  return activeRepository;
}
