import type { Request, Response } from 'express';
import { AppError } from '../errors/AppError';
import { reportsStore } from '../store/reports.store';

function requireAccountId(req: Request): string {
  const accountId = req.accountId;
  if (accountId === undefined || accountId === '') {
    throw new AppError(
      'UNAUTHORIZED',
      'Contexto de tenant ausente (accountId).',
      401
    );
  }
  return accountId;
}

/**
 * POST /api/reports → 201
 * Requiere req.validatedReport + req.accountId.
 */
export function createReport(req: Request, res: Response): void {
  if (req.validatedReport === undefined) {
    throw new AppError(
      'BAD_REQUEST',
      'Payload de reporte no validado.',
      400
    );
  }

  const accountId = requireAccountId(req);
  const report = reportsStore.saveReport(req.validatedReport, accountId);
  res.status(201).json(report);
}

/** GET /api/reports → 200 envelope scoped al tenant */
export function listReports(req: Request, res: Response): void {
  const accountId = requireAccountId(req);
  res.status(200).json(reportsStore.getAllReports(accountId));
}

/**
 * GET /api/reports/:id → 200 | 404
 * Cross-tenant: mismo mensaje 404 (no revelar existencia en otro account).
 */
export function getReportById(req: Request, res: Response): void {
  const accountId = requireAccountId(req);
  const rawId = req.params['id'];
  const id = Array.isArray(rawId) ? rawId[0] : rawId;
  if (id === undefined || id === '') {
    throw new AppError('BAD_REQUEST', 'El parámetro id es obligatorio.', 400);
  }

  const report = reportsStore.getReportById(id, accountId);
  if (!report) {
    throw new AppError(
      'NOT_FOUND',
      `No existe un reporte con id "${id}".`,
      404
    );
  }

  res.status(200).json(report);
}
