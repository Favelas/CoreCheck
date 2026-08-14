import type { Request, Response } from 'express';
import { AppError } from '../errors/AppError';
import { reportsStore } from '../store/reports.store';

/**
 * POST /api/reports → 201
 * Requiere req.validatedReport (middleware validateReportBody).
 */
export function createReport(req: Request, res: Response): void {
  if (req.validatedReport === undefined) {
    throw new AppError(
      'BAD_REQUEST',
      'Payload de reporte no validado.',
      400
    );
  }

  const report = reportsStore.create(req.validatedReport);
  res.status(201).json(report);
}

/** GET /api/reports → 200 envelope { total, data } */
export function listReports(_req: Request, res: Response): void {
  res.status(200).json(reportsStore.list());
}

/** GET /api/reports/:id → 200 | 404 */
export function getReportById(req: Request, res: Response): void {
  const rawId = req.params['id'];
  const id = Array.isArray(rawId) ? rawId[0] : rawId;
  if (id === undefined || id === '') {
    throw new AppError('BAD_REQUEST', 'El parámetro id es obligatorio.', 400);
  }

  const report = reportsStore.findById(id);
  if (!report) {
    throw new AppError(
      'NOT_FOUND',
      `No existe un reporte con id "${id}".`,
      404
    );
  }

  res.status(200).json(report);
}
