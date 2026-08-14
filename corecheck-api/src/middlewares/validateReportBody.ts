import type { RequestHandler } from 'express';
import { AppError } from '../errors/AppError';
import { isDeniedIngestField } from '../security/sensitiveFields';
import type { CreateReportInput } from '../types/contracts';

/**
 * Valida y sanitiza body de POST /api/reports.
 * - Objeto JSON no vacío.
 * - `url` obligatorio (string no vacío).
 * - Strip de id/createdAt y denylist de secretos (SEC-API-01).
 */
export const validateReportBody: RequestHandler = (req, _res, next) => {
  const body: unknown = req.body;

  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    next(
      new AppError(
        'BAD_REQUEST',
        'El body debe ser un objeto JSON (reporte de auditoría).',
        400
      )
    );
    return;
  }

  const record = body as Record<string, unknown>;

  if (Object.keys(record).length === 0) {
    next(new AppError('BAD_REQUEST', 'El body no puede estar vacío.', 400));
    return;
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (isDeniedIngestField(key)) {
      continue;
    }
    sanitized[key] = value;
  }

  const url = sanitized['url'];
  if (typeof url !== 'string' || url.trim() === '') {
    next(
      new AppError(
        'BAD_REQUEST',
        'El campo url es obligatorio y debe ser un string no vacío.',
        400
      )
    );
    return;
  }

  sanitized['url'] = url.trim();
  req.validatedReport = sanitized as CreateReportInput;
  next();
};
