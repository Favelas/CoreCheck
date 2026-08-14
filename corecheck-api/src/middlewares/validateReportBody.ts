import type { RequestHandler } from 'express';
import { AppError } from '../errors/AppError';
import type { CreateReportInput } from '../types/contracts';

/**
 * Valida body de POST /api/reports y normaliza el payload.
 * - Rechaza null / array / no-objeto / {}.
 * - Elimina id y createdAt del cliente (el servidor es dueño de la identidad).
 * - Adjunta CreateReportInput en req.validatedReport (ver express.d.ts).
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

  const { id: _ignoreId, createdAt: _ignoreCreatedAt, ...safePayload } = record;

  if (Object.keys(safePayload).length === 0) {
    next(
      new AppError(
        'BAD_REQUEST',
        'El body debe incluir al menos un campo de negocio (ej. url, findings).',
        400
      )
    );
    return;
  }

  // Sanitizado estructuralmente; el schema completo (url obligatorio, etc.)
  // se endurece en una iteración de contrato dedicada + tests nuevos.
  req.validatedReport = safePayload as CreateReportInput;
  next();
};
