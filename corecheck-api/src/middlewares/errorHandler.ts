import type { ErrorRequestHandler } from 'express';
import { AppError } from '../errors/AppError';
import type { ApiErrorBody } from '../types/contracts';

/**
 * Error handler central (4 args — firma Express ErrorRequestHandler).
 * Contrato estable ApiErrorBody: { error, message }
 * Nunca filtra stack al cliente.
 */
export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  const isAppError = err instanceof AppError;
  const statusCode = isAppError ? err.statusCode : 500;
  const body: ApiErrorBody = {
    error: isAppError ? err.code : 'INTERNAL_ERROR',
    message: isAppError ? err.message : 'Error interno del servidor.'
  };

  if (!isAppError) {
    console.error('[CoreCheck API] Unhandled error:', err);
  }

  res.status(statusCode).json(body);
};
