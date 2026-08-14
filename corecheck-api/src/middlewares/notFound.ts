import type { RequestHandler } from 'express';
import { AppError } from '../errors/AppError';

/**
 * 404 para rutas no registradas (después de todos los routers).
 * Delega el shape { error, message } al errorHandler vía AppError.
 */
export const notFoundHandler: RequestHandler = (req, _res, next) => {
  next(
    new AppError(
      'NOT_FOUND',
      `Ruta no encontrada: ${req.method} ${req.originalUrl}`,
      404
    )
  );
};
