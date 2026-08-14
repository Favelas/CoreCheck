import type { NextFunction, Request, RequestHandler, Response } from 'express';

/** Handler sync o async que puede rechazar / lanzar hacia errorHandler. */
export type AsyncRequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => void | Promise<void>;

/**
 * Envuelve handlers sync/async y reenvía errores a errorHandler.
 */
export function asyncHandler(fn: AsyncRequestHandler): RequestHandler {
  return (req, res, next) => {
    try {
      Promise.resolve(fn(req, res, next)).catch(next);
    } catch (err) {
      next(err);
    }
  };
}
