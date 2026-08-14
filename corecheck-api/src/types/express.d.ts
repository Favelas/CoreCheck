import type { Request } from 'express';
import type { CreateReportInput } from './contracts';

/**
 * Augmentation de Express.Request — payload sanitizado por validateReportBody.
 * id/createdAt del cliente ya fueron eliminados.
 */
declare global {
  namespace Express {
    interface Request {
      validatedReport?: CreateReportInput;
    }
  }
}

/** Request tras pasar validateReportBody (validatedReport garantizado). */
export interface ValidatedRequest extends Request {
  validatedReport: CreateReportInput;
}

export {};
