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
      /** Tenant resuelto desde la API key (Fase 1.2). */
      accountId?: string;
      /** Correlación de request (Fase 4.1). */
      requestId?: string;
    }
  }
}

/** Request autenticado con tenant. */
export interface TenantRequest extends Request {
  accountId: string;
}

/** Request tras validateReportBody (validatedReport garantizado). */
export interface ValidatedRequest extends Request {
  validatedReport: CreateReportInput;
  accountId: string;
}

export {};
