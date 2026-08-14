/**
 * Error de dominio HTTP — forma estable para el errorHandler.
 * Contrato de error (enterprise): { error: CODE, message: string }
 */

/** Códigos máquina conocidos; ampliables solo vía unión tipada (no strings sueltos). */
export type AppErrorCode = 'BAD_REQUEST' | 'NOT_FOUND' | 'INTERNAL_ERROR';

export class AppError extends Error {
  readonly code: AppErrorCode;
  readonly statusCode: number;

  constructor(code: AppErrorCode, message: string, statusCode: number) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.statusCode = statusCode;
    // Garantiza instanceof correcto al extender Error bajo CommonJS/tsx
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
