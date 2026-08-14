import type { Request, Response } from 'express';
import { AppError } from '../errors/AppError';
import {
  resolveReportHmacSecret,
  verifyReportIntegrity
} from '../security/reportIntegrity';
import { getReportsRepository } from '../store/repository.context';
import type { ReportVerifyResponse } from '../types/contracts';

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

function requireReportId(req: Request): string {
  const rawId = req.params['id'];
  const id = Array.isArray(rawId) ? rawId[0] : rawId;
  if (id === undefined || id === '') {
    throw new AppError('BAD_REQUEST', 'El parámetro id es obligatorio.', 400);
  }
  return id;
}

export async function createReport(req: Request, res: Response): Promise<void> {
  if (req.validatedReport === undefined) {
    throw new AppError(
      'BAD_REQUEST',
      'Payload de reporte no validado.',
      400
    );
  }

  const accountId = requireAccountId(req);
  const report = await getReportsRepository().saveReport(
    req.validatedReport,
    accountId
  );
  res.status(201).json(report);
}

export async function listReports(req: Request, res: Response): Promise<void> {
  const accountId = requireAccountId(req);
  res
    .status(200)
    .json(await getReportsRepository().getAllReports(accountId));
}

export async function getReportById(
  req: Request,
  res: Response
): Promise<void> {
  const accountId = requireAccountId(req);
  const id = requireReportId(req);

  const report = await getReportsRepository().getReportById(id, accountId);
  if (!report) {
    throw new AppError(
      'NOT_FOUND',
      `No existe un reporte con id "${id}".`,
      404
    );
  }

  res.status(200).json(report);
}

export async function verifyReport(req: Request, res: Response): Promise<void> {
  const accountId = requireAccountId(req);
  const id = requireReportId(req);

  const report = await getReportsRepository().getReportById(id, accountId);
  if (!report) {
    throw new AppError(
      'NOT_FOUND',
      `No existe un reporte con id "${id}".`,
      404
    );
  }

  const verdict = verifyReportIntegrity(report, resolveReportHmacSecret());
  const body: ReportVerifyResponse = {
    valid: verdict.valid,
    algorithm: verdict.algorithm,
    contentHash: verdict.contentHash,
    hashMatches: verdict.hashMatches,
    hmacVerified: verdict.hmacVerified,
    message: verdict.message
  };

  res.status(200).json(body);
}
