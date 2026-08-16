import type { Request, Response } from 'express';
import { AppError } from '../errors/AppError';
import {
  resolveReportHmacSecret,
  verifyReportIntegrity
} from '../security/reportIntegrity';
import {
  buildTrends,
  diffReports,
  filterReports,
  parseGateFailedParam,
  resolveDiffPair,
  type ReportListFilters
} from '../services/reportAnalytics';
import { getReportsRepository } from '../store/repository.context';
import type {
  ReportVerifyResponse,
  SeverityLevel
} from '../types/contracts';

const VALID_SEVERITIES = new Set<SeverityLevel>([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
]);

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

function queryString(req: Request, key: string): string | undefined {
  const raw = req.query[key];
  if (typeof raw === 'string' && raw.trim() !== '') {
    return raw.trim();
  }
  return undefined;
}

function parseFilters(req: Request): ReportListFilters {
  const filters: ReportListFilters = {};

  const url = queryString(req, 'url');
  if (url) {
    (filters as { url?: string }).url = url;
  }

  const failOnRaw = queryString(req, 'failOn');
  if (failOnRaw) {
    const upper = failOnRaw.toUpperCase() as SeverityLevel;
    if (!VALID_SEVERITIES.has(upper)) {
      throw new AppError(
        'BAD_REQUEST',
        `failOn inválido: "${failOnRaw}".`,
        400
      );
    }
    (filters as { failOn?: SeverityLevel }).failOn = upper;
  }

  const gateFailed = parseGateFailedParam(queryString(req, 'gateFailed'));
  if (gateFailed !== undefined) {
    (filters as { gateFailed?: boolean }).gateFailed = gateFailed;
  }

  const since = queryString(req, 'since');
  if (since) {
    (filters as { since?: string }).since = since;
  }

  const q = queryString(req, 'q');
  if (q) {
    (filters as { q?: string }).q = q;
  }

  const limitRaw = queryString(req, 'limit');
  if (limitRaw) {
    const n = Number(limitRaw);
    if (!Number.isFinite(n) || n < 1) {
      throw new AppError('BAD_REQUEST', 'limit debe ser un entero >= 1.', 400);
    }
    (filters as { limit?: number }).limit = Math.min(Math.floor(n), 200);
  }

  return filters;
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
  const filters = parseFilters(req);
  const envelope = await getReportsRepository().getAllReports(accountId);
  const data = filterReports(envelope.data, filters);
  res.status(200).json({ total: data.length, data });
}

export async function getTrends(req: Request, res: Response): Promise<void> {
  const accountId = requireAccountId(req);
  const envelope = await getReportsRepository().getAllReports(accountId);
  const url = queryString(req, 'url');
  const limitRaw = queryString(req, 'limit');
  const limit = limitRaw ? Number(limitRaw) : 50;
  if (limitRaw && (!Number.isFinite(limit) || limit < 1)) {
    throw new AppError('BAD_REQUEST', 'limit debe ser un entero >= 1.', 400);
  }

  const trendOpts: { url?: string; limit: number } = {
    limit: Math.min(Math.floor(limit), 200)
  };
  if (url) {
    trendOpts.url = url;
  }
  res.status(200).json(buildTrends(envelope.data, trendOpts));
}

export async function getDiff(req: Request, res: Response): Promise<void> {
  const accountId = requireAccountId(req);
  const envelope = await getReportsRepository().getAllReports(accountId);
  const options: {
    baseId?: string;
    targetId?: string;
    url?: string;
  } = {};
  const baseId = queryString(req, 'baseId');
  const targetId = queryString(req, 'targetId');
  const url = queryString(req, 'url');
  if (baseId) options.baseId = baseId;
  if (targetId) options.targetId = targetId;
  if (url) options.url = url;

  const pair = resolveDiffPair(envelope.data, options);

  if ('error' in pair) {
    throw new AppError('BAD_REQUEST', pair.error, 400);
  }

  res.status(200).json(diffReports(pair.base, pair.target));
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
