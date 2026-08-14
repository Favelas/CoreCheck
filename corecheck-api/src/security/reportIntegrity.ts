import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { CoreCheckReport } from '../types/contracts';

export type ReportIntegrityAlgorithm = 'SHA-256' | 'HMAC-SHA256';

export interface ReportIntegrityFields {
  readonly contentHash: string;
  readonly integrityAlgorithm: ReportIntegrityAlgorithm;
  readonly hmacSignature?: string;
}

export interface ReportIntegrityVerdict {
  readonly valid: boolean;
  readonly algorithm: ReportIntegrityAlgorithm;
  readonly contentHash: string;
  readonly hashMatches: boolean;
  readonly hmacVerified: boolean | null;
  readonly message: string;
}

const INTEGRITY_META_KEYS = new Set([
  'contentHash',
  'integrityAlgorithm',
  'hmacSignature'
]);

/** Serialización determinista (mismas reglas que attestation del CLI). */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = sortKeysDeep(obj[key]);
    }
    return out;
  }
  return value;
}

/**
 * Payload firmable: reporte sin metadatos de integridad.
 * version fija evita colisiones con evoluciones futuras del schema.
 */
export function buildReportIntegrityPayload(
  report: Omit<CoreCheckReport, keyof ReportIntegrityFields> &
    Partial<ReportIntegrityFields>
): Record<string, unknown> {
  const payload: Record<string, unknown> = { version: 1 };
  for (const [key, value] of Object.entries(report)) {
    if (INTEGRITY_META_KEYS.has(key)) {
      continue;
    }
    payload[key] = value;
  }
  return payload;
}

export function computeContentHash(payload: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalize(payload), 'utf8').digest('hex');
}

export function computeReportHmac(
  payload: Record<string, unknown>,
  secret: string
): string {
  return createHmac('sha256', secret)
    .update(canonicalize(payload), 'utf8')
    .digest('hex');
}

function safeEqualHex(a: string, b: string): boolean {
  try {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length === 0 || ba.length !== bb.length) {
      return false;
    }
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

export function resolveReportHmacSecret(
  env: NodeJS.ProcessEnv = process.env
): string | undefined {
  const secret = env['CORECHECK_REPORT_HMAC_SECRET'];
  if (typeof secret === 'string' && secret.trim() !== '') {
    return secret.trim();
  }
  return undefined;
}

/**
 * Adjunta contentHash (+ HMAC si hay secret) a un reporte ya materializado
 * (id/accountId/createdAt asignados).
 */
export function sealReportIntegrity(
  report: Omit<CoreCheckReport, keyof ReportIntegrityFields>,
  hmacSecret?: string
): CoreCheckReport {
  const payload = buildReportIntegrityPayload(report);
  const contentHash = computeContentHash(payload);

  if (hmacSecret !== undefined && hmacSecret !== '') {
    return {
      ...(report as CoreCheckReport),
      contentHash,
      integrityAlgorithm: 'HMAC-SHA256',
      hmacSignature: computeReportHmac(payload, hmacSecret)
    };
  }

  return {
    ...(report as CoreCheckReport),
    contentHash,
    integrityAlgorithm: 'SHA-256'
  };
}

export function verifyReportIntegrity(
  report: CoreCheckReport,
  hmacSecret?: string
): ReportIntegrityVerdict {
  const payload = buildReportIntegrityPayload(report);
  const actualHash = computeContentHash(payload);
  const hashMatches = safeEqualHex(actualHash, report.contentHash);

  const expectsHmac =
    report.integrityAlgorithm === 'HMAC-SHA256' ||
    Boolean(report.hmacSignature);

  let hmacVerified: boolean | null = null;
  if (expectsHmac) {
    if (hmacSecret === undefined || hmacSecret === '') {
      return {
        valid: false,
        algorithm: 'HMAC-SHA256',
        contentHash: actualHash,
        hashMatches,
        hmacVerified: null,
        message:
          'El reporte requiere HMAC pero no hay CORECHECK_REPORT_HMAC_SECRET.'
      };
    }
    if (report.hmacSignature === undefined) {
      hmacVerified = false;
    } else {
      const expected = computeReportHmac(payload, hmacSecret);
      hmacVerified = safeEqualHex(expected, report.hmacSignature);
    }
  }

  const valid =
    hashMatches && (hmacVerified === null ? true : hmacVerified === true);

  let message: string;
  if (valid) {
    message =
      hmacVerified === true
        ? 'Integridad OK: SHA-256 y HMAC-SHA256 verificados.'
        : 'Integridad OK: SHA-256 verificado.';
  } else if (!hashMatches) {
    message =
      'FALLO de integridad: contentHash no coincide (reporte alterado o incompleto).';
  } else {
    message = 'FALLO de autenticidad: firma HMAC-SHA256 inválida.';
  }

  return {
    valid,
    algorithm: expectsHmac ? 'HMAC-SHA256' : 'SHA-256',
    contentHash: actualHash,
    hashMatches,
    hmacVerified,
    message
  };
}
