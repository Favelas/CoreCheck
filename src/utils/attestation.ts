import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  AuditAttestation,
  AuditFinding,
  AuditReportBundle,
  SeverityLevel
} from '../types/audit.js';

export type AttestationAlgorithm = 'SHA-256' | 'HMAC-SHA256';

/** Payload canónico firmado / hasheado (orden de claves estable). */
export interface AttestationPayload {
  version: 1;
  cliVersion: string;
  target: string;
  timestampUtc: string;
  environment: string;
  failOn: SeverityLevel;
  gateFailed: boolean;
  activeFuzzing: boolean;
  scannedPages: string[];
  digitalQualityScore: number;
  maxCvssScore: number;
  severityCounts: Record<SeverityLevel, number>;
  findingFingerprints: string[];
}

export interface BuildAttestationOptions {
  licenseTier?: string;
  organization?: string;
  accountId?: string;
  localDashboardPath?: string;
  dashboardUrl?: string;
  verificationUrl?: string;
  dashboardBaseUrl?: string;
  /** Flags de ejecución incluidos en el payload. */
  activeFuzzing?: boolean;
  /** Override versión CLI (tests). */
  cliVersion?: string;
  /** Secret HMAC (default: env CORECHECK_ATTESTATION_SECRET). */
  hmacSecret?: string;
}

function resolveCliVersion(override?: string): string {
  if (override) return override;
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const pkgPath = path.resolve(here, '../../package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as { version?: string };
    return pkg.version ?? '1.0.0';
  } catch {
    return process.env.npm_package_version ?? '1.0.0';
  }
}

/** Serialización determinista: ordena claves de objetos en profundidad. */
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

function findingFingerprint(f: AuditFinding): string {
  const url = f.evidence.url ?? '';
  const selector = f.evidence.selector ?? '';
  return `${f.ruleId}|${f.severity}|${f.id}|${url}|${selector}`;
}

/**
 * Construye el payload crudo de attestation a partir del bundle + flags de ejecución.
 */
export function buildAttestationPayload(
  bundle: AuditReportBundle,
  options: BuildAttestationOptions = {}
): AttestationPayload {
  const fingerprints = bundle.findings
    .map(findingFingerprint)
    .sort((a, b) => a.localeCompare(b));

  const scannedPages = [...bundle.scannedPages].sort((a, b) => a.localeCompare(b));

  return {
    version: 1,
    cliVersion: resolveCliVersion(options.cliVersion),
    target: bundle.target,
    timestampUtc: bundle.timestamp,
    environment: bundle.environment ?? 'prod',
    failOn: bundle.failOn,
    gateFailed: bundle.gateFailed,
    activeFuzzing: Boolean(options.activeFuzzing),
    scannedPages,
    digitalQualityScore: bundle.digitalQualityScore,
    maxCvssScore: bundle.maxCvssScore,
    severityCounts: {
      CRITICAL: bundle.severityCounts.CRITICAL ?? 0,
      HIGH: bundle.severityCounts.HIGH ?? 0,
      MEDIUM: bundle.severityCounts.MEDIUM ?? 0,
      LOW: bundle.severityCounts.LOW ?? 0,
      INFO: bundle.severityCounts.INFO ?? 0
    },
    findingFingerprints: fingerprints
  };
}

/** SHA-256 hex del payload canónico. */
export function computeAttestationHash(payload: AttestationPayload): string {
  return createHash('sha256').update(canonicalize(payload), 'utf8').digest('hex');
}

/** HMAC-SHA256 hex del mismo payload (requiere secret). */
export function computeAttestationHmac(
  payload: AttestationPayload,
  secret: string
): string {
  return createHmac('sha256', secret)
    .update(canonicalize(payload), 'utf8')
    .digest('hex');
}

export function verifyAttestationHmac(
  payload: AttestationPayload,
  secret: string,
  expectedHex: string
): boolean {
  const actual = computeAttestationHmac(payload, secret);
  try {
    const a = Buffer.from(actual, 'hex');
    const b = Buffer.from(expectedHex, 'hex');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/** Convierte ruta local a file:// para dashboard offline. */
export function pathToDashboardUrl(filePath: string): string {
  return pathToFileURL(path.resolve(filePath)).href;
}

export function resolveDashboardBaseUrl(override?: string): string | undefined {
  const raw = override || process.env.CORECHECK_DASHBOARD_URL;
  if (!raw || !raw.trim()) return undefined;
  return raw.replace(/\/+$/, '');
}

/** Payload compacto embebido en el QR del PDF (verificación offline). */
export function buildQrAttestationPayload(attestation: AuditAttestation): string {
  return canonicalize({
    v: 1,
    type: 'corecheck-attestation',
    hash: attestation.attestationHash,
    alg: attestation.algorithm,
    hmac: attestation.hmacSignature ?? null,
    cli: attestation.cliVersion,
    ts: attestation.signedAtUtc,
    dash: attestation.dashboardUrl
  });
}

/**
 * Genera metadatos completos de attestation (hash + HMAC opcional + URLs dashboard).
 */
export function buildAttestation(
  bundle: AuditReportBundle,
  meta: BuildAttestationOptions = {}
): AuditAttestation {
  const payload = buildAttestationPayload(bundle, meta);
  const attestationHash = computeAttestationHash(payload);

  const secret =
    meta.hmacSecret ?? process.env.CORECHECK_ATTESTATION_SECRET?.trim() ?? '';
  const useHmac = secret.length > 0;
  const hmacSignature = useHmac ? computeAttestationHmac(payload, secret) : undefined;
  const algorithm: AttestationAlgorithm = useHmac ? 'HMAC-SHA256' : 'SHA-256';

  const shortId = attestationHash.slice(0, 16);

  let dashboardUrl: string;
  let verificationUrl: string;

  if (meta.dashboardUrl) {
    dashboardUrl = meta.dashboardUrl;
    verificationUrl = meta.verificationUrl ?? `${meta.dashboardUrl}#attestation`;
  } else if (meta.localDashboardPath) {
    dashboardUrl = pathToDashboardUrl(meta.localDashboardPath);
    verificationUrl = `${dashboardUrl}#attestation`;
  } else if (bundle.attestation?.dashboardUrl?.startsWith('file:')) {
    dashboardUrl = bundle.attestation.dashboardUrl;
    verificationUrl =
      bundle.attestation.verificationUrl ?? `${dashboardUrl}#attestation`;
  } else {
    const base = resolveDashboardBaseUrl(meta.dashboardBaseUrl);
    if (base) {
      dashboardUrl = `${base}/audits/${shortId}`;
      verificationUrl = `${base}/verify/${shortId}`;
    } else {
      dashboardUrl = 'about:blank';
      verificationUrl = 'about:blank';
    }
  }

  const attestation: AuditAttestation = {
    auditHash: attestationHash,
    attestationHash,
    algorithm,
    hmacSignature,
    cliVersion: payload.cliVersion,
    signedAtUtc: payload.timestampUtc,
    licenseTier: meta.licenseTier ?? bundle.attestation?.licenseTier,
    organization: meta.organization ?? bundle.attestation?.organization,
    accountId: meta.accountId ?? bundle.attestation?.accountId,
    dashboardUrl,
    verificationUrl,
    qrPayload: ''
  };

  attestation.qrPayload = buildQrAttestationPayload(attestation);
  return attestation;
}

/** @deprecated Use computeAttestationHash(buildAttestationPayload(bundle)). */
export function computeAuditHash(bundle: AuditReportBundle): string {
  return computeAttestationHash(buildAttestationPayload(bundle));
}
