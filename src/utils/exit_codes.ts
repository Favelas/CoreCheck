/**
 * Taxonomía estable de exit codes CoreCheck v1.0 (Enterprise Hardened).
 *
 * CI/CD debe ramificar por código — no parsear logs:
 *   0 → Quality Gate PASS
 *   1 → Quality Gate FAIL (umbrales de severidad)
 *   2 → Configuración / argumentos / licencia
 *   3 → Red / conectividad / WAF / target inalcanzable
 *   4 → Fallo interno del motor / Playwright / OOM
 */

export const ExitCode = {
  PASS: 0,
  GATE_FAIL: 1,
  CONFIG: 2,
  NETWORK: 3,
  ENGINE: 4
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

export type CoreCheckErrorKind =
  | 'CONFIG'
  | 'NETWORK'
  | 'ENGINE'
  | 'LICENSE'
  | 'VERIFY';

export class CoreCheckError extends Error {
  readonly exitCode: ExitCodeValue;
  readonly kind: CoreCheckErrorKind;

  constructor(
    message: string,
    kind: CoreCheckErrorKind,
    exitCode?: ExitCodeValue
  ) {
    super(message);
    this.name = 'CoreCheckError';
    this.kind = kind;
    this.exitCode =
      exitCode ??
      (kind === 'NETWORK'
        ? ExitCode.NETWORK
        : kind === 'ENGINE'
          ? ExitCode.ENGINE
          : ExitCode.CONFIG);
  }
}

const NETWORK_PATTERNS: RegExp[] = [
  /\bENOTFOUND\b/i,
  /\bECONNREFUSED\b/i,
  /\bECONNRESET\b/i,
  /\bETIMEDOUT\b/i,
  /\bEAI_AGAIN\b/i,
  /\bENETUNREACH\b/i,
  /net::ERR_/i,
  /NS_ERROR_CONNECTION/i,
  /Navigation failed/i,
  /TimeoutError.*goto/i,
  /Target closed/i,
  /Target page, context or browser has been closed/i,
  /\b403\b.*\b(WAF|cloudflare|forbidden)\b/i,
  /\b429\b/i,
  /unreachable/i,
  /getaddrinfo/i,
  /certificate has expired/i,
  /SSL|TLS.*handshake/i
];

const ENGINE_PATTERNS: RegExp[] = [
  /\bENOMEM\b/i,
  /JavaScript heap out of memory/i,
  /out of memory/i,
  /Protocol error/i,
  /browser has been closed/i,
  /chromium.*crash/i,
  /Failed to launch.*(browser|chromium)/i,
  /Executable doesn't exist/i
];

const CONFIG_PATTERNS: RegExp[] = [
  /inválid/i,
  /invalid/i,
  /debe ser/i,
  /requerid/i,
  /mutuamente excluyentes/i,
  /API Key requerida/i,
  /no existe/i,
  /ENOENT/i,
  /baseline/i
];

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return `${error.message}\n${error.stack ?? ''}`;
  }
  return String(error);
}

/** Clasifica un error desconocido a la taxonomía de exit codes. */
export function classifyError(error: unknown): ExitCodeValue {
  if (error instanceof CoreCheckError) {
    return error.exitCode;
  }

  const msg = errorMessage(error);

  if (ENGINE_PATTERNS.some((re) => re.test(msg))) {
    return ExitCode.ENGINE;
  }
  if (NETWORK_PATTERNS.some((re) => re.test(msg))) {
    return ExitCode.NETWORK;
  }
  if (CONFIG_PATTERNS.some((re) => re.test(msg))) {
    return ExitCode.CONFIG;
  }

  // Por defecto: fallo interno — no mentir como gate fail (1).
  return ExitCode.ENGINE;
}

export function exitCodeLabel(code: ExitCodeValue): string {
  switch (code) {
    case ExitCode.PASS:
      return 'PASS';
    case ExitCode.GATE_FAIL:
      return 'GATE_FAIL';
    case ExitCode.CONFIG:
      return 'CONFIG';
    case ExitCode.NETWORK:
      return 'NETWORK';
    case ExitCode.ENGINE:
      return 'ENGINE';
    default:
      return 'UNKNOWN';
  }
}
