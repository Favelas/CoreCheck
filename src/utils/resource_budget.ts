import * as os from 'node:os';

/**
 * Presupuesto de recursos para runners CI pequeños (GitHub Actions ≈ 2 vCPU / 7 GB).
 *
 * Cada worker de AuditRunner abre ≥1 BrowserContext de página + Form (+ Fuzz opcional).
 * Sin clamp, `--concurrency` alto provoca OOM (exit 4) y falsos negativos operativos.
 */

export type ResourceProfile = 'ci-small' | 'local' | 'high-mem';

export interface ResourceBudgetInput {
  requestedConcurrency: number;
  activeFuzzing?: boolean;
  /** Override memoria total (tests). Default: os.totalmem(). */
  totalMemBytes?: number;
  /** Override memoria libre (tests). Default: os.freemem(). */
  freeMemBytes?: number;
  /** Fuerza perfil CI. Default: detecta GITHUB_ACTIONS / CI. */
  forceCiProfile?: boolean;
}

export interface ResourceBudgetResult {
  concurrency: number;
  requestedConcurrency: number;
  capped: boolean;
  profile: ResourceProfile;
  /** Tope duro aplicado por perfil / memoria. */
  hardCap: number;
  reason?: string;
}

/** Reserva para OS + Node + Chromium base (bytes). */
const RESERVE_BYTES = 1536 * 1024 * 1024;

/** Estimación conservadora por worker (página + form contexts). */
const PER_WORKER_BYTES = 700 * 1024 * 1024;

/** Overhead adicional por fuzzing activo por worker. */
const FUZZ_EXTRA_BYTES = 250 * 1024 * 1024;

/** Cap duro en GitHub Actions / CI genérico. */
export const CI_SMALL_HARD_CAP = 2;

/** Cap duro en máquinas locales modestas (< 8 GB). */
export const LOCAL_MODEST_HARD_CAP = 3;

/** Cap absoluto (incluso high-mem). */
export const ABSOLUTE_HARD_CAP = 8;

export function isCiEnvironment(forceCiProfile?: boolean): boolean {
  if (forceCiProfile === true) return true;
  if (forceCiProfile === false) return false;
  return Boolean(process.env.GITHUB_ACTIONS) || process.env.CI === 'true';
}

/**
 * Calcula concurrencia efectiva segura para el host actual.
 * Nunca sube el valor pedido; solo lo reduce cuando hay riesgo de OOM.
 */
export function clampConcurrency(input: ResourceBudgetInput): ResourceBudgetResult {
  const requested = Math.max(1, Math.floor(input.requestedConcurrency) || 1);
  const totalMem = input.totalMemBytes ?? os.totalmem();
  const freeMem = input.freeMemBytes ?? os.freemem();
  const ci = isCiEnvironment(input.forceCiProfile);

  const perWorker =
    PER_WORKER_BYTES + (input.activeFuzzing ? FUZZ_EXTRA_BYTES : 0);

  const usable = Math.max(0, Math.min(freeMem, totalMem) - RESERVE_BYTES);
  const memBasedCap = Math.max(1, Math.floor(usable / perWorker));

  let profile: ResourceProfile;
  let hardCap: number;

  if (ci) {
    profile = 'ci-small';
    hardCap = CI_SMALL_HARD_CAP;
  } else if (totalMem < 8 * 1024 * 1024 * 1024) {
    profile = 'local';
    hardCap = LOCAL_MODEST_HARD_CAP;
  } else {
    profile = 'high-mem';
    hardCap = ABSOLUTE_HARD_CAP;
  }

  const effectiveCap = Math.min(hardCap, memBasedCap, ABSOLUTE_HARD_CAP);
  const concurrency = Math.min(requested, effectiveCap);
  const capped = concurrency < requested;

  let reason: string | undefined;
  if (capped) {
    reason =
      `Concurrency capped ${requested} → ${concurrency} ` +
      `(profile=${profile}, hardCap=${hardCap}, memCap=${memBasedCap}, ` +
      `free≈${Math.round(freeMem / (1024 * 1024))}MB)`;
  }

  return {
    concurrency,
    requestedConcurrency: requested,
    capped,
    profile,
    hardCap,
    reason
  };
}

/** Args Chromium recomendados para runners con /dev/shm pequeño (GHA/Docker). */
export function chromiumLaunchArgsForBudget(): string[] {
  return [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-blink-features=AutomationControlled'
  ];
}
