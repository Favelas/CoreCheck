import { getReportsRepository } from '../store/repository.context';

/**
 * Retention policy (Fase 4.1).
 * CORECHECK_RETENTION_DAYS — si > 0, purgeOlderThan(now - days).
 */
export function resolveRetentionDays(
  env: NodeJS.ProcessEnv = process.env
): number {
  const raw = env['CORECHECK_RETENTION_DAYS'];
  if (raw === undefined || raw.trim() === '') {
    return 0;
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    return 0;
  }
  return Math.floor(n);
}

export async function runRetentionPurge(
  retentionDays: number = resolveRetentionDays()
): Promise<number> {
  if (retentionDays <= 0) {
    return 0;
  }

  const cutoff = new Date(
    Date.now() - retentionDays * 24 * 60 * 60 * 1000
  ).toISOString();

  const removed = await getReportsRepository().purgeOlderThan(cutoff);
  console.log(
    JSON.stringify({
      level: 'info',
      msg: 'retention_purge',
      retentionDays,
      cutoff,
      removed
    })
  );
  return removed;
}
