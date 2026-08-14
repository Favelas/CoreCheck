import { createPoolFromEnv } from './pool';
import { runMigrations } from './migrate';

async function main(): Promise<void> {
  const pool = createPoolFromEnv();
  try {
    const applied = await runMigrations(pool);
    console.log(
      applied.length === 0
        ? '[migrate] already up to date'
        : `[migrate] done (${applied.length} applied)`
    );
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error('[migrate] failed', error);
  process.exitCode = 1;
});
