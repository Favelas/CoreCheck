/**
 * Entry point — bootstrap HTTP.
 *
 * Auth: CORECHECK_API_KEY o CORECHECK_API_KEYS=key:accountId,...
 * Persistencia: CORECHECK_PERSISTENCE=file|memory|postgres (default file)
 * Datos file: CORECHECK_DATA_DIR (default ./data)
 * Postgres: DATABASE_URL o POSTGRES_* + npm run db:migrate
 * HMAC opcional: CORECHECK_REPORT_HMAC_SECRET
 */
import { createApp } from './src/app';
import { createPoolFromEnv } from './src/db/pool';
import { runMigrations } from './src/db/migrate';
import { parseApiKeyBindingsFromEnv } from './src/security/apiKeys';

async function main(): Promise<void> {
  const PORT = Number(process.env['PORT']) || 3000;
  const configuredBindings = parseApiKeyBindingsFromEnv();
  const persistence = process.env['CORECHECK_PERSISTENCE'] ?? 'file';

  if (configuredBindings.length === 0) {
    console.warn(
      '[CoreCheck API] ADVERTENCIA: sin CORECHECK_API_KEY — /api/* responderá 503 MISCONFIGURED. Health (/) sigue público.'
    );
  } else {
    console.log(
      `[CoreCheck API] ${configuredBindings.length} API key(s) cargada(s) con tenant binding.`
    );
  }

  console.log(`[CoreCheck API] Persistencia: ${persistence}`);

  if (persistence === 'postgres') {
    const pool = createPoolFromEnv();
    const applied = await runMigrations(pool);
    console.log(
      applied.length === 0
        ? '[CoreCheck API] migraciones al día'
        : `[CoreCheck API] migraciones aplicadas: ${applied.join(', ')}`
    );
  }

  const mode =
    persistence === 'memory'
      ? 'memory'
      : persistence === 'postgres'
        ? 'postgres'
        : 'file';

  const app = createApp({ persistence: mode });

  app.listen(PORT, () => {
    console.log(
      `[CoreCheck API] Servidor ejecutándose en http://localhost:${PORT}`
    );
  });
}

main().catch((error: unknown) => {
  console.error('[CoreCheck API] bootstrap failed', error);
  process.exitCode = 1;
});
