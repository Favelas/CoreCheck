/**
 * Entry point — bootstrap HTTP.
 *
 * Auth: CORECHECK_API_KEY o CORECHECK_API_KEYS=key:accountId,...
 * Persistencia: CORECHECK_PERSISTENCE=file|memory (default file)
 * Datos: CORECHECK_DATA_DIR (default ./data)
 * HMAC opcional: CORECHECK_REPORT_HMAC_SECRET
 */
import { createApp } from './src/app';
import { parseApiKeyBindingsFromEnv } from './src/security/apiKeys';

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

const app = createApp({
  persistence: persistence === 'memory' ? 'memory' : 'file'
});

app.listen(PORT, () => {
  console.log(`[CoreCheck API] Servidor ejecutándose en http://localhost:${PORT}`);
});
