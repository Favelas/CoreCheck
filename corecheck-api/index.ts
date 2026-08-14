/**
 * Entry point — solo bootstrap HTTP.
 * La composición de middlewares/rutas vive en src/app.ts.
 *
 * Requiere CORECHECK_API_KEY (o CORECHECK_API_KEYS) para /api/*.
 * Ejemplo PowerShell: $env:CORECHECK_API_KEY="cc_dev_local"
 */
import { createApp } from './src/app';
import { parseApiKeyBindingsFromEnv } from './src/security/apiKeys';

const PORT = Number(process.env['PORT']) || 3000;
const configuredBindings = parseApiKeyBindingsFromEnv();

if (configuredBindings.length === 0) {
  console.warn(
    '[CoreCheck API] ADVERTENCIA: sin CORECHECK_API_KEY — /api/* responderá 503 MISCONFIGURED. Health (/) sigue público.'
  );
} else {
  console.log(
    `[CoreCheck API] ${configuredBindings.length} API key(s) cargada(s) con tenant binding.`
  );
}

const app = createApp();

app.listen(PORT, () => {
  console.log(`[CoreCheck API] Servidor ejecutándose en http://localhost:${PORT}`);
});
