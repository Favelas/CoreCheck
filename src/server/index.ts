#!/usr/bin/env node
/**
 * Entry point del SaaS Control Panel local (dev / demo).
 * Uso: npx tsx src/server/index.ts --port 8787
 */
import { createControlPlaneServer } from './router.js';

function resolvePort(): number {
  const idx = process.argv.indexOf('--port');
  if (idx >= 0 && process.argv[idx + 1]) {
    const n = Number(process.argv[idx + 1]);
    if (Number.isFinite(n)) return n;
  }
  const env = Number(process.env.CORECHECK_CONTROL_PORT ?? 8787);
  return Number.isFinite(env) ? env : 8787;
}

createControlPlaneServer(resolvePort());
