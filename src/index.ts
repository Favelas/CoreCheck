#!/usr/bin/env node
/**
 * Entrypoint raíz: `node dist/index.js` → CLI real en `./cli/index.js`.
 * Evita MODULE_NOT_FOUND cuando se invoca la ruta corta post-build.
 */
import './cli/index.js';
