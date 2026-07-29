// src/inspectors/health_inspector.js
const THRESHOLDS = { MAX_LOAD_TIME_MS: 3000 };

async function inspectHealth(page, fullUrl) {
  const jsErrors = [];
  const alerts = [];

  const consoleHandler = msg => {
    if (msg.type() === 'error') jsErrors.push(msg.text());
  };
  page.on('console', consoleHandler);

  const startTime = Date.now();
  let status = 200;

  try {
    const response = await page.goto(fullUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    const loadTimeMs = Date.now() - startTime;
    await page.waitForTimeout(1000);

    status = response ? response.status() : 200;

    if (status < 200 || status >= 300) {
      alerts.push(`🚨 CRÍTICO: Status HTTP anómalo (${status})`);
    }
    if (loadTimeMs > THRESHOLDS.MAX_LOAD_TIME_MS) {
      alerts.push(`⏱️ LENTITUD: Carga tardó ${loadTimeMs}ms (Umbral: ${THRESHOLDS.MAX_LOAD_TIME_MS}ms)`);
    }
    if (jsErrors.length > 0) {
      alerts.push(`💥 JAVASCRIPT: ${jsErrors.length} error(es) en consola`);
    }

    return { status, loadTimeMs, jsErrors, alerts };
  } finally {
    page.off('console', consoleHandler);
  }
}

module.exports = { inspectHealth };