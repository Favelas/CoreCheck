/**
 * Security Inspector - CoreCheck Auditor Engine
 */

const XSS_PAYLOADS = [
  '"><script>window.__corecheck_xss=true</script>',
  '"><img src=x onerror="window.__corecheck_xss=true">'
];

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "';--",
  "1' ORDER BY 1--"
];

const EDGE_CASE_STRINGS = {
  LONG_STRING: 'A'.repeat(5000)
};

// Set para evitar re-auditar el mismo formulario/página en SPA con hashes (#services, #pricing, etc.)
const auditedFormsCache = new Set();

async function inspectSecurityHeaders(page) {
  const alerts = [];
  try {
    const response = await page.goto(page.url(), { waitUntil: 'domcontentloaded' });
    if (!response) return alerts;

    const headers = response.headers();

    if (!headers['strict-transport-security']) {
      alerts.push('🔒 SEGURIDAD (Cabeceras): Falta HSTS (Strict-Transport-Security). Vulnerable a downgrade attacks.');
    }
    if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
      alerts.push('🔒 SEGURIDAD (Clickjacking): Falta X-Frame-Options o CSP frame-ancestors.');
    }
    if (!headers['x-content-type-options']) {
      alerts.push('🔒 SEGURIDAD (MIME-Sniffing): Falta X-Content-Type-Options: nosniff.');
    }
    if (!headers['content-security-policy']) {
      alerts.push('⚠️ SEGURIDAD (CSP): No se detectó Content-Security-Policy configurada.');
    }
  } catch (e) {}
  return alerts;
}

async function inspectActiveInputSecurity(page) {
  const alerts = [];
  const detections = [];

  const currentUrl = page.url();
  const urlPath = new URL(currentUrl).pathname;

  // Si ya auditamos los inputs de este pathname (ignorado el hash), evitamos duplicar los bugs
  if (auditedFormsCache.has(urlPath)) {
    return { alerts: [], detections: ['🛡️ Seguridad de Inputs: Ya evaluada en vista principal'] };
  }

  const inputs = await page.locator('input:not([type="hidden"]):not([type="submit"]):not([type="checkbox"]):not([type="radio"]), textarea').all();

  if (inputs.length === 0) {
    return { alerts, detections };
  }

  auditedFormsCache.add(urlPath);
  detections.push(`🛡️ Pruebas de Seguridad Ejecutadas en ${inputs.length} campos`);

  let serverDatabaseError = false;
  const consoleHandler = (msg) => {
    const text = msg.text().toLowerCase();
    if (text.includes('sql syntax') || text.includes('mysql') || text.includes('postgres') || text.includes('sqlite')) {
      serverDatabaseError = true;
    }
  };
  page.on('console', consoleHandler);

  for (let idx = 0; idx < inputs.length; idx++) {
    const input = inputs[idx];

    try {
      if (!(await input.isVisible()) || !(await input.isEnabled())) continue;

      // Obtener selector identificable para el reporte (id > name > placeholder > index)
      const inputId = await input.getAttribute('id');
      const inputName = await input.getAttribute('name');
      const inputPlaceholder = await input.getAttribute('placeholder');
      
      const fieldName = inputId ? `#${inputId}` : (inputName ? `[name="${inputName}"]` : (inputPlaceholder ? `"${inputPlaceholder}"` : `Input #${idx + 1}`));

      // A. Prueba XSS
      for (const payload of XSS_PAYLOADS) {
        await input.fill('');
        await input.fill(payload);
        const isVulnerable = await page.evaluate(() => window.__corecheck_xss === true);
        if (isVulnerable) {
          alerts.push(`🚨 CRÍTICO (XSS): El campo ${fieldName} ejecutó script no sanitizado.`);
          break;
        }
      }

      // B. Prueba SQLi
      for (const sqli of SQLI_PAYLOADS) {
        await input.fill('');
        await input.fill(sqli);
        if (serverDatabaseError) {
          alerts.push(`🚨 CRÍTICO (SQLi): El campo ${fieldName} provocó una excepción en base de datos.`);
          break;
        }
      }

      // C. Edge Case (maxlength)
      await input.fill(EDGE_CASE_STRINGS.LONG_STRING);
      const val = await input.inputValue();
      if (val.length === 5000) {
        alerts.push(`⚠️ ADVERTENCIA (Edge Case): El campo ${fieldName} no limita la longitud máxima (falta atributo maxlength).`);
      }

      await input.fill('');

    } catch (e) {}
  }

  page.off('console', consoleHandler);
  return { alerts, detections };
}

async function inspectSecurity(page) {
  const headerAlerts = await inspectSecurityHeaders(page);
  const { alerts: activeAlerts, detections } = await inspectActiveInputSecurity(page);

  return {
    alerts: [...headerAlerts, ...activeAlerts],
    detections
  };
}

module.exports = { inspectSecurity };