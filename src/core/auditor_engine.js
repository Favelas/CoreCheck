const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// Importamos los módulos especializados de la nueva estructura
const { inspectHealth } = require('../inspectors/health_inspector');
const { inspectForms } = require('../inspectors/form_inspector');
const { inspectEcommerce } = require('../inspectors/ecommerce_inspector');
const { inspectA11yAndDOM } = require('../inspectors/a11y_inspector');
const { generateDashboardHTML } = require('./reporter');
const { generateInternalReportMarkdown } = require('./internal_reporter');
const { inspectSecurity } = require('../inspectors/security_inspector');
const { inspectAuth } = require('../inspectors/auth_inspector');

// Rutas de salida con path.join seguro
const REPORTS_DIR = path.join(__dirname, '../../reports');
const SCREENSHOTS_DIR = path.join(REPORTS_DIR, 'screenshots');

if (!fs.existsSync(SCREENSHOTS_DIR)) {
  fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
}

function getFormattedTimestamp() {
  const now = new Date();
  const pad = (num) => String(num).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

function extractProjectPrefix(url) {
  try {
    const host = new URL(url).hostname.toLowerCase().split('.');
    return (host[0] === 'www' ? host[1] : host[0]).replace(/[^a-z0-9]/gi, '') || 'corecheck';
  } catch (e) { return 'corecheck'; }
}

async function auditUniversal(baseUrl, routes = ['/']) {
  const runTimestamp = getFormattedTimestamp();
  const auditResults = [];

  const browser = await chromium.launch({ headless: true });
  const contextDesk = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
  const contextMob = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true });

  const page = await contextDesk.newPage();
  const pageMob = await contextMob.newPage();

  for (let i = 0; i < routes.length; i++) {
    const route = routes[i];
    const fullUrl = `${baseUrl}${route.startsWith('/') ? route.substring(1) : route}`;
    console.log(`🔍 [${i + 1}/${routes.length}] Auditando: ${route}`);

    try {
      // 1. Health Inspection (Performance & Network)
      const healthData = await inspectHealth(page, fullUrl);

      // 2. Specialized Inspections (DOM / Forms / E-commerce / Accessibility / Security)
      const domData = await inspectA11yAndDOM(page);
      const formData = await inspectForms(page);
      const ecomData = await inspectEcommerce(page);
      const securityData = await inspectSecurity(page);
      const authData = await inspectAuth(page);

      // Consolidar observaciones y detecciones
      const alerts = [
        ...healthData.alerts,
        ...domData.alerts,
        ...formData.alerts,
        ...ecomData.alerts,
        ...securityData.alerts,
        ...authData.alerts
      ];

      const detections = [
        ...formData.detections,
        ...ecomData.detections,
        ...securityData.detections
      ];

      // 📸 CAPTURAS DE EVIDENCIA CON WAIT PARA FRAGMENTS/HASHES
      const projectPrefix = extractProjectPrefix(fullUrl);
      const routeClean = route.replace(/[^a-z0-9]/gi, '_').replace(/^_+/, '') || 'home';
      const deskFile = `${projectPrefix}_${runTimestamp}_${i + 1}_${routeClean}_desktop.png`;
      const mobFile = `${projectPrefix}_${runTimestamp}_${i + 1}_${routeClean}_mobile.png`;

      // Manejo de hashes/anchors (ej: /#faq)
      const hashMatch = route.match(/#([a-zA-Z0-9_-]+)/);
      const hashId = hashMatch ? hashMatch[1] : null;

      // Captura Desktop
      if (hashId) {
        await page.locator(`#${hashId}`).scrollIntoViewIfNeeded().catch(() => {});
        await page.waitForTimeout(600); // Tiempos para transiciones smooth scroll
      }
      await page.screenshot({ path: path.join(SCREENSHOTS_DIR, deskFile) });

      // Captura Mobile
      await pageMob.goto(fullUrl, { waitUntil: 'domcontentloaded' });
      if (hashId) {
        await pageMob.locator(`#${hashId}`).scrollIntoViewIfNeeded().catch(() => {});
        await pageMob.waitForTimeout(600);
      }
      await pageMob.screenshot({ path: path.join(SCREENSHOTS_DIR, mobFile) });

      // 📌 PUSH A RESULTADOS
      auditResults.push({
        route,
        status: healthData.status,
        loadTimeMs: healthData.loadTimeMs,
        title: domData.title,
        detections,
        alerts,
        jsErrors: healthData.jsErrors,
        deskFile,
        mobFile,
        passed: alerts.length === 0
      });

    } catch (err) {
      auditResults.push({
        route, status: 500, loadTimeMs: 0, title: 'ERROR',
        detections: [], alerts: [`❌ EXCEPCIÓN: ${err.message}`], jsErrors: [], deskFile: '', mobFile: '', passed: false
      });
    }
  }

  // Cierre del navegador Playwright
  await browser.close();

  // 1. Generar Dashboard HTML (Para el cliente / vista ejecutiva)
  generateDashboardHTML(auditResults, runTimestamp, baseUrl, REPORTS_DIR);

  // 2. Generar Reporte Interno Markdown (QA Triage, prioridad High/Critical & Pasos para reproducir)
  generateInternalReportMarkdown(auditResults, runTimestamp, baseUrl, REPORTS_DIR);
}

module.exports = { auditUniversal };