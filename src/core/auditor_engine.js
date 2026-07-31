/**
 * CoreCheck Auditor Engine - Main Orchestrator
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const { inspectA11yAndDOM } = require('../inspectors/a11y_inspector');
const { inspectForms } = require('../inspectors/form_inspector');
const { inspectAuth } = require('../inspectors/auth_inspector');

async function auditUniversal(baseUrl, routes = ['/']) {
  console.log(`\n🌐 [CoreCheck] Iniciando auditoría en: ${baseUrl}`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  });

  const page = await context.newPage();
  const reportsDir = path.join(process.cwd(), 'reports');
  const screenshotsDir = path.join(reportsDir, 'screenshots');

  if (!fs.existsSync(screenshotsDir)) {
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }

  const results = [];

  for (const route of routes) {
    const fullUrl = new URL(route, baseUrl).href;
    console.log(`\n🔍 Auditando ruta: ${fullUrl}`);

    try {
      // 1. Navegación robusta con espera de inactividad de red (Garantiza carga de SPAs)
      const response = await page.goto(fullUrl, { 
        waitUntil: 'networkidle', 
        timeout: 30000 
      });

      // 2. Confirmación de renderizado en DOM
      await page.waitForSelector('body', { state: 'visible', timeout: 10000 });
      await page.waitForTimeout(1000); // Estabilización visual

      const pageTitle = await page.title();
      const currentUrl = page.url();
      const httpStatus = response ? response.status() : 200;

      console.log(`   📄 Título cargado: "${pageTitle}" [HTTP ${httpStatus}]`);

      // 3. Captura de pantalla real (Sin lienzo en blanco)
      const sanitizedRoute = route.replace(/[^a-zA-Z0-0]/g, '_') || 'root';
      const screenshotName = `shot_${Date.now()}_${sanitizedRoute}.png`;
      const screenshotPath = path.join(screenshotsDir, screenshotName);

      await page.screenshot({ path: screenshotPath, fullPage: false });

      // 4. Ejecución paralela de inspectores
      const a11yData = await inspectA11yAndDOM(page);
      const formData = await inspectForms(page);
      const authData = await inspectAuth(page);

      // 5. Consolidación de hallazgos
      const allAlerts = [
        ...a11yData.alerts,
        ...formData.alerts,
        ...authData.alerts
      ];

      results.push({
        url: currentUrl,
        title: pageTitle,
        status: httpStatus,
        screenshot: path.relative(reportsDir, screenshotPath),
        alerts: allAlerts,
        detections: [...formData.detections, ...authData.detections]
      });

    } catch (err) {
      console.error(`❌ Error al auditar ${fullUrl}: ${err.message}`);
      results.push({
        url: fullUrl,
        title: 'Error de Carga',
        status: 500,
        screenshot: '',
        alerts: [`🚨 CRÍTICO: No se pudo completar la carga de la página. (${err.message})`],
        detections: []
      });
    }
  }

  await browser.close();

  // Generar reporte HTML rápido
  const reportPath = generateHTMLReport(reportsDir, baseUrl, results);
  console.log(`\n📊 Reporte visual generado exitosamente en:\n   ${reportPath}`);
}

function generateHTMLReport(reportsDir, baseUrl, results) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = `audit_dashboard_${timestamp}.html`;
  const filePath = path.join(reportsDir, fileName);

  const htmlContent = `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>CoreCheck Executive Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { background: #0f172a; color: #fff; padding: 24px; border-radius: 12px; margin-bottom: 24px; }
    h1 { margin: 0 0 8px 0; font-size: 24px; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .screenshot { width: 100%; max-width: 600px; border: 1px solid #cbd5e1; border-radius: 8px; margin-top: 12px; display: block; }
    .alert { padding: 10px 14px; border-radius: 6px; margin-bottom: 8px; font-size: 14px; font-weight: 500; }
    .alert-warn { background: #fffbebf; border-left: 4px solid #f59e0b; color: #92400e; }
    .alert-crit { background: #fef2f2; border-left: 4px solid #ef4444; color: #991b1b; }
    .badge { display: inline-block; padding: 4px 8px; background: #e2e8f0; border-radius: 4px; font-size: 12px; font-weight: 600; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>CoreCheck Audit Dashboard</h1>
      <p style="margin:0; opacity:0.8;">Objetivo: ${baseUrl} | Generado: ${new Date().toLocaleString()}</p>
    </header>

    ${results.map(r => `
      <div class="card">
        <h2>${r.title}</h2>
        <p><span class="badge">URL</span> ${r.url} | <span class="badge">HTTP ${r.status}</span></p>

        ${r.screenshot ? `<img src="${r.screenshot}" class="screenshot" alt="Captura de evidencia">` : ''}

        <h3>🔍 Hallazgos (${r.alerts.length})</h3>
        ${r.alerts.length === 0 ? '<p style="color:#16a34a; font-weight:bold;">✅ Sin alertas detectadas en esta página.</p>' : ''}
        ${r.alerts.map(a => `
          <div class="alert ${a.includes('🚨') || a.includes('🔒') ? 'alert-crit' : 'alert-warn'}">
            ${a}
          </div>
        `).join('')}
      </div>
    `).join('')}
  </div>
</body>
</html>
  `;

  fs.writeFileSync(filePath, htmlContent, 'utf-8');
  return filePath;
}

module.exports = { auditUniversal };