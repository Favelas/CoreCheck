// audit_corecheck.js
// 🚀 CoreCheck QA Engine - Auditoría de Salud Minuciosa (Hasta 5 Rutas)
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const THEME = {
  title: '\x1b[1m\x1b[36m',   // Cyan
  success: '\x1b[32m',        // Verde
  warning: '\x1b[33m',        // Ámbar
  error: '\x1b[31m',          // Rojo
  alertHeader: '\x1b[41m\x1b[37m\x1b[1m', // Fondo Rojo / Texto Blanco / Negrita
  reset: '\x1b[0m'
};

// 📌 UMBRALES DE ALERTA (Configurables)
const THRESHOLDS = {
  MAX_LOAD_TIME_MS: 3000, // Alerta si supera los 3.0s (3000 ms)
};

// 📌 CONFIGURACIÓN: Tu URL base y hasta 5 rutas a verificar
const BASE_URL = 'https://corecheck-audit.lovable.app/';

const ROUTES_TO_TEST = [
  '/',           // 1. Home / Hero
  '/#services',  // 2. Servicios
  '/#pricing',   // 3. Precios
  '/#faq'        // 4. Preguntas Frecuentes
  // '/contacto'  // 5. Opción para quinta ruta
];

// Helper: Crear carpeta de capturas si no existe
const SCREENSHOTS_DIR = path.join(__dirname, 'screenshots');
if (!fs.existsSync(SCREENSHOTS_DIR)) {
  fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
}

// Helper: Obtener Date & Time formateado (YYYYMMDD_HHMMSS)
function getFormattedTimestamp() {
  const now = new Date();
  const pad = (num) => String(num).padStart(2, '0');
  const dateStr = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`;
  const timeStr = `${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return `${dateStr}_${timeStr}`;
}

// Helper: Extraer prefijo del proyecto desde la URL o el DOM
function extractProjectPrefix(url, pageTitle = '') {
  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();
    
    // Si la URL contiene subdominio relevante (ej: corecheck-audit.lovable.app)
    const hostParts = hostname.split('.');
    let prefix = hostParts[0];
    if (prefix === 'www' || prefix === 'id-preview') {
      prefix = hostParts[1] || 'project';
    }
    
    // Limpieza de caracteres especiales
    prefix = prefix.replace(/[^a-z0-9]/gi, '').toLowerCase();
    return prefix || 'corecheck';
  } catch (e) {
    return 'corecheck';
  }
}

async function runCoreCheckAudit() {
  const runTimestamp = getFormattedTimestamp();

  console.log(`${THEME.title}====================================================`);
  console.log(`🚀 CORECHECK QA ENGINE - AUDITORÍA DE SALUD MINUCIOSA`);
  console.log(`🌐 Base URL: ${BASE_URL}`);
  console.log(`📅 Timestamp Ejecución: ${runTimestamp}`);
  console.log(`📁 Carpeta de Evidencias: /screenshots`);
  console.log(`====================================================${THEME.reset}\n`);

  const browser = await chromium.launch({ headless: true });

  // Contexto Desktop (1920x1080)
  const contextDesktop = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    colorScheme: 'dark'
  });

  // Contexto Mobile (iPhone 13 - 390x844)
  const contextMobile = await browser.newContext({
    viewport: { width: 390, height: 844 },
    isMobile: true,
    hasTouch: true,
    colorScheme: 'dark'
  });

  const page = await contextDesktop.newPage();
  const pageMobile = await contextMobile.newPage();

  // Tomamos hasta 5 rutas máximo
  const routesToAudit = ROUTES_TO_TEST.slice(0, 5);

  for (let i = 0; i < routesToAudit.length; i++) {
    const route = routesToAudit[i];
    const fullUrl = `${BASE_URL}${route.startsWith('/') ? route.substring(1) : route}`;
    const jsErrors = [];
    const jsWarnings = [];
    const alerts = []; // Contenedor de alertas importantes

    // Listener para errores y advertencias en consola JS
    const consoleListener = msg => {
      if (msg.type() === 'error') jsErrors.push(msg.text());
      if (msg.type() === 'warning') jsWarnings.push(msg.text());
    };
    page.on('console', consoleListener);

    console.log(`${THEME.title}🔍 [${i + 1}/${routesToAudit.length}] INSPECCIONANDO RUTA: ${route}${THEME.reset}`);

    try {
      // 1. Navegación, Medición de Tiempo de Respuesta y Status HTTP
      const startTime = Date.now();
      const response = await page.goto(fullUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      const loadTimeMs = Date.now() - startTime;
      await page.waitForTimeout(1500); // Dar tiempo a render de React

      // Manejo de status para evitar falso positivo 0 en navegación por ancla (#)
      const status = response ? response.status() : 200;
      const statusColor = status >= 200 && status < 300 ? THEME.success : THEME.error;

      // 🛑 REVISIÓN DE ALERTAS DE TIEMPO Y STATUS
      if (status < 200 || status >= 300) {
        alerts.push(`🚨 CRÍTICO: Status HTTP anómalo (${status}). La página no respondió correctamente.`);
      }

      if (loadTimeMs > THRESHOLDS.MAX_LOAD_TIME_MS) {
        alerts.push(`⏱️ LENTITUD: Tiempo de carga alto (${loadTimeMs} ms). Supera el umbral de ${THRESHOLDS.MAX_LOAD_TIME_MS} ms.`);
      }

      // 2. Extracción extendida en el DOM (en un solo page.evaluate para máxima velocidad)
      const pageMetrics = await page.evaluate(() => {
        const imgs = Array.from(document.querySelectorAll('img'));
        const links = Array.from(document.querySelectorAll('a'));

        // Meta Viewport
        const hasViewport = !!document.querySelector('meta[name="viewport"]');

        // Favicon
        const hasFavicon = !!document.querySelector('link[rel*="icon"]');

        // Imágenes rotas
        const brokenImgs = imgs.filter(img => !img.src || img.naturalWidth === 0).length;

        // Accesibilidad básica - Imágenes sin alt
        const missingAlt = imgs.filter(img => !img.hasAttribute('alt') || img.getAttribute('alt').trim() === '').length;

        // Accesibilidad básica - Inputs sin label ni aria-label
        const inputs = Array.from(document.querySelectorAll('input:not([type="hidden"])'));
        const inputsWithoutLabel = inputs.filter(input => {
          const hasId = input.id && document.querySelector(`label[for="${input.id}"]`);
          const wrappedInLabel = input.closest('label');
          const ariaLabel = input.getAttribute('aria-label');
          return !hasId && !wrappedInLabel && !ariaLabel;
        }).length;

        // Enlaces con href vacío o nulo
        const emptyLinks = links.filter(a => !a.getAttribute('href') || a.getAttribute('href').trim() === '#').length;

        return {
          hasViewport,
          hasFavicon,
          brokenImgs,
          missingAlt,
          inputsWithoutLabel,
          emptyLinks
        };
      });

      const pageTitle = await page.title();
      const projectPrefix = extractProjectPrefix(fullUrl, pageTitle);

      // 🛑 REVISIÓN DE ALERTAS DEL DOM Y JS
      if (!pageTitle || pageTitle.trim() === '') {
        alerts.push(`🏷️ SEO/A11Y: La página no tiene la etiqueta <title> configurada.`);
      }

      if (!pageMetrics.hasViewport) {
        alerts.push(`📱 MOBILE: Falta etiqueta <meta name="viewport">. Puede verse mal en celulares.`);
      }

      if (pageMetrics.brokenImgs > 0) {
        alerts.push(`🖼️ IMÁGENES: Se encontraron ${pageMetrics.brokenImgs} imágenes rotas (falla 404 o render).`);
      }

      if (pageMetrics.missingAlt > 0) {
        alerts.push(`♿ ACCESIBILIDAD: Se hallaron ${pageMetrics.missingAlt} imágenes sin atributo 'alt'.`);
      }

      if (pageMetrics.emptyLinks > 0) {
        alerts.push(`🔗 ENLACES: Hay ${pageMetrics.emptyLinks} enlaces vacíos o apuntando a '#'.`);
      }

      if (jsErrors.length > 0) {
        alerts.push(`💥 JAVASCRIPT: Se registraron ${jsErrors.length} error(es) en la consola del navegador.`);
      }

      // 3. Impresión de Resultados / Assertions
      console.log(`   - Status HTTP:       ${statusColor}${status} OK${THEME.reset}`);
      console.log(`   - Tiempo Carga:      ${loadTimeMs < THRESHOLDS.MAX_LOAD_TIME_MS ? THEME.success : THEME.warning}${loadTimeMs} ms${THEME.reset}`);
      console.log(`   - Título de Página:  "${pageTitle || 'SIN TÍTULO'}"`);
      console.log(`   - Meta Viewport:     ${pageMetrics.hasViewport ? THEME.success + 'Sí' : THEME.error + 'NO (Problema Mobile)'}${THEME.reset}`);
      console.log(`   - Favicon Config:    ${pageMetrics.hasFavicon ? THEME.success + 'Presente' : THEME.warning + 'Ausente / No detectado'}${THEME.reset}`);
      console.log(`   - Imágenes Rotas:   ${pageMetrics.brokenImgs === 0 ? THEME.success + '0 Detectadas' : THEME.error + pageMetrics.brokenImgs + ' Fallando'}${THEME.reset}`);
      console.log(`   - Imágenes sin Alt: ${pageMetrics.missingAlt === 0 ? THEME.success + '0 (Excelente)' : THEME.warning + pageMetrics.missingAlt + ' Faltantes'}${THEME.reset}`);
      console.log(`   - Inputs sin Label: ${pageMetrics.inputsWithoutLabel === 0 ? THEME.success + '0 (Excelente)' : THEME.warning + pageMetrics.inputsWithoutLabel + ' Faltantes'}${THEME.reset}`);
      console.log(`   - Enlaces Vacíos:   ${pageMetrics.emptyLinks === 0 ? THEME.success + '0' : THEME.warning + pageMetrics.emptyLinks}${THEME.reset}`);

      if (jsErrors.length === 0) {
        console.log(`   - Errores JS:       ${THEME.success}0 Detectados${THEME.reset}`);
      } else {
        console.log(`   - Errores JS:       ${THEME.error}${jsErrors.length} Hallados${THEME.reset}`);
        jsErrors.forEach(err => console.log(`     ${THEME.error}↳ ${err}${THEME.reset}`));
      }

      // 4. Capturas de Pantalla Guardadas en /screenshots con Nombramiento Dinámico
      const routeCleanName = route.replace(/[^a-z0-9]/gi, '_').replace(/^_+/, '') || 'home';

      // Nombres de archivos con Prefijo + Timestamp + Ruta + Viewport
      const desktopFileName = `${projectPrefix}_${runTimestamp}_${i + 1}_${routeCleanName}_desktop.png`;
      const mobileFileName = `${projectPrefix}_${runTimestamp}_${i + 1}_${routeCleanName}_mobile.png`;

      const desktopPath = path.join(SCREENSHOTS_DIR, desktopFileName);
      const mobilePath = path.join(SCREENSHOTS_DIR, mobileFileName);

      // Screenshot Desktop
      await page.screenshot({ path: desktopPath, fullPage: false });

      // Screenshot Mobile
      await pageMobile.goto(fullUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await pageMobile.waitForTimeout(1000);
      await pageMobile.screenshot({ path: mobilePath, fullPage: false });

      console.log(`   - Evidencias PNG:    [Desktop: screenshots/${desktopFileName}]`);
      console.log(`                        [Mobile:  screenshots/${mobileFileName}]`);

      // 5. BLOQUE DE ALERTAS IMPORTANTES (Solo si existen hallazgos)
      if (alerts.length > 0) {
        console.log(`\n   ${THEME.alertHeader} ⚠️ ATENCIÓN: REQUIERE VERIFICACIÓN (${alerts.length}) ${THEME.reset}`);
        alerts.forEach(alertItem => {
          console.log(`   ${THEME.warning}${alertItem}${THEME.reset}`);
        });
      }

      console.log(`----------------------------------------------------\n`);

    } catch (err) {
      console.log(`   ${THEME.error}❌ Error al auditar la ruta (${route}): ${err.message}${THEME.reset}\n`);
    } finally {
      page.off('console', consoleListener);
    }
  }

  await browser.close();
  console.log(`${THEME.title}🏁 AUDITORÍA COMPLETADA EXITOSAMENTE.${THEME.reset}\n`);
}

runCoreCheckAudit();