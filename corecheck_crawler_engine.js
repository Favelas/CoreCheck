// corecheck_crawler.js
// 🚀 CoreCheck QA Engine - Crawler Masivo con Auto-Discovery (Apps Grandes)
const { chromium } = require('playwright');

const THEME = {
  title: '\x1b[1m\x1b[36m',   // Cyan
  success: '\x1b[32m',        // Verde
  warning: '\x1b[33m',        // Ámbar
  error: '\x1b[31m',          // Rojo
  reset: '\x1b[0m'
};

const BASE_URL = 'https://books.toscrape.com/';
const MAX_PAGES_TO_AUDIT = 30; // Límite máximo de seguridad

async function runMassiveCrawler() {
  console.log(`${THEME.title}====================================================`);
  console.log(`🚀 CORECHECK QA ENGINE - CRAWLER MASIVO AUTOMÁTICO`);
  console.log(`🌐 Base URL: ${BASE_URL}`);
  console.log(`====================================================${THEME.reset}\n`);

  const browser = await chromium.launch({ headless: true });
  const contextDesktop = await browser.newContext({ viewport: { width: 1920, height: 1080 }, colorScheme: 'dark' });
  const contextMobile = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, colorScheme: 'dark' });

  const page = await contextDesktop.newPage();
  const pageMobile = await contextMobile.newPage();

  const visitedUrls = new Set();
  const queue = [BASE_URL];

  let count = 0;

  while (queue.length > 0 && count < MAX_PAGES_TO_AUDIT) {
    const currentUrl = queue.shift();
    if (visitedUrls.has(currentUrl)) continue;

    visitedUrls.add(currentUrl);
    count++;

    const jsErrors = [];
    const consoleListener = msg => {
      if (msg.type() === 'error') jsErrors.push(msg.text());
    };
    page.on('console', consoleListener);

    console.log(`${THEME.title}🔍 [${count}/${MAX_PAGES_TO_AUDIT}] AUTO-DISCOVERY: ${currentUrl}${THEME.reset}`);

    try {
      // 1. Navegación
      const response = await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(1000);

      const status = response ? response.status() : 0;
      const statusColor = status >= 200 && status < 300 ? THEME.success : THEME.error;
      console.log(`   - Status HTTP:       ${statusColor}${status} OK${THEME.reset}`);

      // 2. Extraer nuevos enlaces del mismo sitio para seguir navegando
      const discoveredLinks = await page.evaluate((domain) => {
        const anchors = Array.from(document.querySelectorAll('a[href]'));
        return anchors
          .map(a => a.href)
          .filter(href => href.startsWith(domain) && !href.includes('#'));
      }, BASE_URL);

      discoveredLinks.forEach(link => {
        if (!visitedUrls.has(link) && !queue.includes(link)) {
          queue.push(link);
        }
      });

      // 3. MISMAS VALIDACIONES MINUCIOSAS QUE EN EL AUDIT DIRECTO
      const pageTitle = await page.title();
      console.log(`   - Título:            "${pageTitle || 'SIN TÍTULO'}"`);

      // Imágenes rotas
      const brokenImages = await page.evaluate(() => {
        const imgs = Array.from(document.querySelectorAll('img'));
        return imgs.filter(img => !img.src || img.naturalWidth === 0).length;
      });
      console.log(`   - Imágenes Rotas:   ${brokenImages === 0 ? THEME.success + '0' : THEME.error + brokenImages}${THEME.reset}`);

      // Accesibilidad
      const a11yStats = await page.evaluate(() => {
        const imgs = Array.from(document.querySelectorAll('img'));
        const imgsWithoutAlt = imgs.filter(img => !img.hasAttribute('alt') || img.getAttribute('alt').trim() === '').length;
        return { imgsWithoutAlt };
      });
      console.log(`   - Imágenes sin Alt: ${a11yStats.imgsWithoutAlt === 0 ? THEME.success + '0' : THEME.warning + a11yStats.imgsWithoutAlt}${THEME.reset}`);

      // Consola JS
      console.log(`   - Errores JS:       ${jsErrors.length === 0 ? THEME.success + '0 Detectados' : THEME.error + jsErrors.length + ' Hallados'}${THEME.reset}`);

      // Evidencias visuales
      const cleanName = `auto_${count}`;
      await page.screenshot({ path: `evidence_crawl_${cleanName}_desktop.png`, fullPage: false });
      
      await pageMobile.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await pageMobile.screenshot({ path: `evidence_crawl_${cleanName}_mobile.png`, fullPage: false });

      console.log(`----------------------------------------------------\n`);

    } catch (err) {
      console.log(`   ${THEME.error}❌ Error navegando a ${currentUrl}: ${err.message}${THEME.reset}\n`);
    } finally {
      page.off('console', consoleListener);
    }
  }

  await browser.close();
  console.log(`${THEME.title}🏁 CRAWLER AUTOMÁTICO FINALIZADO. Páginas inspeccionadas: ${visitedUrls.size}${THEME.reset}\n`);
}

runMassiveCrawler();