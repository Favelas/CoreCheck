// // audit_runner.js*//
// const { auditUniversal } = require('./src/core/auditor_engine');

// const TARGET_URL = 'https://midominio.com';
// const ROUTES = ['/', '/services', '/pricing', '/faq'];

// (async () => {
//   console.log(`🚀 Auditando ${TARGET_URL} a través de ${ROUTES.length} rutas...`);
//   await auditUniversal(TARGET_URL, ROUTES);
//   console.log('\n✅ Auditoría finalizada.');
// })();



//multiple sites 
/**
 * Audit Runner - CoreCheck Test Suite Target Selection
 */

const { auditUniversal } = require('./src/core/auditor_engine');

// URLs objetivo enterprise seleccionadas para la auditoría
const TARGET_SITES = [
  'https://opensource-demo.orangehrmlive.com/web/index.php/auth/login',
  'https://www.saucedemo.com/',
  'https://automationexercise.com/login'
];

(async () => {
  console.log('🚀 [CoreCheck] Iniciando ejecución de auditoría universal...');

  for (const url of TARGET_SITES) {
    try {
      await auditUniversal(url, ['/']);
    } catch (err) {
      console.error(`❌ Error en auditoría para ${url}: ${err.message}`);
    }
  }

  console.log('\n✅ [CoreCheck] Proceso finalizado. Revisa la carpeta /reports para abrir el dashboard HTML.');
})();