import { AuditRunner } from './core/audit_runner';
import { AuditExecutionOptions } from './types/audit';

// Configuración de ejecución Enterprise
const TARGET_SITES = [
  'https://opensource-demo.orangehrmlive.com/web/index.php/auth/login',
  'https://www.saucedemo.com/',
  'https://automationexercise.com/login'
];

(async () => {
  console.log('🚀 [CoreCheck DevSecOps Engine 2.5] Iniciando auditoría activa de alta precisión...\n');

  for (const url of TARGET_SITES) {
    console.log(`🔍 [Audit Target] Ejecutando inspección, fuzzing y captura de evidencia en: ${url}`);

    const options: AuditExecutionOptions = {
      targetUrl: url,
      concurrency: 2,
      timeoutMs: 30000,
      maxRetries: 2,
      activeFuzzing: true, // Inyección de vectores XSS / Boundary Stress en vivo
      outputFormats: ['json', 'sarif']
    };

    try {
      const runner = new AuditRunner(options);
      const findings = await runner.run();

      console.log(`✅ [Completado] Se identificaron ${findings.length} hallazgos en ${url}.\n`);
    } catch (error) {
      console.error(`❌ [Critical Error] Colapso durante la auditoría de ${url}:`, (error as Error).message);
    }
  }

  console.log('📊 [Reportes Generados] Revisa la carpeta ./audit-results/ para consultar los archivos .json, .sarif y screenshots.');
})();