import { chromium, Browser } from 'playwright';
import { AuditExecutionOptions, AuditFinding, OutputFormat } from '../types/audit';
import { FormActiveInspector } from '../inspectors/form_active_inspector';
import { ConsoleDataInspector } from '../inspectors/console_data_inspector';
import { VisualMetaInspector } from '../inspectors/visual_meta_inspector';
import { HeadersConfigInspector } from '../inspectors/headers_config_inspector';
import { exportToSarif } from '../utils/sarif_exporter';
import { promises as fs } from 'fs';

export class AuditRunner {
  private options: Required<AuditExecutionOptions>;

  constructor(options: AuditExecutionOptions) {
    const defaultFormats: OutputFormat[] = ['json', 'sarif'];

    // Construcción segura garantizando que Required<T> se satisfaga
    this.options = {
      targetUrl: options.targetUrl,
      storageStatePath: options.storageStatePath ?? '',
      concurrency: options.concurrency ?? 2,
      timeoutMs: options.timeoutMs ?? 30000,
      maxRetries: options.maxRetries ?? 2,
      activeFuzzing: options.activeFuzzing ?? true,
      outputFormats: options.outputFormats ?? defaultFormats
    };
  }

  public async run(): Promise<AuditFinding[]> {
    let browser: Browser | null = null;
    const allFindings: AuditFinding[] = [];

    // Derivar directorio de salida desde el inicio para evitar errores de ámbito
    const baseDir = this.getOutputDir();
    await fs.mkdir(baseDir, { recursive: true });

    try {
      browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });

      const contextOptions = this.options.storageStatePath
        ? { storageState: this.options.storageStatePath }
        : {};

      const context = await browser.newContext(contextOptions);
      const page = await context.newPage();

      page.setDefaultTimeout(this.options.timeoutMs);

      // Instanciar inspectores base
      const consoleInspector = new ConsoleDataInspector(page);
      const visualMetaInspector = new VisualMetaInspector(page);

      // 🛡️ 1. Navegación Estricta con Verificación de Renderizado
      let navigationSuccess = false;
      let attempt = 0;

      while (attempt <= this.options.maxRetries && !navigationSuccess) {
        try {
          attempt++;

          // Esperar la carga inicial del DOM
          await page.goto(this.options.targetUrl, {
            waitUntil: 'domcontentloaded',
            timeout: this.options.timeoutMs
          });

          // Esperar a que la estructura base del DOM esté renderizada
          await page.waitForSelector('body', { timeout: 10000 });

          navigationSuccess = true;
        } catch (error) {
          if (attempt > this.options.maxRetries) {
            console.error(`[CRITICAL] Error al renderizar ${this.options.targetUrl}: ${(error as Error).message}`);
          } else {
            await new Promise((res) => setTimeout(res, 2000));
          }
        }
      }

      // 🚨 Guardia de Seguridad: Validar si la página realmente renderizó elementos interactivos o contenido
      const isPageRendered = await page.evaluate(() => {
        const hasInputs = document.querySelectorAll('input, button, form, textarea').length > 0;
        const bodyText = document.body ? document.body.innerText.trim().length : 0;
        return hasInputs || bodyText > 50;
      }).catch(() => false);

      // Si la página falló en cargar o quedó en blanco, REGISTRAR HALLAZGO CRÍTICO y abortar
      if (!navigationSuccess || !isPageRendered) {
        allFindings.push({
          id: `NAV-FAILED-${Date.now()}`,
          ruleId: 'SEC-NAV-RENDER-FAILED',
          title: 'Fallo Crítico en la Carga y Renderizado de la Aplicación Target',
          severity: 'CRITICAL',
          description: `La aplicación en '${this.options.targetUrl}' no se renderizó de forma adecuada dentro del tiempo límite (${this.options.timeoutMs}ms). El DOM quedó inaccesible o vacío.`,
          evidence: {
            snippet: await page.content().catch(() => 'Sin contenido DOM')
          },
          remediation: {
            explanation: 'Verifique que el servidor de la aplicación responda correctamente y no bloquee automatizaciones headless o conexiones automatizadas.',
            codeBefore: '// Timeout en tiempo de carga',
            codeAfter: '// Optimizar la entrega de recursos e infraestructura del frontend'
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-400']
          }
        });

        // Capturar evidencia en imagen del fallo de carga y exportar reporte
        await visualMetaInspector.captureScreenshot(baseDir, 'evidence_landing_failed');
        await this.generateReports(allFindings, baseDir);
        return allFindings;
      }

      // 📸 Captura de Evidencia Visual tras confirmar renderizado exitoso
      await visualMetaInspector.captureScreenshot(baseDir, 'evidence_landing');

      // -----------------------------------------------------------------------
      // 🛡️ NIVEL 1: ASVS V14 — Inspección de Cabeceras HTTP y Configuración
      // -----------------------------------------------------------------------
      const headersInspector = new HeadersConfigInspector(page);
      const headerFindings = await headersInspector.inspectHeaders(this.options.targetUrl);
      allFindings.push(...headerFindings);

      // -----------------------------------------------------------------------
      // 2. Ejecución aislada de Inspectores Restantes (Storage, Forms, Fuzzing)
      // -----------------------------------------------------------------------
      const inspectorTasks: Promise<AuditFinding[]>[] = [];

      if (this.options.activeFuzzing) {
        const activeInspector = new FormActiveInspector(page);
        inspectorTasks.push(activeInspector.executeActiveFuzzing());
      }

      // 🟡 NIVEL 2: ASVS V2/V3 — Inspección de Web Storage (Tokens, JWT, Secrets)
      inspectorTasks.push(consoleInspector.inspectStorage());

      // 🔍 Tarea: Inspección de Meta-etiquetas HTML
      inspectorTasks.push(
        visualMetaInspector.inspectMetadata().then((issues) =>
          issues.map((issue): AuditFinding => ({
            id: `META-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            ruleId: issue.type,
            title: issue.message,
            severity: issue.severity === 'LOW' ? 'LOW' : 'INFO',
            description: issue.message,
            evidence: {
              screenshotPath: `${baseDir}/screenshots/evidence_landing.png`
            },
            remediation: {
              explanation: 'Remueva la etiqueta <meta name="generator"> o configure el servidor para no exponer la versión exacta de la tecnología utilizada.',
              codeBefore: '<meta name="generator" content="Framework/v1.0">',
              codeAfter: '<!-- Remover la etiqueta meta generator -->'
            },
            standards: {
              owasp: ['A05:2021-Security Misconfiguration'],
              cwe: ['CWE-200']
            }
          }))
        )
      );

      // Esperar la resolución de todos los inspectores sin colapsar la suite si uno falla
      const results = await Promise.allSettled(inspectorTasks);

      results.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          allFindings.push(...result.value);
        } else {
          console.error(`[CRITICAL] Inspector en índice ${index} colapsó con error:`, result.reason);
        }
      });

      // Consolidación y exportación de reportes finales
      await this.generateReports(allFindings, baseDir);

      return allFindings;
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }

  private getOutputDir(): string {
    let domainSlug = 'target';
    try {
      const parsedUrl = new URL(this.options.targetUrl);
      domainSlug = parsedUrl.hostname.replace(/^www\./, '');
    } catch {
      domainSlug = this.options.targetUrl.replace(/[^a-zA-Z0-9]/g, '_');
    }

    const now = new Date();
    const pad = (n: number) => n.toString().padStart(2, '0');

    const year = now.getFullYear();
    const month = pad(now.getMonth() + 1);
    const day = pad(now.getDate());
    const hours = pad(now.getHours());
    const minutes = pad(now.getMinutes());
    const seconds = pad(now.getSeconds());

    const localTimestamp = `${year}-${month}-${day}_${hours}-${minutes}-${seconds}`;
    const folderName = `${domainSlug}_${localTimestamp}`;

    return `./audit-results/${folderName}`;
  }

  private async generateReports(findings: AuditFinding[], baseDir: string): Promise<void> {
    if (this.options.outputFormats.includes('json')) {
      await fs.writeFile(
        `${baseDir}/report.json`,
        JSON.stringify({ target: this.options.targetUrl, timestamp: new Date().toISOString(), findings }, null, 2),
        'utf-8'
      );
    }

    if (this.options.outputFormats.includes('sarif')) {
      await exportToSarif(findings, `${baseDir}/results.sarif`);
    }
  }
}