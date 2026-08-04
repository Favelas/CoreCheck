import { promises as fs } from 'fs';
import { Browser, BrowserContext, Response, chromium } from 'playwright';

// Importaciones relativas locales (con extensión .js requerida por Node16/ESM)
import { ConsoleDataInspector } from '../inspectors/console_data_inspector.js';
import { FormActiveInspector } from '../inspectors/form_active_inspector.js';
import { FuzzingInspector } from '../inspectors/fuzzing_inspector.js';
import { HeadersConfigInspector } from '../inspectors/headers_config_inspector.js';
import { VisualMetaInspector } from '../inspectors/visual_meta_inspector.js';
import { AuditExecutionOptions, AuditFinding, FindingLocation, OutputFormat } from '../types/audit.js';

export class AuditRunner {
  private options: Required<AuditExecutionOptions>;

  constructor(options: AuditExecutionOptions) {
    const defaultFormats: OutputFormat[] = ['json', 'sarif'];

    this.options = {
      targetUrl: options.targetUrl,
      storageStatePath: options.storageStatePath ?? '',
      concurrency: options.concurrency ?? 2,
      timeoutMs: options.timeoutMs ?? 30000,
      maxRetries: options.maxRetries ?? 2,
      activeFuzzing: options.activeFuzzing ?? true,
      // Conservado en el contrato; la generación de reportes la orquesta la CLI (Punto 6 / Opción A).
      outputFormats: options.outputFormats ?? defaultFormats,
      outputDir: options.outputDir ?? ''
    };
  }

  public async run(): Promise<AuditFinding[]> {
    let browser: Browser | null = null;
    const contextsToClose: BrowserContext[] = [];
    const allFindings: AuditFinding[] = [];

    const baseDir = this.getOutputDir();
    await fs.mkdir(baseDir, { recursive: true });

    try {
      browser = await chromium.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-blink-features=AutomationControlled'
        ]
      });

      const contextOptions = {
        ...(this.options.storageStatePath ? { storageState: this.options.storageStatePath } : {}),
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        viewport: { width: 1280, height: 720 },
        deviceScaleFactor: 1,
        isMobile: false,
        hasTouch: false
      };

      // Contexto principal para la auditoría pasiva
      const mainContext = await browser.newContext(contextOptions);
      mainContext.setDefaultTimeout(this.options.timeoutMs);
      contextsToClose.push(mainContext);

      const page = await mainContext.newPage();

      const consoleInspector = new ConsoleDataInspector(page);
      const visualMetaInspector = new VisualMetaInspector(page);

      // 🛡️ 1. Navegación Estricta con Retry Loop Activo
      let navigationSuccess = false;
      let attempt = 0;
      let mainResponse: Response | null = null;

      while (attempt <= this.options.maxRetries && !navigationSuccess) {
        try {
          attempt++;

          mainResponse = await page.goto(this.options.targetUrl, {
            waitUntil: 'commit',
            timeout: this.options.timeoutMs
          });

          // Sin .catch silenciado: si expira el tiempo, dispara el catch del retry loop
          await page.waitForFunction(
            () => {
              const hasInteractiveElements =
                document.querySelectorAll('input, button, form, a, textarea').length > 0;
              const bodyLength = document.body ? document.body.innerText.trim().length : 0;
              return hasInteractiveElements || bodyLength > 30;
            },
            { timeout: this.options.timeoutMs }
          );

          navigationSuccess = true;
        } catch (error) {
          if (attempt > this.options.maxRetries) {
            console.error(
              `[CRITICAL] Error al renderizar ${this.options.targetUrl}: ${(error as Error).message}`
            );
          } else {
            await new Promise((res) => setTimeout(res, 2000));
          }
        }
      }

      // Guardia de seguridad ante fallo de renderizado
      if (!navigationSuccess) {
        allFindings.push({
          id: `NAV-FAILED-${Date.now()}`,
          ruleId: 'SEC-NAV-RENDER-FAILED',
          title: 'Fallo Crítico en la Carga y Renderizado de la Aplicación Target',
          severity: 'CRITICAL',
          description: `La aplicación en '${this.options.targetUrl}' no se renderizó dentro del tiempo límite (${this.options.timeoutMs}ms).`,
          evidence: {
            snippet: await page.content().catch(() => 'Sin contenido DOM')
          },
          remediation: {
            explanation:
              'Verifique que el servidor de la aplicación responda correctamente y no bloquee automatizaciones.',
            codeBefore: '// Timeout en tiempo de carga',
            codeAfter: '// Optimizar la entrega de recursos e infraestructura del frontend'
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-400']
          }
        });

        await visualMetaInspector.captureScreenshot(baseDir, 'evidence_landing_failed');
        return allFindings;
      }

      // Captura de evidencia tras renderizado exitoso
      await visualMetaInspector.captureScreenshot(baseDir, 'evidence_landing');

      // -----------------------------------------------------------------------
      // 🛡️ NIVEL 1: Inspección de Cabeceras HTTP
      // -----------------------------------------------------------------------
      if (mainResponse) {
        const headersInspector = new HeadersConfigInspector();
        const headerFindings = headersInspector.inspectHeadersFromResponse(
          this.options.targetUrl,
          mainResponse.status(),
          mainResponse.headers()
        );
        allFindings.push(...headerFindings);
      } else {
        console.warn(`[WARN] No se obtuvo respuesta HTTP principal para ${this.options.targetUrl}.`);
      }

      // -----------------------------------------------------------------------
      // 2. Tareas Aisladas por Contexto Independiente
      // -----------------------------------------------------------------------
      const inspectorTasks: Promise<AuditFinding[]>[] = [];

      // Storage & Meta (Contexto Principal)
      inspectorTasks.push(consoleInspector.inspectStorage());
      inspectorTasks.push(
        visualMetaInspector.inspectMetadata().then((issues) =>
          issues.map(
            (issue): AuditFinding => ({
              id: `META-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
              ruleId: issue.type,
              title: issue.message,
              severity: issue.severity === 'LOW' ? 'LOW' : 'INFO',
              description: issue.message,
              evidence: {
                screenshotPath: `${baseDir}/screenshots/evidence_landing.png`
              },
              remediation: {
                explanation:
                  'Remueva la etiqueta <meta name="generator"> o configure el servidor para no exponer la versión exacta.',
                codeBefore: '<meta name="generator" content="Framework/v1.0">',
                codeAfter: '<!-- Remover la etiqueta meta generator -->'
              },
              standards: {
                owasp: ['A05:2021-Security Misconfiguration'],
                cwe: ['CWE-200']
              }
            })
          )
        )
      );

      // Contexto Aislado 1: FormInspector
      const formTask = (async (): Promise<AuditFinding[]> => {
        const formCtx = await browser.newContext(contextOptions);
        formCtx.setDefaultTimeout(this.options.timeoutMs);
        contextsToClose.push(formCtx);

        const formPage = await formCtx.newPage();
        const resp = await formPage.goto(this.options.targetUrl, { waitUntil: 'domcontentloaded' });

        if (!resp || !resp.ok()) {
          console.error(`[ERROR] FormInspector no pudo cargar la página target. Status: ${resp?.status()}`);
          return [];
        }

        const formInspector = new FormActiveInspector(formPage);
        return formInspector.executeActiveFuzzing();
      })();
      inspectorTasks.push(formTask);

      // Contexto Aislado 2: FuzzingInspector
      if (this.options.activeFuzzing) {
        const fuzzTask = (async (): Promise<AuditFinding[]> => {
          const fuzzCtx = await browser.newContext(contextOptions);
          fuzzCtx.setDefaultTimeout(this.options.timeoutMs);
          contextsToClose.push(fuzzCtx);

          const fuzzPage = await fuzzCtx.newPage();
          const resp = await fuzzPage.goto(this.options.targetUrl, { waitUntil: 'domcontentloaded' });

          if (!resp || !resp.ok()) {
            console.error(`[ERROR] FuzzingInspector no pudo cargar la página target. Status: ${resp?.status()}`);
            return [];
          }

          const fuzzingInspector = new FuzzingInspector(fuzzPage);
          return fuzzingInspector.executeFuzzing();
        })();
        inspectorTasks.push(fuzzTask);
      }

      // Esperar todos los inspectores
      const results = await Promise.allSettled(inspectorTasks);

      results.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          allFindings.push(...result.value);
        } else {
          console.error(`[CRITICAL] Inspector en índice ${index} colapsó con error:`, result.reason);
        }
      });

      return this.deduplicateFindings(allFindings);
    } finally {
      // Cierre limpio de contextos e instancias
      for (const ctx of contextsToClose) {
        await ctx.close().catch(() => {});
      }
      if (browser) {
        await browser.close();
      }
    }
  }

  private deduplicateFindings(findings: AuditFinding[]): AuditFinding[] {
    const groupedMap = new Map<string, AuditFinding>();

    for (const finding of findings) {
      const key = finding.ruleId;

      const currentLocation: FindingLocation = {
        selector: finding.evidence.selector,
        snippet: finding.evidence.snippet
      };

      if (!groupedMap.has(key)) {
        const locations: FindingLocation[] = [];
        if (currentLocation.selector || currentLocation.snippet) {
          locations.push(currentLocation);
        }

        groupedMap.set(key, {
          ...finding,
          evidence: {
            ...finding.evidence,
            ...(locations.length > 0 ? { locations } : {})
          }
        });
      } else {
        const existingFinding = groupedMap.get(key)!;

        if (!existingFinding.evidence.locations) {
          existingFinding.evidence.locations = [];
          if (existingFinding.evidence.selector || existingFinding.evidence.snippet) {
            existingFinding.evidence.locations.push({
              selector: existingFinding.evidence.selector,
              snippet: existingFinding.evidence.snippet
            });
          }
        }

        if (currentLocation.selector || currentLocation.snippet) {
          existingFinding.evidence.locations.push(currentLocation);
        }
      }
    }

    return Array.from(groupedMap.values()).map((finding) => {
      const locationsCount = finding.evidence.locations?.length || 0;

      if (locationsCount > 1) {
        return {
          ...finding,
          title: `${finding.title} (${locationsCount} elementos detectados)`,
          description: `${finding.description} Se identificaron un total de ${locationsCount} ocurrencias en el DOM.`
        };
      }

      return finding;
    });
  }

  /**
   * Usa el outputDir de la CLI si está definido; si no, genera un path con timestamp
   * (uso standalone del runner sin orquestación CLI).
   */
  private getOutputDir(): string {
    if (this.options.outputDir) {
      return this.options.outputDir;
    }

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
    return `./audit-results/${domainSlug}_${localTimestamp}`;
  }
}