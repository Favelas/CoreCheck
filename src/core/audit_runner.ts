import { chromium, Browser } from 'playwright';
import { AuditExecutionOptions, AuditFinding, OutputFormat } from '../types/audit';
import { FormActiveInspector } from '../inspectors/form_active_inspector';
import { exportToSarif } from '../utils/sarif_exporter';
import * as fs from 'fs/promises';

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

      page.setDefaultTimeout(this.options.timeoutMs!);

      // Estrategia de Retries y Resiliencia en la Navegación
      let navigationSuccess = false;
      let attempt = 0;

      while (attempt <= this.options.maxRetries! && !navigationSuccess) {
        try {
          attempt++;
          await page.goto(this.options.targetUrl, { waitUntil: 'networkidle' });
          navigationSuccess = true;
        } catch (error) {
          if (attempt > this.options.maxRetries!) {
            throw new Error(`Falló la conexión con ${this.options.targetUrl} tras ${attempt} reintentos: ${(error as Error).message}`);
          }
          await new Promise((res) => setTimeout(res, 2000));
        }
      }

      // Ejecución aislada de Inspectores mediante Promise.allSettled
      const inspectorTasks: Promise<AuditFinding[]>[] = [];

      if (this.options.activeFuzzing) {
        const activeInspector = new FormActiveInspector(page);
        inspectorTasks.push(activeInspector.executeActiveFuzzing());
      }

      // Esperar la resolución de todos los inspectores sin colapsar la suite si uno falla
      const results = await Promise.allSettled(inspectorTasks);

      results.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          allFindings.push(...result.value);
        } else {
          console.error(`[CRITICAL] Inspector en índice ${index} colapsó con error:`, result.reason);
        }
      });

      // Consolidación y exportación de reportes
      await this.generateReports(allFindings);

      return allFindings;
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }

  private async generateReports(findings: AuditFinding[]): Promise<void> {
  // 1. Extraer el nombre/dominio del sitio web (ej. "automationexercise.com" o "saucedemo.com")
  let domainSlug = 'target';
  try {
    const parsedUrl = new URL(this.options.targetUrl);
    domainSlug = parsedUrl.hostname.replace(/^www\./, ''); // Quita el 'www.' si existe
  } catch {
    domainSlug = this.options.targetUrl.replace(/[^a-zA-Z0-9]/g, '_');
  }

  // 2. Obtener la hora local formateada (Año-Mes-Día_Hora-Minuto-Segundo)
  const now = new Date();
  const pad = (n: number) => n.toString().padStart(2, '0');
  
  const year = now.getFullYear();
  const month = pad(now.getMonth() + 1);
  const day = pad(now.getDate());
  const hours = pad(now.getHours());
  const minutes = pad(now.getMinutes());
  const seconds = pad(now.getSeconds());

  const localTimestamp = `${year}-${month}-${day}_${hours}-${minutes}-${seconds}`;

  // 3. Crear el nombre de la carpeta identificable: [dominio]_[fecha_hora_local]
  const folderName = `${domainSlug}_${localTimestamp}`;
  const baseDir = `./audit-results/${folderName}`;

  await fs.mkdir(baseDir, { recursive: true });

  if (this.options.outputFormats.includes('json')) {
    await fs.writeFile(
      `${baseDir}/report.json`,
      JSON.stringify({ target: this.options.targetUrl, timestamp: localTimestamp, findings }, null, 2),
      'utf-8'
    );
  }

  if (this.options.outputFormats.includes('sarif')) {
    await exportToSarif(findings, `${baseDir}/results.sarif`);
  }
}
}