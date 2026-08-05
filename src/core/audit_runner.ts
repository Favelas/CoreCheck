import { promises as fs } from 'fs';
import { Browser, BrowserContext, Response, chromium } from 'playwright';

import { ConsoleDataInspector } from '../inspectors/console_data_inspector.js';
import { FormActiveInspector } from '../inspectors/form_active_inspector.js';
import { FuzzingInspector } from '../inspectors/fuzzing_inspector.js';
import { HeadersConfigInspector } from '../inspectors/headers_config_inspector.js';
import { VisualMetaInspector } from '../inspectors/visual_meta_inspector.js';
import {
  AuditExecutionOptions,
  AuditFinding,
  AuditRunResult,
  FindingLocation,
  OutputFormat
} from '../types/audit.js';
import { SiteCrawler } from './crawler.js';

type BrowserContextOptions = Parameters<Browser['newContext']>[0];

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
      activeFuzzing: options.activeFuzzing ?? false,
      outputFormats: options.outputFormats ?? defaultFormats,
      outputDir: options.outputDir ?? '',
      maxDepth: options.maxDepth ?? 2,
      maxPages: options.maxPages ?? 10,
      sameOriginOnly: options.sameOriginOnly ?? true
    };
  }

  public async run(): Promise<AuditRunResult> {
    let browser: Browser | null = null;
    const contextsToClose: BrowserContext[] = [];
    const allFindings: AuditFinding[] = [];
    let scannedPages: string[] = [];

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

      const contextOptions: BrowserContextOptions = {
        ...(this.options.storageStatePath ? { storageState: this.options.storageStatePath } : {}),
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        viewport: { width: 1280, height: 720 },
        deviceScaleFactor: 1,
        isMobile: false,
        hasTouch: false
      };

      const crawlContext = await browser.newContext(contextOptions);
      crawlContext.setDefaultTimeout(this.options.timeoutMs);
      contextsToClose.push(crawlContext);

      const crawlPage = await crawlContext.newPage();
      const crawler = new SiteCrawler(crawlPage);

      console.log(
        `[Crawler] Descubriendo superficie (maxDepth=${this.options.maxDepth}, maxPages=${this.options.maxPages}, sameOriginOnly=${this.options.sameOriginOnly})...`
      );

      const crawlResult = await crawler.crawl({
        startUrl: this.options.targetUrl,
        maxDepth: this.options.maxDepth,
        maxPages: this.options.maxPages,
        sameOriginOnly: this.options.sameOriginOnly,
        timeoutMs: this.options.timeoutMs
      });

      scannedPages = crawlResult.pages.map((p) => p.url);
      if (scannedPages.length === 0) {
        scannedPages = [this.options.targetUrl];
      }

      console.log(`[Crawler] Páginas a auditar (${scannedPages.length}):`);
      scannedPages.forEach((url, index) => console.log(`  ${index + 1}. ${url}`));

      for (let i = 0; i < scannedPages.length; i++) {
        const pageUrl = scannedPages[i];
        console.log(`[Audit] (${i + 1}/${scannedPages.length}) ${pageUrl}`);

        const pageFindings = await this.auditSinglePage(
          browser,
          contextOptions,
          contextsToClose,
          pageUrl,
          baseDir,
          i === 0
        );
        allFindings.push(...this.stampPageUrl(pageFindings, pageUrl));
      }

      return {
        findings: this.deduplicateFindings(allFindings),
        scannedPages
      };
    } finally {
      for (const ctx of contextsToClose) {
        await ctx.close().catch(() => {});
      }
      if (browser) {
        await browser.close();
      }
    }
  }

  private async auditSinglePage(
    browser: Browser,
    contextOptions: BrowserContextOptions,
    contextsToClose: BrowserContext[],
    pageUrl: string,
    baseDir: string,
    captureLandingScreenshot: boolean
  ): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const pageContext = await browser.newContext(contextOptions);
    pageContext.setDefaultTimeout(this.options.timeoutMs);
    contextsToClose.push(pageContext);

    const page = await pageContext.newPage();
    const consoleInspector = new ConsoleDataInspector(page);
    const visualMetaInspector = new VisualMetaInspector(page);

    let navigationSuccess = false;
    let attempt = 0;
    let mainResponse: Response | null = null;

    while (attempt <= this.options.maxRetries && !navigationSuccess) {
      try {
        attempt++;
        mainResponse = await page.goto(pageUrl, {
          waitUntil: 'commit',
          timeout: this.options.timeoutMs
        });

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
          console.error(`[CRITICAL] Error al renderizar ${pageUrl}: ${(error as Error).message}`);
        } else {
          await new Promise((res) => setTimeout(res, 2000));
        }
      }
    }

    if (!navigationSuccess) {
      findings.push({
        id: `NAV-FAILED-${Date.now()}`,
        ruleId: 'SEC-NAV-RENDER-FAILED',
        title: 'Fallo Crítico en la Carga y Renderizado de la Aplicación Target',
        severity: 'CRITICAL',
        description: `La aplicación en '${pageUrl}' no se renderizó dentro del tiempo límite (${this.options.timeoutMs}ms).`,
        evidence: {
          url: pageUrl,
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

      if (captureLandingScreenshot) {
        await visualMetaInspector.captureScreenshot(baseDir, 'evidence_landing_failed');
      }
      return findings;
    }

    if (captureLandingScreenshot) {
      await visualMetaInspector.captureScreenshot(baseDir, 'evidence_landing');
    }

    if (mainResponse) {
      const headersInspector = new HeadersConfigInspector();
      findings.push(
        ...headersInspector.inspectHeadersFromResponse(
          pageUrl,
          mainResponse.status(),
          mainResponse.headers()
        )
      );
    } else {
      console.warn(`[WARN] No se obtuvo respuesta HTTP principal para ${pageUrl}.`);
    }

    const inspectorTasks: Promise<AuditFinding[]>[] = [];

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
              url: pageUrl,
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

    const formTask = (async (): Promise<AuditFinding[]> => {
      const formCtx = await browser.newContext(contextOptions);
      formCtx.setDefaultTimeout(this.options.timeoutMs);
      contextsToClose.push(formCtx);

      const formPage = await formCtx.newPage();
      const resp = await formPage.goto(pageUrl, { waitUntil: 'domcontentloaded' });

      if (!resp || !resp.ok()) {
        console.error(
          `[ERROR] FormInspector no pudo cargar ${pageUrl}. Status: ${resp?.status()}`
        );
        return [];
      }

      const formInspector = new FormActiveInspector(formPage);
      return formInspector.executeActiveFuzzing();
    })();
    inspectorTasks.push(formTask);

    if (this.options.activeFuzzing) {
      const fuzzTask = (async (): Promise<AuditFinding[]> => {
        const fuzzCtx = await browser.newContext(contextOptions);
        fuzzCtx.setDefaultTimeout(this.options.timeoutMs);
        contextsToClose.push(fuzzCtx);

        const fuzzPage = await fuzzCtx.newPage();
        const resp = await fuzzPage.goto(pageUrl, { waitUntil: 'domcontentloaded' });

        if (!resp || !resp.ok()) {
          console.error(
            `[ERROR] FuzzingInspector no pudo cargar ${pageUrl}. Status: ${resp?.status()}`
          );
          return [];
        }

        const fuzzingInspector = new FuzzingInspector(fuzzPage);
        return fuzzingInspector.executeFuzzing();
      })();
      inspectorTasks.push(fuzzTask);
    }

    const results = await Promise.allSettled(inspectorTasks);
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      } else {
        console.error(`[CRITICAL] Inspector en índice ${index} colapsó:`, result.reason);
      }
    });

    return findings;
  }

  private stampPageUrl(findings: AuditFinding[], pageUrl: string): AuditFinding[] {
    return findings.map((finding) => {
      const baseLocations: FindingLocation[] =
        finding.evidence.locations ??
        (finding.evidence.selector || finding.evidence.snippet
          ? [
              {
                selector: finding.evidence.selector,
                snippet: finding.evidence.snippet
              }
            ]
          : []);

      const locations = baseLocations.map((loc) => ({
        ...loc,
        url: loc.url ?? pageUrl
      }));

      return {
        ...finding,
        evidence: {
          ...finding.evidence,
          url: finding.evidence.url ?? pageUrl,
          ...(locations.length > 0 ? { locations } : {})
        }
      };
    });
  }

  private deduplicateFindings(findings: AuditFinding[]): AuditFinding[] {
    const groupedMap = new Map<string, AuditFinding>();

    for (const finding of findings) {
      const pageUrl = finding.evidence.url ?? '';
      const key = `${finding.ruleId}::${pageUrl}::${finding.evidence.selector ?? ''}`;

      const currentLocation: FindingLocation = {
        selector: finding.evidence.selector,
        snippet: finding.evidence.snippet,
        url: pageUrl || undefined
      };

      if (!groupedMap.has(key)) {
        const locations: FindingLocation[] = [];
        if (currentLocation.selector || currentLocation.snippet || currentLocation.url) {
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
          if (
            existingFinding.evidence.selector ||
            existingFinding.evidence.snippet ||
            existingFinding.evidence.url
          ) {
            existingFinding.evidence.locations.push({
              selector: existingFinding.evidence.selector,
              snippet: existingFinding.evidence.snippet,
              url: existingFinding.evidence.url
            });
          }
        }

        if (currentLocation.selector || currentLocation.snippet || currentLocation.url) {
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
