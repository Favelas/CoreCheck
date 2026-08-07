import { promises as fs } from 'fs';
import * as path from 'node:path';
import { Browser, BrowserContext, Response, chromium } from 'playwright';

import { ConsoleDataInspector } from '../inspectors/console_data_inspector.js';
import { FormActiveInspector } from '../inspectors/form_active_inspector.js';
import { FuzzingInspector } from '../inspectors/fuzzing_inspector.js';
import { HeadersConfigInspector } from '../inspectors/headers_config_inspector.js';
import { A11yRealInspector } from '../inspectors/a11y_real_inspector.js';
import { NetworkPassiveInspector } from '../inspectors/network_passive_inspector.js';
import { PerformanceInspector } from '../inspectors/performance_inspector.js';
import { PrivacyInspector } from '../inspectors/privacy_inspector.js';
import { SeoGeoInspector } from '../inspectors/seo_geo_inspector.js';
import { LlmReadinessInspector } from '../inspectors/llm_readiness_inspector.js';
import { VisualMetaInspector } from '../inspectors/visual_meta_inspector.js';
import {
  AuditAuthConfig,
  AuditExecutionOptions,
  AuditFinding,
  AuditRunResult,
  FindingLocation,
  OutputFormat
} from '../types/audit.js';
import { sanitizeAndBudgetEvidence } from '../utils/evidence.js';
import { CoreCheckError } from '../utils/exit_codes.js';
import {
  chromiumLaunchArgsForBudget,
  clampConcurrency
} from '../utils/resource_budget.js';
import {
  formatWafNetworkMessage,
  isRetryableStatus,
  withExponentialBackoff
} from '../utils/http_retry.js';
import { AuthHandler } from './auth_handler.js';
import { SiteCrawler } from './crawler.js';
import { ZeroFPEngine } from './zero_fp_engine.js';

type BrowserContextOptions = Parameters<Browser['newContext']>[0];

type RunnerOptions = Required<
  Omit<AuditExecutionOptions, 'authConfig' | 'environment' | 'baselinePath' | 'apiKey'>
> & {
  authConfig?: AuditAuthConfig;
  environment?: AuditExecutionOptions['environment'];
  baselinePath?: string;
  apiKey?: string;
};

export class AuditRunner {
  private options: RunnerOptions;

  constructor(options: AuditExecutionOptions) {
    const defaultFormats: OutputFormat[] = ['json', 'sarif'];
    const requestedConcurrency = options.concurrency ?? 2;
    const budget = clampConcurrency({
      requestedConcurrency,
      activeFuzzing: options.activeFuzzing ?? false
    });

    if (budget.capped && budget.reason) {
      console.warn(`[ResourceBudget] ${budget.reason}`);
    }

    this.options = {
      targetUrl: options.targetUrl,
      storageStatePath: options.storageStatePath ?? '',
      concurrency: budget.concurrency,
      timeoutMs: options.timeoutMs ?? 30000,
      maxRetries: options.maxRetries ?? 2,
      activeFuzzing: options.activeFuzzing ?? false,
      outputFormats: options.outputFormats ?? defaultFormats,
      outputDir: options.outputDir ?? '',
      maxDepth: options.maxDepth ?? 2,
      maxPages: options.maxPages ?? 10,
      sameOriginOnly: options.sameOriginOnly ?? true,
      authConfig: options.authConfig,
      environment: options.environment,
      baselinePath: options.baselinePath,
      apiKey: options.apiKey
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
      try {
        browser = await chromium.launch({
          headless: true,
          args: chromiumLaunchArgsForBudget()
        });
      } catch (launchError) {
        throw new CoreCheckError(
          `No se pudo lanzar Chromium/Playwright: ${(launchError as Error).message}`,
          'ENGINE'
        );
      }

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

      if (this.options.authConfig) {
        const authHandler = new AuthHandler();
        try {
          const authResult = await authHandler.authenticate(
            crawlContext,
            this.options.authConfig,
            this.options.timeoutMs
          );

          if (authResult.extraHTTPHeaders) {
            contextOptions.extraHTTPHeaders = {
              ...(contextOptions.extraHTTPHeaders ?? {}),
              ...authResult.extraHTTPHeaders
            };
          }
          if (authResult.storageState) {
            contextOptions.storageState = authResult.storageState;
          }
        } catch (authError) {
          const msg = (authError as Error).message;
          const looksNetwork =
            /ENOTFOUND|ECONNREFUSED|Timeout|net::ERR_|403|429|unreachable/i.test(msg);
          throw new CoreCheckError(
            `Fallo de autenticación previa al crawl: ${msg}`,
            looksNetwork ? 'NETWORK' : 'CONFIG'
          );
        }
      }

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

      // Re-evaluar presupuesto si el DOM del landing es denso (SPA/pesada).
      const domDensity = await this.probeDomDensity(crawlPage);
      let concurrency = Math.max(1, Math.floor(this.options.concurrency) || 1);
      if (domDensity === 'high') {
        const adjusted = clampConcurrency({
          requestedConcurrency: concurrency,
          activeFuzzing: this.options.activeFuzzing,
          domDensity: 'high'
        });
        if (adjusted.capped || adjusted.concurrency < concurrency) {
          console.warn(
            `[ResourceBudget] High DOM density detected — concurrency ${concurrency} → ${adjusted.concurrency}`
          );
        }
        concurrency = adjusted.concurrency;
      }

      const artifactsDir = path.join(baseDir, 'artifacts');
      console.log(
        `[Audit] Escaneo de páginas con concurrency=${concurrency}` +
          (concurrency > 1
            ? ' (contextos Playwright en paralelo; Zero-FP sigue serial)'
            : '')
      );

      // Pool de workers: paraleliza auditSinglePage respetando --concurrency.
      // Límite: cada worker abre su propio BrowserContext; valores altos aumentan
      // presión de memoria/CPU en runners CI. Zero-FP permanece serial post-dedup.
      let cursor = 0;
      const workerCount = Math.min(concurrency, scannedPages.length);
      const workers = Array.from({ length: workerCount }, async () => {
        while (true) {
          const i = cursor++;
          if (i >= scannedPages.length) {
            return;
          }
          const pageUrl = scannedPages[i];
          console.log(`[Audit] (${i + 1}/${scannedPages.length}) ${pageUrl}`);

          const pageFindings = await this.auditSinglePage(
            browser!,
            contextOptions,
            contextsToClose,
            pageUrl,
            baseDir,
            i === 0
          );
          allFindings.push(...this.stampPageUrl(pageFindings, pageUrl, artifactsDir));
        }
      });
      await Promise.all(workers);

      const deduped = this.deduplicateFindings(allFindings);

      const revalContext = await browser.newContext(contextOptions);
      revalContext.setDefaultTimeout(this.options.timeoutMs);
      contextsToClose.push(revalContext);
      const revalPage = await revalContext.newPage();
      const zeroFp = new ZeroFPEngine(revalPage, this.options.timeoutMs);
      const findings = await zeroFp.revalidate(deduped);

      return {
        findings,
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
    const networkInspector = new NetworkPassiveInspector(page);
    const performanceInspector = new PerformanceInspector(page);
    const privacyInspector = new PrivacyInspector(page);
    networkInspector.attach(pageUrl);
    performanceInspector.attach();
    privacyInspector.attach(pageUrl);

    let navigationSuccess = false;
    let attemptMeta = { attempts: 0, lastStatus: undefined as number | undefined };
    let mainResponse: Response | null = null;

    try {
      const navOutcome = await withExponentialBackoff(
        async () => {
          const response = await page.goto(pageUrl, {
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
          return response;
        },
        (response) => response?.status(),
        {
          maxAttempts: Math.max(2, this.options.maxRetries + 1),
          baseDelayMs: 400,
          maxDelayMs: 8_000,
          onRetry: ({ attempt, status, delayMs }) => {
            console.warn(
              `[Audit] Retry nav ${attempt} ${pageUrl} (HTTP ${status ?? 'n/a'}) — backoff ${delayMs}ms`
            );
          }
        }
      );
      mainResponse = navOutcome.value;
      attemptMeta = {
        attempts: navOutcome.attempts,
        lastStatus: navOutcome.lastStatus
      };
      if (isRetryableStatus(navOutcome.lastStatus)) {
        const msg = formatWafNetworkMessage(
          navOutcome.lastStatus!,
          pageUrl,
          navOutcome.attempts
        );
        // Landing/target principal → fail-closed NETWORK (exit 3).
        // Subpáginas → hallazgo INFRA sin tumbar toda la corrida.
        if (captureLandingScreenshot) {
          throw new CoreCheckError(msg, 'NETWORK');
        }
        findings.push({
          id: `WAF-${Date.now()}`,
          ruleId: 'INFRA-WAF-RATE-LIMIT',
          title: 'WAF / Rate-limit bloqueó la navegación',
          severity: 'HIGH',
          category: 'INFRA',
          ruleType: 'INFRA_FAILURE',
          description: msg,
          evidence: {
            url: pageUrl,
            responseStatus: navOutcome.lastStatus,
            snippet: msg.slice(0, 512)
          },
          remediation: {
            explanation:
              'Allowlist de runners CI, reducir ritmo de crawl o auditar staging sin bot protection.',
            codeBefore: '// 403/429 persistente',
            codeAfter: '// backoff + allowlist + staging interno'
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-400']
          }
        });
        return findings;
      }
      navigationSuccess = true;
    } catch (error) {
      if (error instanceof CoreCheckError) {
        throw error;
      }
      console.error(`[CRITICAL] Error al renderizar ${pageUrl}: ${(error as Error).message}`);
    }

    if (!navigationSuccess) {
      findings.push({
        id: `NAV-FAILED-${Date.now()}`,
        ruleId: 'SEC-NAV-RENDER-FAILED',
        title: 'Fallo Crítico en la Carga y Renderizado de la Aplicación Target',
        severity: 'CRITICAL',
        category: 'INFRA',
        ruleType: 'INFRA_FAILURE',
        description:
          `La aplicación en '${pageUrl}' no se renderizó dentro del tiempo límite (${this.options.timeoutMs}ms)` +
          (attemptMeta.lastStatus ? ` (last HTTP ${attemptMeta.lastStatus})` : '') +
          `.`,
        evidence: {
          url: pageUrl,
          responseStatus: attemptMeta.lastStatus,
          snippet: await page.content().catch(() => 'Sin contenido DOM')
        },
        remediation: {
          explanation:
            'Verifique que el servidor responda, no bloquee automatizaciones (WAF) y optimice el render inicial.',
          codeBefore: '// Timeout en tiempo de carga',
          codeAfter: '// Optimizar entrega de recursos + allowlist runners CI'
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

    const namedInspectors: Array<{ name: string; task: Promise<AuditFinding[]> }> = [
      { name: 'ConsoleDataInspector', task: consoleInspector.inspectStorage() },
      { name: 'A11yRealInspector', task: new A11yRealInspector(page).inspect() },
      { name: 'NetworkPassiveInspector', task: networkInspector.collect() },
      { name: 'PerformanceInspector', task: performanceInspector.inspect(pageUrl) },
      { name: 'SeoGeoInspector', task: new SeoGeoInspector(page).inspect(pageUrl) },
      // llm.txt es origin-scoped; se ejecuta en todas las páginas y el consolidator lo fusiona.
      { name: 'LlmReadinessInspector', task: new LlmReadinessInspector(page).inspect(pageUrl) },
      { name: 'PrivacyInspector', task: privacyInspector.inspect(pageUrl) },
      {
        name: 'VisualMetaInspector',
        task: visualMetaInspector.inspectMetadata().then((issues) =>
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
      },
      {
        name: 'FormActiveInspector',
        task: (async (): Promise<AuditFinding[]> => {
          const formCtx = await browser.newContext(contextOptions);
          formCtx.setDefaultTimeout(this.options.timeoutMs);
          contextsToClose.push(formCtx);

          const formPage = await formCtx.newPage();
          const resp = await formPage.goto(pageUrl, { waitUntil: 'domcontentloaded' });

          if (!resp || !resp.ok()) {
            console.error(
              `[ERROR] FormInspector no pudo cargar ${pageUrl}. Status: ${resp?.status()}`
            );
            return [
              this.buildInfraFailureFinding(
                'FormActiveInspector',
                pageUrl,
                `No se pudo cargar la página para auditoría de formularios (HTTP ${resp?.status() ?? 'n/a'}).`
              )
            ];
          }

          const formInspector = new FormActiveInspector(formPage);
          return formInspector.executeActiveFuzzing();
        })()
      }
    ];

    if (this.options.activeFuzzing) {
      namedInspectors.push({
        name: 'FuzzingInspector',
        task: (async (): Promise<AuditFinding[]> => {
          const fuzzCtx = await browser.newContext(contextOptions);
          fuzzCtx.setDefaultTimeout(this.options.timeoutMs);
          contextsToClose.push(fuzzCtx);

          const fuzzPage = await fuzzCtx.newPage();
          const resp = await fuzzPage.goto(pageUrl, { waitUntil: 'domcontentloaded' });

          if (!resp || !resp.ok()) {
            console.error(
              `[ERROR] FuzzingInspector no pudo cargar ${pageUrl}. Status: ${resp?.status()}`
            );
            return [
              this.buildInfraFailureFinding(
                'FuzzingInspector',
                pageUrl,
                `No se pudo cargar la página para fuzzing activo (HTTP ${resp?.status() ?? 'n/a'}).`
              )
            ];
          }

          const fuzzingInspector = new FuzzingInspector(fuzzPage);
          return fuzzingInspector.executeFuzzing();
        })()
      });
    }

    const results = await Promise.allSettled(namedInspectors.map((n) => n.task));
    results.forEach((result, index) => {
      const inspectorName = namedInspectors[index]?.name ?? `Inspector#${index}`;
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      } else {
        const reason =
          result.reason instanceof Error
            ? result.reason.message
            : String(result.reason);
        console.error(`[INFRA_FAILURE] ${inspectorName} colapsó:`, reason);
        findings.push(
          this.buildInfraFailureFinding(inspectorName, pageUrl, reason)
        );
      }
    });

    return findings;
  }

  private async probeDomDensity(
    page: import('playwright').Page
  ): Promise<'normal' | 'high'> {
    try {
      const count = await page.evaluate(() => document.querySelectorAll('*').length);
      // Umbral conservador: DOMs densos (SPA/tablas masivas) fuerzan serialización.
      return count >= 2_500 ? 'high' : 'normal';
    } catch {
      return 'normal';
    }
  }

  /** Hallazgo explícito cuando un inspector falla — evita degradación silenciosa. */
  private buildInfraFailureFinding(
    inspectorName: string,
    pageUrl: string,
    reason: string
  ): AuditFinding {
    const safeReason = reason.slice(0, 512);
    return {
      id: `INFRA-${inspectorName}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      ruleId: 'INFRA-INSPECTOR-FAILURE',
      title: `Fallo de infraestructura: ${inspectorName}`,
      severity: 'HIGH',
      category: 'INFRA',
      ruleType: 'INFRA_FAILURE',
      confidence: 'HIGH',
      description:
        `El inspector "${inspectorName}" abortó durante el escaneo de '${pageUrl}'. ` +
        `La dimensión correspondiente puede estar incompleta. Motivo: ${safeReason}`,
      evidence: {
        url: pageUrl,
        snippet: safeReason
      },
      remediation: {
        explanation:
          'Revise logs del runner, estabilidad de Playwright y timeouts. Re-ejecute el gate; ' +
          'si persiste, abra incidente interno (playbook Enterprise).',
        codeBefore: '// Inspector crash silenciado → falso negativo',
        codeAfter: '// INFRA-INSPECTOR-FAILURE visible en gate + artefactos'
      },
      standards: {
        owasp: ['A05:2021-Security Misconfiguration'],
        cwe: ['CWE-754']
      }
    };
  }

  private stampPageUrl(
    findings: AuditFinding[],
    pageUrl: string,
    artifactsDir: string
  ): AuditFinding[] {
    return findings.map((finding) => {
      const budgeted = sanitizeAndBudgetEvidence(
        finding.id,
        finding.evidence.snippet,
        artifactsDir
      );

      const baseLocations: FindingLocation[] =
        finding.evidence.locations ??
        (finding.evidence.selector || finding.evidence.snippet || budgeted.snippet
          ? [
              {
                selector: finding.evidence.selector,
                snippet: budgeted.snippet ?? finding.evidence.snippet
              }
            ]
          : []);

      const locations = baseLocations.map((loc) => {
        const locBudget = sanitizeAndBudgetEvidence(
          `${finding.id}-loc`,
          loc.snippet,
          artifactsDir
        );
        return {
          ...loc,
          snippet: locBudget.snippet ?? loc.snippet,
          url: loc.url ?? pageUrl
        };
      });

      return {
        ...finding,
        evidence: {
          ...finding.evidence,
          url: finding.evidence.url ?? pageUrl,
          snippet: budgeted.snippet ?? finding.evidence.snippet,
          ...(budgeted.artifactPath
            ? { artifactPath: finding.evidence.artifactPath ?? budgeted.artifactPath }
            : {}),
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
