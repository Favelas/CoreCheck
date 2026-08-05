#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';

import { AuditRunner } from '../core/audit_runner.js';
import { ComplianceMapper } from '../core/compliance_mapper.js';
import { CvssScorer } from '../core/cvss_scorer.js';
import { FindingConsolidator } from '../core/finding_consolidator.js';
import { PolicyEngine } from '../core/policy_engine.js';
import {
  buildTicketPayloads,
  notifyWebhook,
  TicketClient
} from '../integrations/index.js';
import { LicenseValidator, UsageTelemetry } from '../licensing/index.js';
import { generateHtmlReport } from '../reporters/htmlReporter.js';
import { generateMarkdownReport } from '../reporters/markdownReporter.js';
import { buildAttestation, generatePdfReport } from '../reporters/pdf_reporter.js';
import {
  AuditEnvironment,
  AuditExecutionOptions,
  AuditReportBundle,
  CvssVersion,
  OutputFormat,
  SeverityLevel,
  TicketProvider
} from '../types/audit.js';
import { LicenseModule } from '../types/license.js';
import { exportToSarif } from '../utils/sarif_exporter.js';

const program = new Command();

const VALID_SEVERITIES = new Set<SeverityLevel>([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
]);

const VALID_FORMATS = new Set<OutputFormat>([
  'json',
  'sarif',
  'html',
  'markdown',
  'pdf'
]);

const VALID_ENVS = new Set<AuditEnvironment>(['prod', 'staging', 'dev']);
const VALID_TICKETS = new Set<TicketProvider>(['jira', 'azure_boards', 'gitlab']);
const VALID_CVSS = new Set<CvssVersion>(['3.1', '4.0']);

function parseFormats(raw: string): OutputFormat[] {
  const formats = raw
    .split(',')
    .map((f) => f.trim().toLowerCase())
    .filter(Boolean) as OutputFormat[];

  if (formats.length === 0) {
    throw new Error(
      'Debe indicar al menos un formato en --formats (json,sarif,html,markdown,pdf).'
    );
  }

  const invalid = formats.filter((f) => !VALID_FORMATS.has(f));
  if (invalid.length > 0) {
    throw new Error(
      `Formato(s) inválido(s): ${invalid.join(', ')}. Válidos: ${[...VALID_FORMATS].join(', ')}.`
    );
  }

  return [...new Set(formats)];
}

function parseFailOn(raw: string): SeverityLevel {
  const severity = raw.trim().toUpperCase() as SeverityLevel;
  if (!VALID_SEVERITIES.has(severity)) {
    throw new Error(
      `Severidad inválida en --fail-on: "${raw}". Válidas: ${[...VALID_SEVERITIES].join(', ')}.`
    );
  }
  return severity;
}

function parseEnvironment(raw: string): AuditEnvironment {
  const env = raw.trim().toLowerCase() as AuditEnvironment;
  if (!VALID_ENVS.has(env)) {
    throw new Error(
      `Entorno inválido en --environment: "${raw}". Válidos: prod, staging, dev.`
    );
  }
  return env;
}

function parseCvssVersion(raw: string): CvssVersion {
  const version = raw.trim() as CvssVersion;
  if (!VALID_CVSS.has(version)) {
    throw new Error(
      `Versión CVSS inválida en --cvss-version: "${raw}". Válidas: 3.1, 4.0.`
    );
  }
  return version;
}

/** Parsea `--auth-header "Name: Value"` repetibles a Record. */
function parseAuthHeaders(rawHeaders: string[] | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  if (!rawHeaders || rawHeaders.length === 0) {
    return headers;
  }

  for (const raw of rawHeaders) {
    const sep = raw.indexOf(':');
    if (sep <= 0) {
      throw new Error(
        `Header inválido en --auth-header: "${raw}". Use el formato "Name: Value".`
      );
    }
    const name = raw.slice(0, sep).trim();
    const value = raw.slice(sep + 1).trim();
    if (!name || !value) {
      throw new Error(
        `Header inválido en --auth-header: "${raw}". Name y Value son requeridos.`
      );
    }
    headers[name] = value;
  }

  return headers;
}

function assertValidUrl(raw: string): string {
  try {
    const url = new URL(raw);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('protocol');
    }
    return url.toString();
  } catch {
    throw new Error(`URL inválida en --url: "${raw}". Debe ser una URL http(s) absoluta.`);
  }
}

function assertWebhookUrl(raw: string): string {
  try {
    const url = new URL(raw);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('protocol');
    }
    return url.toString();
  } catch {
    throw new Error(
      `URL inválida en --webhook-url: "${raw}". Debe ser una URL http(s) absoluta.`
    );
  }
}

function parsePositiveInt(raw: string, flagName: string): number {
  const value = parseInt(raw, 10);
  if (Number.isNaN(value) || value < 0) {
    throw new Error(`${flagName} debe ser un entero >= 0.`);
  }
  return value;
}

function buildDatedOutputDir(baseDir: string, targetUrl: string): string {
  let domainSlug = 'target';
  try {
    domainSlug = new URL(targetUrl).hostname.replace(/^www\./, '');
  } catch {
    domainSlug = targetUrl.replace(/[^a-zA-Z0-9]/g, '_');
  }

  const now = new Date();
  const pad = (n: number) => n.toString().padStart(2, '0');
  const stamp = [
    `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`,
    `${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`
  ].join('_');

  return path.join(baseDir, `${domainSlug}_${stamp}`);
}

program
  .name('corecheck-audit')
  .description('CoreCheck DevSecOps Engine - Motor de auditoría de seguridad y accesibilidad')
  .requiredOption('-u, --url <string>', 'URL objetivo a auditar')
  .option('-a, --auth-state <path>', 'Ruta al archivo storageState.json de Playwright')
  .option(
    '-f, --formats <items>',
    'Formatos de reporte separados por coma (json,html,sarif,markdown,pdf)',
    'json,html,sarif'
  )
  .option(
    '-o, --output-dir <path>',
    'Directorio base de reportes (se crea subcarpeta dominio_timestamp)',
    './audit-results'
  )
  .option(
    '--flat-output',
    'Escribir reportes directo en --output-dir sin subcarpeta fechada (útil en CI)',
    false
  )
  .option(
    '--fail-on <severity>',
    'Severidad mínima para exit code 1 (override de política por entorno)',
    'HIGH'
  )
  .option('-c, --concurrency <number>', 'Número de ejecuciones concurrentes', '2')
  .option('-t, --timeout <number>', 'Timeout global en ms por página', '30000')
  .option('--max-depth <number>', 'Profundidad máxima del crawler BFS', '2')
  .option('--max-pages <number>', 'Máximo de páginas a descubrir/auditar', '10')
  .option('--fuzzing', 'Habilitar fuzzing activo', false)
  .option('--auth-login-url <url>', 'URL del formulario de login (auth avanzada)')
  .option('--auth-user <username>', 'Usuario para form-login')
  .option('--auth-pass <password>', 'Password para form-login')
  .option(
    '--auth-header <header>',
    'Header HTTP custom "Name: Value" (repetible; p.ej. Authorization: Bearer …)',
    (value: string, previous: string[]) => [...previous, value],
    [] as string[]
  )
  .option(
    '--cvss-version <version>',
    'Versión CVSS para calibración: 3.1 | 4.0',
    '3.1'
  )
  .option('--pdf', 'Generar PDF ejecutivo (equivalente a incluir pdf en --formats)', false)
  .option('--output-pdf <path>', 'Nombre o ruta del PDF (siempre se guarda dentro de --output-dir)')
  .option('--webhook-url <url>', 'Webhook Slack/Teams/genérico para alertas CI/CD')
  .option(
    '--environment <env>',
    'Entorno de política: prod | staging | dev',
    'prod'
  )
  .option(
    '--baseline <path>',
    'Ruta a .corecheckignore o baseline JSON de hallazgos aceptados'
  )
  .option(
    '--tickets <provider>',
    'Exportar / enviar tickets: jira | azure_boards | gitlab'
  )
  .option('--ticket-project <key>', 'Project key / area / GitLab project id para tickets')
  .option(
    '--ticket-submit',
    'Enviar tickets por HTTP (requiere credenciales). Default: dry-run (solo exporta JSON)',
    false
  )
  .option('--jira-domain <url>', 'Jira Cloud domain (ej. https://acme.atlassian.net)')
  .option('--jira-email <email>', 'Jira user email (Basic auth)')
  .option('--jira-token <token>', 'Jira API token (env JIRA_API_TOKEN)')
  .option(
    '--webhook-secret <secret>',
    'HMAC secret para firmar webhooks (env CORECHECK_WEBHOOK_SECRET)'
  )
  .option(
    '--api-key <key>',
    'API Key comercial CoreCheck (alternativa: env CORECHECK_API_KEY)'
  )
  .option(
    '--skip-license',
    'Omitir validación de licencia (solo desarrollo local; no usar en CI prod)',
    false
  );

program.parse(process.argv);

void (async () => {
  const startedAt = Date.now();
  try {
    const opts = program.opts();
    const targetUrl = assertValidUrl(opts.url);
    let outputFormats = parseFormats(opts.formats);
    if (opts.pdf && !outputFormats.includes('pdf')) {
      outputFormats = [...outputFormats, 'pdf'];
    }

    const cliFailOn = parseFailOn(opts.failOn);
    const environment = parseEnvironment(opts.environment as string);
    const maxDepth = parsePositiveInt(opts.maxDepth, '--max-depth');
    let maxPages = parsePositiveInt(opts.maxPages, '--max-pages');
    if (maxPages < 1) {
      throw new Error('--max-pages debe ser >= 1.');
    }

    const webhookUrl = opts.webhookUrl
      ? assertWebhookUrl(opts.webhookUrl as string)
      : undefined;

    const ticketProvider = opts.tickets
      ? (String(opts.tickets).toLowerCase() as TicketProvider)
      : undefined;
    if (ticketProvider && !VALID_TICKETS.has(ticketProvider)) {
      throw new Error(
        `--tickets inválido: "${opts.tickets}". Válidos: jira, azure_boards, gitlab.`
      );
    }

    const wantsPdf = outputFormats.includes('pdf') || Boolean(opts.pdf) || Boolean(opts.outputPdf);
    const requestedModules: LicenseModule[] = ['compliance_mapping'];
    if (wantsPdf) requestedModules.push('pdf_report');
    if (ticketProvider) requestedModules.push('ticketing');
    if (opts.fuzzing) requestedModules.push('active_fuzzing');
    if (webhookUrl) requestedModules.push('webhooks');

    // ——— Fase 4: License gate ———
    const apiKey = LicenseValidator.resolveApiKey(opts.apiKey as string | undefined);
    const skipLicense = Boolean(opts.skipLicense);
    let licenseInfo = undefined as
      | import('../types/license.js').LicenseInfo
      | undefined;

    if (!skipLicense) {
      if (!apiKey) {
        throw new Error(
          'API Key requerida. Use --api-key <key> o la variable de entorno CORECHECK_API_KEY. ' +
            'Para desarrollo local: --api-key cc_dev_growth o --skip-license.'
        );
      }

      const validator = new LicenseValidator();
      const licenseResult = await validator.validate({
        apiKey,
        targetUrl,
        requestedPages: maxPages,
        requestedModules
      });

      if (!licenseResult.ok) {
        // Si el plan limita páginas, auto-cap en lugar de abortar cuando solo es PAGE_LIMIT.
        if (
          licenseResult.code === 'PAGE_LIMIT_EXCEEDED' &&
          licenseResult.effectiveMaxPages &&
          licenseResult.license
        ) {
          console.warn(
            `[License] Cap de páginas aplicado: ${maxPages} → ${licenseResult.effectiveMaxPages} (${licenseResult.license.tier})`
          );
          maxPages = licenseResult.effectiveMaxPages;
          licenseInfo = licenseResult.license;
        } else {
          console.error(`[License] ${licenseResult.code}: ${licenseResult.message}`);
          process.exit(2);
        }
      } else {
        licenseInfo = licenseResult.license;
        if (
          licenseResult.effectiveMaxPages &&
          maxPages > licenseResult.effectiveMaxPages
        ) {
          maxPages = licenseResult.effectiveMaxPages;
        }
        console.log(
          `[License] OK · tier=${licenseInfo?.tier} · org=${licenseInfo?.organization}` +
            (licenseResult.offlineFallback ? ' · offline-cache' : '')
        );
      }

      // Enforce module gates even after OK (defense in depth).
      if (licenseInfo) {
        if (wantsPdf && !licenseInfo.entitlements.allowedModules.includes('pdf_report')) {
          console.error(
            `[License] MODULE_NOT_ALLOWED: reporte PDF requiere Enterprise Core o superior (plan actual: ${licenseInfo.tier}).`
          );
          process.exit(2);
        }
        if (
          ticketProvider &&
          !licenseInfo.entitlements.allowedModules.includes('ticketing')
        ) {
          console.error(
            `[License] MODULE_NOT_ALLOWED: ticketing requiere Enterprise Governance (plan actual: ${licenseInfo.tier}).`
          );
          process.exit(2);
        }
      }
    } else {
      console.warn('[License] --skip-license activo: validación comercial omitida.');
    }

    const baseOutputDir = path.resolve(opts.outputDir);
    const outputDir = opts.flatOutput
      ? baseOutputDir
      : buildDatedOutputDir(baseOutputDir, targetUrl);

    console.log(`[CoreCheck DevSecOps Engine] Iniciando auditoría activa...`);
    console.log(`Target URL: ${targetUrl}`);
    console.log(`Output dir: ${outputDir}`);
    console.log(`Formats: ${outputFormats.join(', ')}`);
    console.log(`Environment: ${environment}`);
    console.log(`Crawler: maxDepth=${maxDepth}, maxPages=${maxPages}`);
    if (webhookUrl) {
      console.log(`Webhook: ${webhookUrl}`);
    }

    fs.mkdirSync(outputDir, { recursive: true });

    const authLoginUrl = opts.authLoginUrl
      ? assertValidUrl(opts.authLoginUrl)
      : undefined;
    if ((opts.authUser || opts.authPass) && !authLoginUrl) {
      throw new Error(
        'Si usa --auth-user/--auth-pass debe indicar también --auth-login-url.'
      );
    }

    const customHeaders = parseAuthHeaders(opts.authHeader as string[] | undefined);
    const hasCustomHeaders = Object.keys(customHeaders).length > 0;
    const cvssVersion = parseCvssVersion(String(opts.cvssVersion ?? '3.1'));
    const concurrency = parsePositiveInt(opts.concurrency, '--concurrency');
    if (concurrency < 1) {
      throw new Error('--concurrency debe ser >= 1.');
    }

    const auditOptions: AuditExecutionOptions = {
      targetUrl,
      storageStatePath: opts.authState,
      concurrency,
      timeoutMs: parseInt(opts.timeout, 10),
      outputFormats,
      outputDir,
      activeFuzzing: Boolean(opts.fuzzing),
      maxDepth,
      maxPages,
      sameOriginOnly: true,
      environment,
      baselinePath: opts.baseline as string | undefined,
      apiKey,
      ...(authLoginUrl || hasCustomHeaders
        ? {
            authConfig: {
              ...(authLoginUrl
                ? {
                    loginUrl: authLoginUrl,
                    username: opts.authUser as string | undefined,
                    password: opts.authPass as string | undefined
                  }
                : {}),
              ...(hasCustomHeaders ? { customHeaders } : {})
            }
          }
        : {})
    };

    const runner = new AuditRunner(auditOptions);
    const { findings, scannedPages } = await runner.run();

    console.log(`\nScanned pages (${scannedPages.length}):`);
    scannedPages.forEach((url) => console.log(`  - ${url}`));

    // 0) Site-level consolidation (headers / privacy policy / robots.txt)
    const consolidator = new FindingConsolidator();
    const { findings: consolidatedFindings, stats: consolidationStats } =
      consolidator.consolidate(findings);
    console.log(
      `[Consolidate] ${consolidationStats.beforeCount} → ${consolidationStats.afterCount} hallazgos` +
        ` (site-level fusionados: ${consolidationStats.siteLevelMerged}, reglas sitio: ${consolidationStats.uniqueSiteRules})`
    );

    // 1) CVSS calibration
    console.log(`CVSS version: ${cvssVersion}`);
    const cvssScorer = new CvssScorer(cvssVersion);
    const cvssFindings = cvssScorer.enrichFindings(consolidatedFindings);
    const { maxCvssScore, penalty: cvssPenalty } =
      cvssScorer.globalScorePenalty(cvssFindings);

    // 2) Policy / baseline suppressions + gate
    const policy = await PolicyEngine.fromPaths({
      environment,
      baselinePath: opts.baseline as string | undefined,
      cwd: process.cwd()
    });
    const failOnSeverity = policy.resolveFailOn(cliFailOn);
    const policyResult = policy.evaluate(cvssFindings, failOnSeverity);

    console.log(
      `Fail-on: ${failOnSeverity} · Suppressed: ${policyResult.suppressedCount} · Max CVSS: ${maxCvssScore}`
    );

    // 3) Compliance + executive bundle
    const mapper = new ComplianceMapper();
    const bundle: AuditReportBundle = mapper.buildReportBundle({
      target: targetUrl,
      scannedPages,
      findings: policyResult.activeFindings,
      failOn: failOnSeverity,
      gateFailed: policyResult.gateFailed,
      environment,
      suppressedCount: policyResult.suppressedCount,
      maxCvssScore,
      cvssPenalty
    });

    // Dashboard HTML local + attestation criptográfica (SHA-256 / HMAC opcional).
    const interactiveDashboardPath = path.join(outputDir, 'interactive-dashboard.html');
    bundle.attestation = buildAttestation(bundle, {
      licenseTier: licenseInfo?.tier,
      organization: licenseInfo?.organization,
      accountId: licenseInfo?.accountId,
      localDashboardPath: interactiveDashboardPath,
      activeFuzzing: Boolean(opts.fuzzing)
    });

    console.log(
      `Digital Quality Score: ${bundle.digitalQualityScore}/100 · Compliance-mapped: ${bundle.compliance.mappedFindingCount}`
    );
    console.log(
      `Attestation Hash (${bundle.attestation.algorithm}): ${bundle.attestation.attestationHash.slice(0, 16)}…`
    );

    // Siempre materializar el dashboard local cuando hay PDF o HTML.
    const wantsInteractive =
      wantsPdf ||
      outputFormats.includes('html') ||
      outputFormats.includes('pdf');
    if (wantsInteractive) {
      generateHtmlReport(bundle, interactiveDashboardPath);
      console.log(`Dashboard interactivo: ${interactiveDashboardPath}`);
    }

    if (outputFormats.includes('json')) {
      const jsonPath = path.join(outputDir, 'findings.json');
      fs.writeFileSync(
        jsonPath,
        JSON.stringify(
          {
            target: bundle.target,
            timestamp: bundle.timestamp,
            environment: bundle.environment,
            attestationHash: bundle.attestation.attestationHash,
            license: licenseInfo
              ? {
                  tier: licenseInfo.tier,
                  accountId: licenseInfo.accountId,
                  organization: licenseInfo.organization,
                  status: licenseInfo.status
                }
              : null,
            attestation: bundle.attestation,
            scannedPages: bundle.scannedPages,
            digitalQualityScore: bundle.digitalQualityScore,
            maxCvssScore: bundle.maxCvssScore,
            severityCounts: bundle.severityCounts,
            dimensions: bundle.dimensions,
            compliance: bundle.compliance,
            gateFailed: bundle.gateFailed,
            failOn: bundle.failOn,
            suppressedCount: bundle.suppressedCount,
            findings: bundle.findings
          },
          null,
          2
        ),
        'utf-8'
      );
      console.log(`Reporte JSON: ${jsonPath}`);
    }

    if (outputFormats.includes('sarif')) {
      const sarifPath = path.join(outputDir, 'results.sarif');
      await exportToSarif(bundle.findings, sarifPath, bundle);
      console.log(`Reporte SARIF: ${sarifPath}`);
    }

    if (outputFormats.includes('html')) {
      const htmlPath = path.join(outputDir, 'report.html');
      generateHtmlReport(bundle, htmlPath);
      console.log(`Reporte HTML: ${htmlPath}`);
    }

    if (outputFormats.includes('markdown')) {
      const mdPath = path.join(outputDir, 'report.md');
      generateMarkdownReport(bundle, mdPath);
      console.log(`Reporte Markdown: ${mdPath}`);
    }

    if (wantsPdf) {
      // Siempre dentro de outputDir (carpeta dominio_timestamp bajo audit-results).
      const pdfFileName = opts.outputPdf
        ? path.basename(String(opts.outputPdf))
        : 'executive-report.pdf';
      const pdfPath = path.join(outputDir, pdfFileName);
      await generatePdfReport(bundle, pdfPath);
      console.log(`Reporte PDF: ${pdfPath}`);
      console.log(`Dashboard (local): ${interactiveDashboardPath}`);
    }

    if (ticketProvider) {
      const ticketFindings = bundle.findings.filter(
        (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
      );
      const ticketContext = {
        projectKey: opts.ticketProject as string | undefined,
        areaPath: opts.ticketProject as string | undefined,
        gitlabProjectId: opts.ticketProject as string | undefined
      };

      // Siempre exportar payloads locales (artefacto CI).
      const payloads = buildTicketPayloads(ticketProvider, ticketFindings, ticketContext);
      const ticketsPath = path.join(outputDir, `tickets-${ticketProvider}.json`);
      fs.writeFileSync(ticketsPath, JSON.stringify(payloads, null, 2), 'utf-8');
      console.log(
        `Ticketing payloads (${ticketProvider}): ${ticketsPath} (${payloads.length})`
      );

      const ticketClient = new TicketClient();
      const wantSubmit = Boolean(opts.ticketSubmit);
      const submitResult = await ticketClient.submit({
        provider: ticketProvider,
        findings: ticketFindings,
        context: ticketContext,
        // dry-run por defecto; --ticket-submit opt-in + credenciales.
        dryRun: !wantSubmit,
        jira: {
          domain: opts.jiraDomain as string | undefined,
          email: opts.jiraEmail as string | undefined,
          apiToken: opts.jiraToken as string | undefined,
          projectKey: opts.ticketProject as string | undefined
        },
        azure: {
          project: opts.ticketProject as string | undefined
        },
        gitlab: {
          projectId: opts.ticketProject as string | undefined
        }
      });

      const submitPath = path.join(outputDir, `tickets-${ticketProvider}-submit.json`);
      fs.writeFileSync(submitPath, JSON.stringify(submitResult, null, 2), 'utf-8');

      if (submitResult.dryRun) {
        console.log(
          `[Ticketing] DRY-RUN (${ticketProvider}): ${submitResult.skipped} issue(s) no enviados. ` +
            `Use --ticket-submit + credenciales (JIRA_DOMAIN/JIRA_EMAIL/JIRA_API_TOKEN/JIRA_PROJECT_KEY).`
        );
      } else {
        console.log(
          `[Ticketing] HTTP (${ticketProvider}): submitted=${submitResult.submitted} failed=${submitResult.failed}`
        );
        for (const r of submitResult.results.filter((x) => x.ok && x.issueKey)) {
          console.log(`  · ${r.ruleId} → ${r.issueKey}${r.issueUrl ? ` (${r.issueUrl})` : ''}`);
        }
        for (const r of submitResult.results.filter((x) => !x.ok)) {
          console.warn(`  · FAIL ${r.ruleId}: ${r.error ?? r.status}`);
        }
      }
      console.log(`Ticketing submit report: ${submitPath}`);
    }

    if (webhookUrl) {
      const result = await notifyWebhook({
        webhookUrl,
        bundle,
        signingSecret: opts.webhookSecret as string | undefined
      });
      if (result.ok) {
        console.log(
          `Webhook (${result.channel}): notificado OK [${result.status}]` +
            (result.signed ? ' · signed' : '')
        );
      } else {
        console.warn(
          `Webhook (${result.channel}): fallo — ${result.error ?? result.status ?? 'unknown'}`
        );
      }
    }

    // ——— Fase 4: Telemetry (non-blocking) ———
    if (licenseInfo) {
      new UsageTelemetry().reportAsync({
        license: licenseInfo,
        targetUrl,
        pagesScanned: scannedPages.length,
        durationMs: Date.now() - startedAt,
        bundle
      });
    }

    console.log(`\nAuditoría finalizada. Total de hallazgos: ${bundle.findings.length}`);

    if (policyResult.gateFailed) {
      console.log(`[GATE FAIL] Hallazgos con severidad >= ${failOnSeverity}`);
      process.exit(1);
    }

    console.log(`[GATE PASS] Ningún hallazgo supera el umbral ${failOnSeverity}`);
    process.exit(0);
  } catch (error) {
    console.error(`[Critical Error]`, (error as Error).message);
    process.exit(1);
  }
})();
