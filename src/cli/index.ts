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
import { isUploadEnabled } from '../http/control_plane_http.js';
import { maybeUploadAuditReport } from '../services/upload_report.js';
import { generateHtmlReport } from '../reporters/htmlReporter.js';
import { generateMarkdownReport } from '../reporters/markdownReporter.js';
import { buildAttestation, generatePdfReport } from '../reporters/pdf_reporter.js';
import {
  AuditEnvironment,
  AuditExecutionOptions,
  AuditReportBundle,
  CvssVersion,
  SeverityLevel,
  TicketProvider
} from '../types/audit.js';
import { LicenseModule } from '../types/license.js';
import { exportToSarif } from '../utils/sarif_exporter.js';
import { getPackageVersion } from '../utils/package_version.js';
import {
  DEFAULT_FORMATS_CSV,
  resolveArtifactLayout,
  resolveOutputFormats
} from './cli_contract.js';
import {
  classifyError,
  CoreCheckError,
  ExitCode,
  exitCodeLabel
} from './exit_codes.js';
import { registerVerifyCommand } from './verify_command.js';

const VALID_SEVERITIES = new Set<SeverityLevel>([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
]);

const VALID_ENVS = new Set<AuditEnvironment>(['prod', 'staging', 'dev']);
const VALID_TICKETS = new Set<TicketProvider>(['jira', 'azure_boards', 'gitlab']);
const VALID_CVSS = new Set<CvssVersion>(['3.1', '4.0']);

function parseFailOn(raw: string): SeverityLevel {
  const severity = raw.trim().toUpperCase() as SeverityLevel;
  if (!VALID_SEVERITIES.has(severity)) {
    throw new CoreCheckError(
      `Severidad inválida en --fail-on: "${raw}". Válidas: ${[...VALID_SEVERITIES].join(', ')}.`,
      'CONFIG'
    );
  }
  return severity;
}

function parseEnvironment(raw: string): AuditEnvironment {
  const env = raw.trim().toLowerCase() as AuditEnvironment;
  if (!VALID_ENVS.has(env)) {
    throw new CoreCheckError(
      `Entorno inválido en --environment: "${raw}". Válidos: prod, staging, dev.`,
      'CONFIG'
    );
  }
  return env;
}

function parseCvssVersion(raw: string): CvssVersion {
  const version = raw.trim() as CvssVersion;
  if (!VALID_CVSS.has(version)) {
    throw new CoreCheckError(
      `Versión CVSS inválida en --cvss-version: "${raw}". Válidas: 3.1, 4.0.`,
      'CONFIG'
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
      throw new CoreCheckError(
        `Header inválido en --auth-header: "${raw}". Use el formato "Name: Value".`,
        'CONFIG'
      );
    }
    const name = raw.slice(0, sep).trim();
    const value = raw.slice(sep + 1).trim();
    if (!name || !value) {
      throw new CoreCheckError(
        `Header inválido en --auth-header: "${raw}". Name y Value son requeridos.`,
        'CONFIG'
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
    throw new CoreCheckError(
      `URL inválida en --url: "${raw}". Debe ser una URL http(s) absoluta.`,
      'CONFIG'
    );
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
    throw new CoreCheckError(
      `URL inválida en --webhook-url: "${raw}". Debe ser una URL http(s) absoluta.`,
      'CONFIG'
    );
  }
}

function parsePositiveInt(raw: string, flagName: string): number {
  const value = parseInt(raw, 10);
  if (Number.isNaN(value) || value < 0) {
    throw new CoreCheckError(`${flagName} debe ser un entero >= 0.`, 'CONFIG');
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

function registerRunOptions(command: Command): Command {
  return command
    .requiredOption('-u, --url <string>', 'URL objetivo a auditar')
    .option('-a, --auth-state <path>', 'Ruta al archivo storageState.json de Playwright')
    .option(
      '-f, --formats <items>',
      'Formatos canónicos CSV: json,html,sarif,markdown,pdf',
      DEFAULT_FORMATS_CSV
    )
    .option(
      '-o, --output-dir <path>',
      'Directorio base de reportes (subcarpeta dominio_timestamp salvo --flat-output)',
      './audit-results'
    )
    .option(
      '--out <path>',
      'Salida CI: directorio de artefactos, o ruta de archivo (implica flat + basename preferido)'
    )
    .option(
      '--flat-output',
      'Escribir reportes directo en el directorio de salida sin subcarpeta fechada',
      false
    )
    .option('--html', 'Emitir report.html (contrato de formato; ver cli_contract)', false)
    .option('--json', 'Emitir findings.json', false)
    .option('--sarif', 'Emitir results.sarif', false)
    .option('--markdown', 'Emitir report.md', false)
    .option('--pdf', 'Emitir PDF ejecutivo', false)
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
    .option('--cvss-version <version>', 'Versión CVSS para calibración: 3.1 | 4.0', '3.1')
    .option(
      '--output-pdf <path>',
      'Nombre o ruta del PDF (siempre se materializa dentro del directorio de salida)'
    )
    .option('--webhook-url <url>', 'Webhook Slack/Teams/genérico para alertas CI/CD')
    .option('--environment <env>', 'Entorno de política: prod | staging | dev', 'prod')
    .option(
      '--baseline <path>',
      'Ruta a .corecheckignore o baseline JSON de hallazgos aceptados'
    )
    .option('--tickets <provider>', 'Exportar / enviar tickets: jira | azure_boards | gitlab')
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
      '--upload',
      'Publicar el reporte en corecheck-api POST /api/reports (env CORECHECK_UPLOAD=true)',
      false
    )
    .option(
      '--upload-url <url>',
      'Base URL del Control Plane de reportes (env CORECHECK_REPORTS_API_URL / CORECHECK_API_URL)'
    )
    .option(
      '--upload-strict',
      'Si el upload falla, abortar con exit NETWORK (default: soft-fail + warn)',
      false
    )
    .option(
      '--skip-license',
      'Omitir validación de licencia (solo desarrollo local; no usar en CI prod)',
      false
    );
}

const program = new Command()
  .name('corecheck')
  .description(
    'CoreCheck v1.0 — Unified Digital Quality & Security Gate (DAST, A11y, Perf, Privacy, SEO/GEO, AI readiness)'
  )
  .version(getPackageVersion());

registerVerifyCommand(program);

const runCommand = registerRunOptions(
  program
    .command('run', { isDefault: true })
    .description(
      'Ejecuta una auditoría Quality Gate contra una URL (entrypoint canónico CI/CD)'
    )
);

runCommand.action(async (opts: Record<string, unknown>, command: Command) => {
  const startedAt = Date.now();
  try {
    const targetUrl = assertValidUrl(String(opts.url));
    const outputFormats = resolveOutputFormats({
      formatsCsv: String(opts.formats ?? DEFAULT_FORMATS_CSV),
      formatsSource: command.getOptionValueSource('formats'),
      toggles: {
        html: Boolean(opts.html),
        json: Boolean(opts.json),
        sarif: Boolean(opts.sarif),
        markdown: Boolean(opts.markdown),
        pdf: Boolean(opts.pdf)
      },
      outputPdf: opts.outputPdf ? String(opts.outputPdf) : undefined
    });

    const cliFailOn = parseFailOn(String(opts.failOn));
    const environment = parseEnvironment(opts.environment as string);
    const maxDepth = parsePositiveInt(String(opts.maxDepth), '--max-depth');
    let maxPages = parsePositiveInt(String(opts.maxPages), '--max-pages');
    if (maxPages < 1) {
      throw new CoreCheckError('--max-pages debe ser >= 1.', 'CONFIG');
    }

    const webhookUrl = opts.webhookUrl
      ? assertWebhookUrl(opts.webhookUrl as string)
      : undefined;

    const ticketProvider = opts.tickets
      ? (String(opts.tickets).toLowerCase() as TicketProvider)
      : undefined;
    if (ticketProvider && !VALID_TICKETS.has(ticketProvider)) {
      throw new CoreCheckError(
        `--tickets inválido: "${opts.tickets}". Válidos: jira, azure_boards, gitlab.`,
        'CONFIG'
      );
    }

    const wantsPdf =
      outputFormats.includes('pdf') || Boolean(opts.pdf) || Boolean(opts.outputPdf);
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
        throw new CoreCheckError(
          'API Key requerida. Use --api-key <key> o la variable de entorno CORECHECK_API_KEY. ' +
            'Para desarrollo local: --api-key cc_dev_growth o --skip-license.',
          'LICENSE'
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
          process.exit(ExitCode.CONFIG);
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
          process.exit(ExitCode.CONFIG);
        }
        if (
          ticketProvider &&
          !licenseInfo.entitlements.allowedModules.includes('ticketing')
        ) {
          console.error(
            `[License] MODULE_NOT_ALLOWED: ticketing requiere Enterprise Governance (plan actual: ${licenseInfo.tier}).`
          );
          process.exit(ExitCode.CONFIG);
        }
      }
    } else {
      console.warn('[License] --skip-license activo: validación comercial omitida.');
    }

    const artifactLayout = resolveArtifactLayout({
      outputDir: String(opts.outputDir),
      outputDirSource: command.getOptionValueSource('outputDir'),
      out: opts.out !== undefined ? String(opts.out) : undefined,
      outSource: command.getOptionValueSource('out'),
      flatOutput: Boolean(opts.flatOutput),
      flatOutputSource: command.getOptionValueSource('flatOutput'),
      outputPdf: opts.outputPdf ? String(opts.outputPdf) : undefined
    });

    const outputDir = artifactLayout.flatOutput
      ? artifactLayout.baseOutputDir
      : buildDatedOutputDir(artifactLayout.baseOutputDir, targetUrl);

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
      ? assertValidUrl(opts.authLoginUrl as string)
      : undefined;
    if ((opts.authUser || opts.authPass) && !authLoginUrl) {
      throw new CoreCheckError(
        'Si usa --auth-user/--auth-pass debe indicar también --auth-login-url.',
        'CONFIG'
      );
    }

    const customHeaders = parseAuthHeaders(opts.authHeader as string[] | undefined);
    const hasCustomHeaders = Object.keys(customHeaders).length > 0;
    const cvssVersion = parseCvssVersion(String(opts.cvssVersion ?? '3.1'));
    const concurrencyRaw = parsePositiveInt(String(opts.concurrency), '--concurrency');
    if (concurrencyRaw < 1) {
      throw new CoreCheckError('--concurrency debe ser >= 1.', 'CONFIG');
    }

    const timeoutMs = parsePositiveInt(String(opts.timeout), '--timeout');
    if (timeoutMs < 1) {
      throw new CoreCheckError('--timeout debe ser >= 1.', 'CONFIG');
    }

    // El AuditRunner aplica ResourceBudget (cap CI/memoria); aquí solo validamos el pedido.
    const concurrency = concurrencyRaw;

    const auditOptions: AuditExecutionOptions = {
      targetUrl,
      storageStatePath: opts.authState as string | undefined,
      concurrency,
      timeoutMs,
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
            activeFuzzing: Boolean(opts.fuzzing),
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
      const htmlPath = path.join(outputDir, artifactLayout.htmlFileName);
      generateHtmlReport(bundle, htmlPath);
      console.log(`Reporte HTML: ${htmlPath}`);
    }

    if (outputFormats.includes('markdown')) {
      const mdPath = path.join(outputDir, 'report.md');
      generateMarkdownReport(bundle, mdPath);
      console.log(`Reporte Markdown: ${mdPath}`);
    }

    if (wantsPdf) {
      const pdfPath = path.join(outputDir, artifactLayout.pdfFileName);
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

    // ——— Slice 1: Upload reporte al Control Plane (corecheck-api) ———
    const uploadEnabled = isUploadEnabled(Boolean(opts.upload));
    if (uploadEnabled) {
      try {
        const uploadResult = await maybeUploadAuditReport({
          enabled: true,
          strict: Boolean(opts.uploadStrict),
          apiKey: apiKey,
          baseUrl: opts.uploadUrl ? String(opts.uploadUrl) : undefined,
          bundle
        });
        if (uploadResult.uploaded && uploadResult.reportId) {
          console.log(`[Upload] reportId=${uploadResult.reportId}`);
        }
      } catch (uploadError) {
        // --upload-strict: clasificar como NETWORK y salir.
        throw new CoreCheckError(
          uploadError instanceof Error ? uploadError.message : String(uploadError),
          'NETWORK'
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
      console.log(
        `[GATE FAIL] Hallazgos con severidad >= ${failOnSeverity} · exit=${ExitCode.GATE_FAIL} (${exitCodeLabel(ExitCode.GATE_FAIL)})`
      );
      process.exit(ExitCode.GATE_FAIL);
    }

    console.log(
      `[GATE PASS] Ningún hallazgo supera el umbral ${failOnSeverity} · exit=${ExitCode.PASS} (${exitCodeLabel(ExitCode.PASS)})`
    );
    process.exit(ExitCode.PASS);
  } catch (error) {
    const code = classifyError(error);
    const message = error instanceof Error ? error.message : String(error);
    console.error(
      `[Critical Error] exit=${code} (${exitCodeLabel(code)}) · ${message}`
    );
    process.exit(code);
  }
});

void program.parseAsync(process.argv);
