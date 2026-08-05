#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';

import { AuditRunner } from '../core/audit_runner.js';
import { ComplianceMapper } from '../core/compliance_mapper.js';
import { CvssScorer } from '../core/cvss_scorer.js';
import { PolicyEngine } from '../core/policy_engine.js';
import {
  buildTicketPayloads,
  notifyWebhook
} from '../integrations/index.js';
import { generateHtmlReport } from '../reporters/htmlReporter.js';
import { generateMarkdownReport } from '../reporters/markdownReporter.js';
import { generatePdfReport } from '../reporters/pdf_reporter.js';
import {
  AuditEnvironment,
  AuditExecutionOptions,
  AuditReportBundle,
  OutputFormat,
  SeverityLevel,
  TicketProvider
} from '../types/audit.js';
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
  .option('--pdf', 'Generar PDF ejecutivo (equivalente a incluir pdf en --formats)', false)
  .option('--output-pdf <path>', 'Ruta de salida del PDF ejecutivo')
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
    'Exportar payloads de ticketing: jira | azure_boards | gitlab'
  )
  .option('--ticket-project <key>', 'Project key / area / GitLab project id para tickets');

program.parse(process.argv);

void (async () => {
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
    const maxPages = parsePositiveInt(opts.maxPages, '--max-pages');
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

    const auditOptions: AuditExecutionOptions = {
      targetUrl,
      storageStatePath: opts.authState,
      concurrency: parseInt(opts.concurrency, 10),
      timeoutMs: parseInt(opts.timeout, 10),
      outputFormats,
      outputDir,
      activeFuzzing: Boolean(opts.fuzzing),
      maxDepth,
      maxPages,
      sameOriginOnly: true,
      environment,
      baselinePath: opts.baseline as string | undefined,
      ...(authLoginUrl
        ? {
            authConfig: {
              loginUrl: authLoginUrl,
              username: opts.authUser as string | undefined,
              password: opts.authPass as string | undefined
            }
          }
        : {})
    };

    const runner = new AuditRunner(auditOptions);
    const { findings, scannedPages } = await runner.run();

    console.log(`\nScanned pages (${scannedPages.length}):`);
    scannedPages.forEach((url) => console.log(`  - ${url}`));

    // 1) CVSS calibration
    const cvssScorer = new CvssScorer('3.1');
    const cvssFindings = cvssScorer.enrichFindings(findings);
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

    console.log(
      `Digital Quality Score: ${bundle.digitalQualityScore}/100 · Compliance-mapped: ${bundle.compliance.mappedFindingCount}`
    );

    if (outputFormats.includes('json')) {
      const jsonPath = path.join(outputDir, 'findings.json');
      fs.writeFileSync(
        jsonPath,
        JSON.stringify(
          {
            target: bundle.target,
            timestamp: bundle.timestamp,
            environment: bundle.environment,
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
      generateHtmlReport(bundle.findings, htmlPath);
      console.log(`Reporte HTML: ${htmlPath}`);
    }

    if (outputFormats.includes('markdown')) {
      const mdPath = path.join(outputDir, 'report.md');
      generateMarkdownReport(bundle.findings, mdPath);
      console.log(`Reporte Markdown: ${mdPath}`);
    }

    if (outputFormats.includes('pdf') || opts.pdf || opts.outputPdf) {
      const pdfPath = opts.outputPdf
        ? path.resolve(opts.outputPdf as string)
        : path.join(outputDir, 'executive-report.pdf');
      await generatePdfReport(bundle, pdfPath);
      console.log(`Reporte PDF: ${pdfPath}`);
    }

    if (ticketProvider) {
      const ticketFindings = bundle.findings.filter(
        (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
      );
      const payloads = buildTicketPayloads(ticketProvider, ticketFindings, {
        projectKey: opts.ticketProject as string | undefined,
        areaPath: opts.ticketProject as string | undefined,
        gitlabProjectId: opts.ticketProject as string | undefined
      });
      const ticketsPath = path.join(outputDir, `tickets-${ticketProvider}.json`);
      fs.writeFileSync(ticketsPath, JSON.stringify(payloads, null, 2), 'utf-8');
      console.log(`Ticketing payloads (${ticketProvider}): ${ticketsPath} (${payloads.length})`);
    }

    if (webhookUrl) {
      const result = await notifyWebhook({ webhookUrl, bundle });
      if (result.ok) {
        console.log(`Webhook (${result.channel}): notificado OK [${result.status}]`);
      } else {
        console.warn(
          `Webhook (${result.channel}): fallo — ${result.error ?? result.status ?? 'unknown'}`
        );
      }
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
