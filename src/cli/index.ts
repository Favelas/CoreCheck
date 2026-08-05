#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';

import { AuditRunner } from '../core/audit_runner.js';
import { generateHtmlReport } from '../reporters/htmlReporter.js';
import { generateMarkdownReport } from '../reporters/markdownReporter.js';
import {
  AuditExecutionOptions,
  OutputFormat,
  SeverityLevel
} from '../types/audit.js';
import { exportToSarif } from '../utils/sarif_exporter.js';

const program = new Command();

const SEVERITY_WEIGHTS: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

const VALID_SEVERITIES = new Set<SeverityLevel>([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
]);

const VALID_FORMATS = new Set<OutputFormat>(['json', 'sarif', 'html', 'markdown']);

function parseFormats(raw: string): OutputFormat[] {
  const formats = raw
    .split(',')
    .map((f) => f.trim().toLowerCase())
    .filter(Boolean) as OutputFormat[];

  if (formats.length === 0) {
    throw new Error('Debe indicar al menos un formato en --formats (json,sarif,html,markdown).');
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

function parsePositiveInt(raw: string, flagName: string): number {
  const value = parseInt(raw, 10);
  if (Number.isNaN(value) || value < 0) {
    throw new Error(`${flagName} debe ser un entero >= 0.`);
  }
  return value;
}

/** Crea `./audit-results/{dominio}_{YYYY-MM-DD_HH-mm-ss}` para no pisar corridas previas. */
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
    'Formatos de reporte separados por coma (json,html,sarif,markdown)',
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
    'Severidad mínima para retornar exit code 1 (CRITICAL, HIGH, MEDIUM, LOW, INFO)',
    'HIGH'
  )
  .option('-c, --concurrency <number>', 'Número de ejecuciones concurrentes', '2')
  .option('-t, --timeout <number>', 'Timeout global en ms por página', '30000')
  .option('--max-depth <number>', 'Profundidad máxima del crawler BFS', '2')
  .option('--max-pages <number>', 'Máximo de páginas a descubrir/auditar', '10')
  .option('--fuzzing', 'Habilitar fuzzing activo', false);

program.parse(process.argv);

void (async () => {
  try {
    const opts = program.opts();
    const targetUrl = assertValidUrl(opts.url);
    const outputFormats = parseFormats(opts.formats);
    const failOnSeverity = parseFailOn(opts.failOn);
    const maxDepth = parsePositiveInt(opts.maxDepth, '--max-depth');
    const maxPages = parsePositiveInt(opts.maxPages, '--max-pages');
    if (maxPages < 1) {
      throw new Error('--max-pages debe ser >= 1.');
    }

    const baseOutputDir = path.resolve(opts.outputDir);
    const outputDir = opts.flatOutput
      ? baseOutputDir
      : buildDatedOutputDir(baseOutputDir, targetUrl);

    console.log(`[CoreCheck DevSecOps Engine] Iniciando auditoría activa...`);
    console.log(`Target URL: ${targetUrl}`);
    console.log(`Output dir: ${outputDir}`);
    console.log(`Formats: ${outputFormats.join(', ')}`);
    console.log(`Fail-on: ${failOnSeverity}`);
    console.log(`Crawler: maxDepth=${maxDepth}, maxPages=${maxPages}`);

    fs.mkdirSync(outputDir, { recursive: true });

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
      sameOriginOnly: true
    };

    const runner = new AuditRunner(auditOptions);
    const { findings, scannedPages } = await runner.run();

    console.log(`\nScanned pages (${scannedPages.length}):`);
    scannedPages.forEach((url) => console.log(`  - ${url}`));

    if (outputFormats.includes('json')) {
      const jsonPath = path.join(outputDir, 'findings.json');
      fs.writeFileSync(
        jsonPath,
        JSON.stringify(
          {
            target: targetUrl,
            timestamp: new Date().toISOString(),
            scannedPages,
            findings
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
      await exportToSarif(findings, sarifPath);
      console.log(`Reporte SARIF: ${sarifPath}`);
    }

    if (outputFormats.includes('html')) {
      const htmlPath = path.join(outputDir, 'report.html');
      generateHtmlReport(findings, htmlPath);
      console.log(`Reporte HTML: ${htmlPath}`);
    }

    if (outputFormats.includes('markdown')) {
      const mdPath = path.join(outputDir, 'report.md');
      generateMarkdownReport(findings, mdPath);
      console.log(`Reporte Markdown: ${mdPath}`);
    }

    const minFailWeight = SEVERITY_WEIGHTS[failOnSeverity];
    const hasFailingFindings = findings.some(
      (f) => (SEVERITY_WEIGHTS[f.severity] ?? 0) >= minFailWeight
    );

    console.log(`\nAuditoría finalizada. Total de hallazgos: ${findings.length}`);

    if (hasFailingFindings) {
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
