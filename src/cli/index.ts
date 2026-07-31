#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';

import { AuditRunner } from '../core/audit_runner.js';
import { generateHtmlReport } from '../reporters/htmlReporter.js';
import { AuditExecutionOptions, AuditFinding, OutputFormat, SeverityLevel } from '../types/audit.js';

const program = new Command();

const SEVERITY_WEIGHTS: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

program
  .name('corecheck-audit')
  .description('CoreCheck DevSecOps Engine - Motor de auditoría de seguridad y accesibilidad')
  .requiredOption('-u, --url <string>', 'URL objetivo a auditar')
  .option('-a, --auth-state <path>', 'Ruta al archivo storageState.json de Playwright')
  .option('-f, --formats <items>', 'Formatos de reporte separados por coma (json,html,sarif)', 'json,html')
  .option('-o, --output-dir <path>', 'Directorio de salida de reportes', './audit-results')
  .option('--fail-on <severity>', 'Severidad mínima para retornar exit code 1 (CRITICAL, HIGH, MEDIUM, LOW)', 'HIGH')
  .option('-c, --concurrency <number>', 'Número de ejecuciones concurrentes', '2')
  .option('-t, --timeout <number>', 'Timeout global en ms por página', '30000')
  .option('--fuzzing', 'Habilitar fuzzing activo', false);

program.parse(process.argv);

void (async () => {
  const opts = program.opts();
  const targetUrl: string = opts.url;
  const outputFormats: OutputFormat[] = opts.formats.split(',').map((f: string) => f.trim().toLowerCase() as OutputFormat);
  const failOnSeverity = (opts.failOn.toUpperCase() as SeverityLevel) || 'HIGH';
  const outputDir: string = opts.outputDir;

  console.log(`🚀 [CoreCheck DevSecOps Engine] Iniciando auditoría activa...`);
  console.log(`🔍 Target URL: ${targetUrl}`);

  const auditOptions: AuditExecutionOptions = {
    targetUrl,
    storageStatePath: opts.authState,
    concurrency: parseInt(opts.concurrency, 10),
    timeoutMs: parseInt(opts.timeout, 10),
    outputFormats,
    activeFuzzing: Boolean(opts.fuzzing),
  };

  try {
    const runner = new AuditRunner(auditOptions);
    const findings: AuditFinding[] = await runner.run();

    // Asegurar directorio de reportes
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Generación de Reportes
    if (outputFormats.includes('json')) {
      fs.writeFileSync(path.join(outputDir, 'findings.json'), JSON.stringify(findings, null, 2));
      console.log(`📄 Reporte JSON generado en: ${path.join(outputDir, 'findings.json')}`);
    }

    if (outputFormats.includes('html')) {
      generateHtmlReport(findings, path.join(outputDir, 'report.html'));
      console.log(`📊 Reporte HTML generado en: ${path.join(outputDir, 'report.html')}`);
    }

    // Evaluación del Gate de CI
    const minFailWeight = SEVERITY_WEIGHTS[failOnSeverity] ?? 3;
    const hasFailingFindings = findings.some(f => (SEVERITY_WEIGHTS[f.severity] ?? 0) >= minFailWeight);

    console.log(`\n✅ Auditoría finalizada. Total de hallazgos: ${findings.length}`);

    if (hasFailingFindings) {
      console.error(`❌ [GATE FAIL] Se encontraron hallazgos con severidad >= ${failOnSeverity}`);
      process.exit(1);
    } else {
      console.log(`✓ [GATE PASS] Ningún hallazgo supera el umbral de severidad ${failOnSeverity}`);
      process.exit(0);
    }
  } catch (error) {
    console.error(`❌ [Critical Error] Colapso durante la auditoría:`, (error as Error).message);
    process.exit(1);
  }
})();