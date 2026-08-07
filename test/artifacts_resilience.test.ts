import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { generateHtmlReport } from '../src/reporters/htmlReporter.ts';
import { generateMarkdownReport } from '../src/reporters/markdownReporter.ts';
import {
  buildAttestation,
  generatePdfReport
} from '../src/reporters/pdf_reporter.ts';
import { sanitizeAndBudgetEvidence } from '../src/utils/evidence.ts';
import { exportToSarif } from '../src/utils/sarif_exporter.ts';
import { getPackageVersion } from '../src/utils/package_version.ts';
import { sampleBundle, sampleFinding } from './helpers/fixtures.ts';

describe('artifact resilience', () => {
  it('writes non-empty HTML, Markdown, JSON, SARIF and PDF', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-art-'));
    const bundle = sampleBundle({
      findings: [
        sampleFinding({ ruleId: 'SEC-HDR-CSP', severity: 'HIGH' }),
        sampleFinding({ ruleId: 'A11Y-CONTRAST', severity: 'MEDIUM' })
      ],
      gateFailed: true,
      failOn: 'HIGH'
    });
    bundle.attestation = buildAttestation(bundle, {
      activeFuzzing: false,
      localDashboardPath: path.join(dir, 'interactive-dashboard.html'),
      cliVersion: getPackageVersion()
    });

    const htmlPath = path.join(dir, 'report.html');
    const mdPath = path.join(dir, 'report.md');
    const jsonPath = path.join(dir, 'findings.json');
    const sarifPath = path.join(dir, 'results.sarif');
    const pdfPath = path.join(dir, 'executive-report.pdf');
    const dashPath = path.join(dir, 'interactive-dashboard.html');

    generateHtmlReport(bundle, htmlPath);
    generateHtmlReport(bundle, dashPath);
    generateMarkdownReport(bundle, mdPath);
    await exportToSarif(bundle.findings, sarifPath, bundle);
    await generatePdfReport(bundle, pdfPath);

    const jsonBody = {
      target: bundle.target,
      timestamp: bundle.timestamp,
      environment: bundle.environment,
      activeFuzzing: false,
      attestation: bundle.attestation,
      scannedPages: bundle.scannedPages,
      digitalQualityScore: bundle.digitalQualityScore,
      maxCvssScore: bundle.maxCvssScore,
      severityCounts: bundle.severityCounts,
      gateFailed: bundle.gateFailed,
      failOn: bundle.failOn,
      findings: bundle.findings
    };
    await fs.writeFile(jsonPath, JSON.stringify(jsonBody, null, 2), 'utf8');

    for (const file of [htmlPath, mdPath, jsonPath, sarifPath, pdfPath, dashPath]) {
      const stat = await fs.stat(file);
      assert.ok(stat.size > 64, `${path.basename(file)} too small (${stat.size})`);
    }

    const html = await fs.readFile(htmlPath, 'utf8');
    assert.match(html, /<!DOCTYPE html>/i);
    assert.match(html, /SEC-HDR-CSP/);

    const md = await fs.readFile(mdPath, 'utf8');
    assert.match(md, /SEC-HDR-CSP/);

    const json = JSON.parse(await fs.readFile(jsonPath, 'utf8')) as {
      findings: unknown[];
      attestation: { attestationHash: string };
    };
    assert.ok(Array.isArray(json.findings));
    assert.ok(json.attestation.attestationHash.length >= 32);

    const sarif = JSON.parse(await fs.readFile(sarifPath, 'utf8')) as {
      version: string;
      runs: Array<{ tool: { driver: { version: string } }; results: unknown[] }>;
    };
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].tool.driver.version, getPackageVersion());
    assert.ok(sarif.runs[0].results.length >= 1);

    const pdf = await fs.readFile(pdfPath);
    assert.equal(pdf.subarray(0, 4).toString('utf8'), '%PDF');

    await fs.rm(dir, { recursive: true, force: true });
  });

  it('empty findings still produce valid non-corrupt reports', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-empty-'));
    const bundle = sampleBundle({ findings: [], gateFailed: false });
    bundle.attestation = buildAttestation(bundle, {
      activeFuzzing: false,
      cliVersion: '1.0.0'
    });

    const htmlPath = path.join(dir, 'report.html');
    const mdPath = path.join(dir, 'report.md');
    const sarifPath = path.join(dir, 'results.sarif');

    generateHtmlReport(bundle, htmlPath);
    generateMarkdownReport(bundle, mdPath);
    await exportToSarif([], sarifPath, bundle);

    const md = await fs.readFile(mdPath, 'utf8');
    assert.match(md, /No se detectaron hallazgos|0|sin hallazgos/i);

    const sarif = JSON.parse(await fs.readFile(sarifPath, 'utf8')) as {
      runs: Array<{ results: unknown[] }>;
    };
    assert.deepEqual(sarif.runs[0].results, []);

    const htmlStat = await fs.stat(htmlPath);
    assert.ok(htmlStat.size > 64);

    await fs.rm(dir, { recursive: true, force: true });
  });

  it('enforces 2KB evidence budget and spills oversized DOM to disk', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-ev-'));
    const big = 'x'.repeat(4096);
    const budgeted = sanitizeAndBudgetEvidence('FIND-1', big, dir);
    assert.ok(budgeted.snippet);
    assert.ok(Buffer.byteLength(budgeted.snippet, 'utf8') <= 2048);
    assert.ok(budgeted.artifactPath);
    const spilled = await fs.readFile(budgeted.artifactPath, 'utf8');
    assert.equal(spilled.length, 4096);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
