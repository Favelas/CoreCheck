import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  resolveArtifactLayout,
  resolveOutputFormats
} from '../src/cli/cli_contract.ts';

describe('cli_contract.resolveOutputFormats', () => {
  it('uses default CSV when no toggles are set', () => {
    const formats = resolveOutputFormats({
      formatsCsv: 'json,html,sarif',
      formatsSource: 'default',
      toggles: {}
    });
    assert.deepEqual(formats, ['json', 'html', 'sarif']);
  });

  it('lets boolean toggles own the set when --formats is default', () => {
    const formats = resolveOutputFormats({
      formatsCsv: 'json,html,sarif',
      formatsSource: 'default',
      toggles: { html: true, pdf: true, json: true, sarif: true }
    });
    assert.deepEqual(formats, ['html', 'json', 'sarif', 'pdf']);
  });

  it('unions toggles into an explicit --formats list', () => {
    const formats = resolveOutputFormats({
      formatsCsv: 'json',
      formatsSource: 'cli',
      toggles: { html: true }
    });
    assert.deepEqual(formats, ['json', 'html']);
  });

  it('implies pdf when --output-pdf is provided', () => {
    const formats = resolveOutputFormats({
      formatsCsv: 'json,html,sarif',
      formatsSource: 'default',
      toggles: {},
      outputPdf: 'executive.pdf'
    });
    assert.ok(formats.includes('pdf'));
  });
});

describe('cli_contract.resolveArtifactLayout', () => {
  it('maps --out file path to parent dir + flat layout + preferred html name', () => {
    const layout = resolveArtifactLayout({
      outputDir: './audit-results',
      outputDirSource: 'default',
      out: 'ci-artifacts/ci-report.html',
      outSource: 'cli',
      flatOutput: false,
      flatOutputSource: 'default'
    });

    assert.equal(layout.flatOutput, true);
    assert.equal(layout.htmlFileName, 'ci-report.html');
    assert.equal(path.basename(layout.baseOutputDir), 'ci-artifacts');
  });

  it('rejects conflicting --out file with flat-output disabled from CLI', () => {
    assert.throws(
      () =>
        resolveArtifactLayout({
          outputDir: './audit-results',
          outputDirSource: 'default',
          out: 'reports/report.html',
          outSource: 'cli',
          flatOutput: false,
          flatOutputSource: 'cli'
        }),
      /Conflicto de contrato CLI/
    );
  });
});
