import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  buildAttestation,
  verifyJsonReportAttestation
} from '../src/utils/attestation.ts';
import { ExitCode } from '../src/utils/exit_codes.ts';
import { sampleBundle, sampleFinding } from './helpers/fixtures.ts';

describe('attestation round-trip', () => {
  it('verifies SHA-256 integrity without HMAC secret', () => {
    const bundle = sampleBundle({
      findings: [sampleFinding({ ruleId: 'SEC-HDR-CSP', severity: 'MEDIUM' })]
    });
    const attestation = buildAttestation(bundle, {
      activeFuzzing: false,
      cliVersion: '1.0.0'
    });
    assert.equal(attestation.algorithm, 'SHA-256');
    assert.equal(attestation.hmacSignature, undefined);

    const report = {
      ...bundle,
      activeFuzzing: false,
      attestation
    };
    const result = verifyJsonReportAttestation(report);
    assert.equal(result.ok, true);
    assert.equal(result.hashMatches, true);
    assert.equal(result.hmacVerified, null);
  });

  it('verifies HMAC-SHA256 authenticity with secret', () => {
    const bundle = sampleBundle();
    const secret = 'enterprise-attestation-secret';
    const attestation = buildAttestation(bundle, {
      activeFuzzing: true,
      hmacSecret: secret,
      cliVersion: '1.0.0'
    });
    assert.equal(attestation.algorithm, 'HMAC-SHA256');
    assert.ok(attestation.hmacSignature);

    const report = {
      ...bundle,
      activeFuzzing: true,
      attestation
    };
    const result = verifyJsonReportAttestation(report, { hmacSecret: secret });
    assert.equal(result.ok, true);
    assert.equal(result.hashMatches, true);
    assert.equal(result.hmacVerified, true);
  });

  it('fails integrity when findings payload is tampered', () => {
    const bundle = sampleBundle();
    const attestation = buildAttestation(bundle, {
      activeFuzzing: false,
      hmacSecret: 'k',
      cliVersion: '1.0.0'
    });
    const report = {
      ...bundle,
      activeFuzzing: false,
      digitalQualityScore: bundle.digitalQualityScore + 7,
      attestation
    };
    const result = verifyJsonReportAttestation(report, { hmacSecret: 'k' });
    assert.equal(result.ok, false);
    assert.equal(result.hashMatches, false);
  });

  it('fails authenticity when HMAC secret is wrong', () => {
    const bundle = sampleBundle();
    const attestation = buildAttestation(bundle, {
      activeFuzzing: false,
      hmacSecret: 'correct-secret',
      cliVersion: '1.0.0'
    });
    const report = { ...bundle, activeFuzzing: false, attestation };
    const result = verifyJsonReportAttestation(report, {
      hmacSecret: 'wrong-secret'
    });
    assert.equal(result.ok, false);
    assert.equal(result.hashMatches, true);
    assert.equal(result.hmacVerified, false);
  });

  it('CLI verify exits 0 on valid report and 1 on bad HMAC', () => {
    const bundle = sampleBundle();
    const attestation = buildAttestation(bundle, {
      activeFuzzing: false,
      hmacSecret: 'cli-secret',
      cliVersion: '1.0.0'
    });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cc-att-'));
    const file = path.join(dir, 'findings.json');
    fs.writeFileSync(
      file,
      JSON.stringify({ ...bundle, activeFuzzing: false, attestation }, null, 2)
    );

    const ok = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'src/cli/index.ts',
        'verify',
        '--report',
        file,
        '--key',
        'cli-secret'
      ],
      { cwd: process.cwd(), encoding: 'utf8' }
    );
    assert.equal(ok.status, ExitCode.PASS, ok.stderr || ok.stdout);

    const bad = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'src/cli/index.ts',
        'verify',
        '--report',
        file,
        '--key',
        'nope'
      ],
      { cwd: process.cwd(), encoding: 'utf8' }
    );
    assert.equal(bad.status, ExitCode.GATE_FAIL, bad.stderr || bad.stdout);

    fs.rmSync(dir, { recursive: true, force: true });
  });
});
