/**
 * Smoke puntual Fase 1 — gate de cierre antes de Fase 2.
 * Valida: taxonomía exit + attestation HMAC round-trip + CLI verify.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  buildAttestation,
  verifyJsonReportAttestation
} from '../src/utils/attestation.ts';
import {
  CoreCheckError,
  ExitCode,
  classifyError
} from '../src/utils/exit_codes.ts';
import type { AuditReportBundle } from '../src/types/audit.ts';

const bundle: AuditReportBundle = {
  target: 'https://example.com/',
  timestamp: '2026-08-06T00:00:00.000Z',
  scannedPages: ['https://example.com/'],
  findings: [],
  digitalQualityScore: 100,
  maxCvssScore: 0,
  severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  dimensions: [],
  compliance: { frameworks: [], mappedFindingCount: 0 },
  gateFailed: false,
  failOn: 'HIGH',
  environment: 'staging'
};

const attestation = buildAttestation(bundle, {
  activeFuzzing: false,
  hmacSecret: 'phase1-secret',
  cliVersion: '1.0.0'
});

const report = {
  ...bundle,
  activeFuzzing: false,
  attestation
};

const ok = verifyJsonReportAttestation(report, { hmacSecret: 'phase1-secret' });
assert.equal(ok.ok, true);
assert.equal(ok.hashMatches, true);
assert.equal(ok.hmacVerified, true);

const tampered = verifyJsonReportAttestation(
  { ...report, digitalQualityScore: 1 },
  { hmacSecret: 'phase1-secret' }
);
assert.equal(tampered.ok, false);
assert.equal(tampered.hashMatches, false);

assert.equal(classifyError(new CoreCheckError('bad', 'CONFIG')), ExitCode.CONFIG);
assert.equal(classifyError(new CoreCheckError('net', 'NETWORK')), ExitCode.NETWORK);
assert.equal(classifyError(new CoreCheckError('oom', 'ENGINE')), ExitCode.ENGINE);
assert.equal(classifyError(new Error('ENOTFOUND host')), ExitCode.NETWORK);
assert.equal(classifyError(new Error('JavaScript heap out of memory')), ExitCode.ENGINE);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cc-phase1-'));
const file = path.join(dir, 'findings.json');
fs.writeFileSync(file, JSON.stringify(report, null, 2), 'utf8');

const cliOk = spawnSync(
  process.execPath,
  ['--import', 'tsx', 'src/cli/index.ts', 'verify', '--report', file, '--key', 'phase1-secret'],
  { cwd: process.cwd(), encoding: 'utf8' }
);
assert.equal(cliOk.status, ExitCode.PASS, cliOk.stderr || cliOk.stdout);

const cliBad = spawnSync(
  process.execPath,
  ['--import', 'tsx', 'src/cli/index.ts', 'verify', '--report', file, '--key', 'wrong-secret'],
  { cwd: process.cwd(), encoding: 'utf8' }
);
assert.equal(cliBad.status, ExitCode.GATE_FAIL, cliBad.stderr || cliBad.stdout);

fs.rmSync(dir, { recursive: true, force: true });
console.log('PHASE1_SMOKE_OK');
