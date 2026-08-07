import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { PolicyEngine } from '../src/core/policy_engine.ts';
import { ExitCode } from '../src/utils/exit_codes.ts';
import { sampleFinding } from './helpers/fixtures.ts';

/** Contrato CLI: gateFailed → exit 1; pass → exit 0. */
function gateExitCode(gateFailed: boolean): number {
  return gateFailed ? ExitCode.GATE_FAIL : ExitCode.PASS;
}

describe('policy fail-on + baseline exit taxonomy', () => {
  it('fail-on HIGH fails gate on HIGH finding → exit 1', () => {
    const policy = new PolicyEngine('staging', []);
    const result = policy.evaluate(
      [
        sampleFinding({ ruleId: 'SEC-HDR-CSP', severity: 'HIGH' }),
        sampleFinding({ ruleId: 'A11Y-COLOR', severity: 'LOW' })
      ],
      'HIGH'
    );
    assert.equal(result.gateFailed, true);
    assert.equal(gateExitCode(result.gateFailed), ExitCode.GATE_FAIL);
  });

  it('fail-on CRITICAL ignores HIGH → exit 0', () => {
    const policy = new PolicyEngine('staging', []);
    const result = policy.evaluate(
      [sampleFinding({ ruleId: 'SEC-HDR-CSP', severity: 'HIGH' })],
      'CRITICAL'
    );
    assert.equal(result.gateFailed, false);
    assert.equal(gateExitCode(result.gateFailed), ExitCode.PASS);
  });

  it('baseline suppression can clear a gate fail', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-base-'));
    const baselinePath = path.join(dir, 'baseline.json');
    await fs.writeFile(
      baselinePath,
      JSON.stringify({
        version: 1,
        accepted: [{ ruleId: 'SEC-HDR-CSP', reason: 'accepted risk' }]
      }),
      'utf8'
    );

    const policy = await PolicyEngine.fromPaths({
      environment: 'prod',
      baselinePath,
      cwd: dir
    });
    const failOn = policy.resolveFailOn('HIGH');
    const result = policy.evaluate(
      [sampleFinding({ ruleId: 'SEC-HDR-CSP', severity: 'HIGH' })],
      failOn
    );

    assert.equal(result.suppressedCount, 1);
    assert.equal(result.activeFindings.length, 0);
    assert.equal(result.gateFailed, false);
    assert.equal(gateExitCode(result.gateFailed), ExitCode.PASS);

    await fs.rm(dir, { recursive: true, force: true });
  });

  it('resolveFailOn prefers CLI over environment default', () => {
    const prod = new PolicyEngine('prod', []);
    assert.equal(prod.resolveFailOn('MEDIUM'), 'MEDIUM');
    assert.equal(prod.resolveFailOn(undefined), 'HIGH');
  });

  it('corrupt baseline JSON surfaces as thrown error (CONFIG path)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-base-bad-'));
    const baselinePath = path.join(dir, 'broken.json');
    await fs.writeFile(baselinePath, '{not-json', 'utf8');

    await assert.rejects(
      () =>
        PolicyEngine.fromPaths({
          environment: 'staging',
          baselinePath,
          cwd: dir
        }),
      /JSON|Unexpected|SyntaxError/i
    );

    await fs.rm(dir, { recursive: true, force: true });
  });
});
