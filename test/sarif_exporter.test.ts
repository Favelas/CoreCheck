import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { AuditFinding } from '../src/types/audit.js';
import { exportToSarif } from '../src/utils/sarif_exporter.ts';

function sampleFinding(severity: AuditFinding['severity'], baseScore?: number): AuditFinding {
  return {
    id: `f-${severity}`,
    ruleId: `RULE-${severity}`,
    title: `${severity} finding`,
    severity,
    description: 'contract test finding',
    evidence: {
      url: 'https://example.com/',
      snippet: '<html></html>'
    },
    remediation: {
      explanation: 'Fix it',
      codeBefore: '',
      codeAfter: ''
    },
    standards: {},
    ...(baseScore !== undefined
      ? {
          cvss: {
            version: '3.1' as const,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            baseScore,
            severity: severity === 'INFO' ? 'LOW' : severity
          }
        }
      : {})
  };
}

describe('sarif_exporter GitHub Code Scanning contract', () => {
  it('emits numeric security-severity on rules and results (not qualitative labels)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'corecheck-sarif-'));
    const out = path.join(dir, 'results.sarif');

    await exportToSarif(
      [
        sampleFinding('MEDIUM'),
        sampleFinding('HIGH', 7.5),
        sampleFinding('CRITICAL')
      ],
      out
    );

    const sarif = JSON.parse(await fs.readFile(out, 'utf8')) as {
      runs: Array<{
        tool: { driver: { rules: Array<{ properties: Record<string, unknown> }> } };
        results: Array<{ properties: Record<string, unknown> }>;
      }>;
    };

    const rules = sarif.runs[0].tool.driver.rules;
    const results = sarif.runs[0].results;

    for (const rule of rules) {
      const score = rule.properties['security-severity'];
      assert.equal(typeof score, 'string');
      assert.match(String(score), /^\d+(\.\d+)?$/);
      const numeric = Number(score);
      assert.ok(numeric >= 0 && numeric <= 10);
      assert.notEqual(String(score).toLowerCase(), 'medium');
      assert.notEqual(String(score).toLowerCase(), 'high');
      assert.notEqual(String(score).toLowerCase(), 'critical');

      const problem = rule.properties.problem as { severity: string };
      assert.ok(['error', 'warning', 'recommendation'].includes(problem.severity));
    }

    const mediumRule = rules.find((r) => r.properties['security-severity'] === '5.0');
    assert.ok(mediumRule, 'MEDIUM without CVSS should map to 5.0');

    const highWithCvss = results.find((r) => r.properties.severityLabel === 'high');
    assert.equal(highWithCvss?.properties['security-severity'], '7.5');

    await fs.rm(dir, { recursive: true, force: true });
  });
});
