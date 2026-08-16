'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  buildTrends,
  diffReports,
  filterReports,
  resolveDiffPair
} = require('../src/services/reportAnalytics');

function report(partial) {
  return {
    id: partial.id,
    createdAt: partial.createdAt,
    accountId: 'tenant_default',
    contentHash: 'abc',
    integrityAlgorithm: 'SHA-256',
    url: partial.url ?? 'https://example.com/',
    failOn: partial.failOn ?? 'HIGH',
    findingsCount: partial.findings?.length ?? 0,
    findings: partial.findings ?? [],
    digitalQualityScore: partial.digitalQualityScore ?? 80,
    gateFailed: partial.gateFailed ?? false,
    summary: partial.summary ?? 'ok',
    ...partial
  };
}

describe('reportAnalytics (Slice 3)', () => {
  const r1 = report({
    id: 'older',
    createdAt: '2026-08-01T10:00:00.000Z',
    digitalQualityScore: 70,
    gateFailed: true,
    findings: [
      {
        id: 'a',
        ruleId: 'SEC-A',
        title: 'A',
        severity: 'HIGH',
        description: 'd'
      }
    ]
  });
  const r2 = report({
    id: 'newer',
    createdAt: '2026-08-02T10:00:00.000Z',
    digitalQualityScore: 85,
    gateFailed: false,
    findings: [
      {
        id: 'a',
        ruleId: 'SEC-A',
        title: 'A',
        severity: 'HIGH',
        description: 'd'
      },
      {
        id: 'b',
        ruleId: 'SEO-B',
        title: 'B',
        severity: 'MEDIUM',
        description: 'd'
      }
    ]
  });

  it('filterReports por url y gateFailed', () => {
    const other = report({
      id: 'x',
      createdAt: '2026-08-03T00:00:00.000Z',
      url: 'https://other.test/',
      gateFailed: false
    });
    const filtered = filterReports([r1, r2, other], {
      url: 'example.com',
      gateFailed: true
    });
    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].id, 'older');
  });

  it('buildTrends calcula delta y fail rate', () => {
    const trends = buildTrends([r1, r2], { url: 'example.com' });
    assert.equal(trends.totalRuns, 2);
    assert.equal(trends.latest.id, 'newer');
    assert.equal(trends.previous.id, 'older');
    assert.equal(trends.scoreDelta, 15);
    assert.equal(trends.gateFailRate, 0.5);
  });

  it('diffReports detecta added/removed y regression', () => {
    const d = diffReports(r1, r2);
    assert.equal(d.added.length, 1);
    assert.equal(d.added[0].ruleId, 'SEO-B');
    assert.equal(d.removed.length, 0);
    assert.equal(d.unchangedCount, 1);
    assert.equal(d.scoreDelta, 15);
    assert.equal(d.regression, false);

    const worse = diffReports(r2, r1);
    assert.equal(worse.removed.length, 1);
    assert.equal(worse.added.length, 0);
    assert.equal(worse.regression, true);
  });

  it('resolveDiffPair usa últimos 2 por url', () => {
    const pair = resolveDiffPair([r1, r2], { url: 'example.com' });
    assert.ok(!('error' in pair));
    assert.equal(pair.base.id, 'older');
    assert.equal(pair.target.id, 'newer');
  });
});
