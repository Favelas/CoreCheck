'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  canonicalize,
  computeContentHash,
  sealReportIntegrity,
  verifyReportIntegrity
} = require('../src/security/reportIntegrity');

describe('reportIntegrity (Phase 2 unit)', () => {
  it('canonicalize ordena claves de forma estable', () => {
    const a = canonicalize({ b: 1, a: 2 });
    const b = canonicalize({ a: 2, b: 1 });
    assert.equal(a, b);
  });

  it('seal + verify SHA-256 en verde', () => {
    const sealed = sealReportIntegrity({
      url: 'https://example.com',
      id: '11111111-1111-4111-8111-111111111111',
      createdAt: '2026-01-01T00:00:00.000Z',
      accountId: 'tenant_default'
    });

    assert.equal(sealed.integrityAlgorithm, 'SHA-256');
    assert.equal(typeof sealed.contentHash, 'string');
    assert.equal(sealed.contentHash.length, 64);
    assert.equal(sealed.hmacSignature, undefined);

    const verdict = verifyReportIntegrity(sealed);
    assert.equal(verdict.valid, true);
    assert.equal(verdict.hashMatches, true);
  });

  it('detecta tampering del summary', () => {
    const sealed = sealReportIntegrity({
      url: 'https://example.com',
      summary: 'clean',
      id: '11111111-1111-4111-8111-111111111111',
      createdAt: '2026-01-01T00:00:00.000Z',
      accountId: 'tenant_default'
    });

    const tampered = { ...sealed, summary: 'evil' };
    const verdict = verifyReportIntegrity(tampered);
    assert.equal(verdict.valid, false);
    assert.equal(verdict.hashMatches, false);
  });

  it('HMAC-SHA256 verifica con secret', () => {
    const sealed = sealReportIntegrity(
      {
        url: 'https://example.com',
        id: '11111111-1111-4111-8111-111111111111',
        createdAt: '2026-01-01T00:00:00.000Z',
        accountId: 'tenant_default'
      },
      'test-hmac-secret'
    );

    assert.equal(sealed.integrityAlgorithm, 'HMAC-SHA256');
    assert.ok(sealed.hmacSignature);

    assert.equal(
      verifyReportIntegrity(sealed, 'test-hmac-secret').valid,
      true
    );
    assert.equal(verifyReportIntegrity(sealed, 'wrong-secret').valid, false);
  });

  it('computeContentHash es determinista', () => {
    const payload = { version: 1, url: 'https://example.com', accountId: 't' };
    assert.equal(computeContentHash(payload), computeContentHash(payload));
  });
});
