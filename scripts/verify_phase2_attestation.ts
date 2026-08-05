/**
 * Fase 2 verification: attestation hash determinism + HMAC.
 * Usage: npx tsx scripts/verify_phase2_attestation.ts
 */
import {
  buildAttestation,
  buildAttestationPayload,
  canonicalize,
  computeAttestationHash,
  computeAttestationHmac,
  verifyAttestationHmac
} from '../src/utils/attestation.js';
import { AuditReportBundle } from '../src/types/audit.js';

const bundle: AuditReportBundle = {
  target: 'https://example.com/',
  timestamp: '2026-08-05T17:00:00.000Z',
  scannedPages: [
    'https://example.com/b',
    'https://example.com/a',
    'https://example.com/'
  ],
  findings: [
    {
      id: 'f2',
      ruleId: 'SEC-HDR-CSP-MISSING',
      title: 'CSP',
      severity: 'HIGH',
      description: 'missing',
      evidence: { url: 'https://example.com/b' },
      remediation: { explanation: 'add csp' },
      standards: {}
    },
    {
      id: 'f1',
      ruleId: 'A11Y-color-contrast',
      title: 'Contrast',
      severity: 'HIGH',
      description: 'contrast',
      evidence: { url: 'https://example.com/a', selector: '.btn' },
      remediation: { explanation: 'fix contrast' },
      standards: { wcag: ['1.4.3'] }
    }
  ],
  digitalQualityScore: 42.5,
  maxCvssScore: 6.1,
  severityCounts: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
  dimensions: [],
  compliance: { frameworks: [], mappedFindingCount: 0 },
  gateFailed: true,
  failOn: 'HIGH',
  environment: 'prod',
  suppressedCount: 0
};

const opts = {
  cliVersion: '1.0.0',
  activeFuzzing: false,
  localDashboardPath: 'C:/tmp/interactive-dashboard.html',
  licenseTier: 'ENTERPRISE_GOVERNANCE' as const
};

const payload1 = buildAttestationPayload(bundle, opts);
const payload2 = buildAttestationPayload(bundle, opts);
const hash1 = computeAttestationHash(payload1);
const hash2 = computeAttestationHash(payload2);

const att1 = buildAttestation(bundle, opts);
const att2 = buildAttestation(bundle, { ...opts });

const secret = 'corecheck-phase2-test-secret';
const hmac1 = computeAttestationHmac(payload1, secret);
const hmac2 = computeAttestationHmac(payload2, secret);
const attHmac = buildAttestation(bundle, { ...opts, hmacSecret: secret });

const mutated = buildAttestationPayload(bundle, { ...opts, activeFuzzing: true });
const hashMutated = computeAttestationHash(mutated);

const checks: Array<{ name: string; ok: boolean; detail: string }> = [
  {
    name: 'canonical payload stable',
    ok: canonicalize(payload1) === canonicalize(payload2),
    detail: 'payload1 === payload2'
  },
  {
    name: 'SHA-256 deterministic',
    ok: hash1 === hash2 && hash1.length === 64,
    detail: hash1.slice(0, 16)
  },
  {
    name: 'attestationHash === auditHash',
    ok: att1.attestationHash === att1.auditHash && att1.attestationHash === hash1,
    detail: att1.attestationHash.slice(0, 16)
  },
  {
    name: 'buildAttestation deterministic',
    ok: att1.attestationHash === att2.attestationHash,
    detail: 'att1 === att2'
  },
  {
    name: 'scannedPages sorted in payload',
    ok:
      payload1.scannedPages[0].endsWith('/') &&
      payload1.scannedPages[1].includes('/a') &&
      payload1.scannedPages[2].includes('/b'),
    detail: payload1.scannedPages.map((p) => new URL(p).pathname).join(',')
  },
  {
    name: 'finding fingerprints sorted',
    ok: payload1.findingFingerprints[0].startsWith('A11Y'),
    detail: payload1.findingFingerprints.join(' || ')
  },
  {
    name: 'HMAC deterministic',
    ok: hmac1 === hmac2 && hmac1.length === 64,
    detail: hmac1.slice(0, 16)
  },
  {
    name: 'HMAC verifies',
    ok: verifyAttestationHmac(payload1, secret, hmac1),
    detail: 'timingSafeEqual OK'
  },
  {
    name: 'HMAC mode sets algorithm',
    ok:
      attHmac.algorithm === 'HMAC-SHA256' &&
      attHmac.hmacSignature === hmac1 &&
      attHmac.attestationHash === hash1,
    detail: attHmac.algorithm
  },
  {
    name: 'flag change breaks hash',
    ok: hashMutated !== hash1,
    detail: `${hash1.slice(0, 8)} ≠ ${hashMutated.slice(0, 8)}`
  },
  {
    name: 'qrPayload includes hash',
    ok: Boolean(att1.qrPayload?.includes(att1.attestationHash)),
    detail: (att1.qrPayload ?? '').slice(0, 80)
  },
  {
    name: 'cliVersion embedded',
    ok: att1.cliVersion === '1.0.0' && payload1.cliVersion === '1.0.0',
    detail: att1.cliVersion
  }
];

const failed = checks.filter((c) => !c.ok);
console.log('=== PHASE 2 ATTESTATION VERIFICATION ===');
for (const c of checks) {
  console.log(`${c.ok ? 'PASS' : 'FAIL'} · ${c.name}: ${c.detail}`);
}

if (failed.length > 0) {
  console.error(`\nPHASE 2 FAILED: ${failed.length} check(s)`);
  process.exit(1);
}

console.log('\nPHASE 2 SIMULATION: ALL CHECKS PASSED');
console.log(`attestationHash=${hash1}`);
