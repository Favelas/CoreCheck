/**
 * Fase 1 verification: site-level finding consolidation.
 * Usage: npx tsx scripts/verify_phase1_consolidation.ts
 */
import { FindingConsolidator } from '../src/core/finding_consolidator.js';
import { AuditFinding } from '../src/types/audit.js';

function stub(
  ruleId: string,
  url: string,
  severity: AuditFinding['severity'] = 'HIGH'
): AuditFinding {
  return {
    id: `${ruleId}-${url}-${Math.random().toString(36).slice(2, 6)}`,
    ruleId,
    title: `Finding ${ruleId}`,
    severity,
    description: `Desc ${ruleId}`,
    category: ruleId.startsWith('PRIV') ? 'PRIVACY' : 'SECURITY',
    ruleType: ruleId.startsWith('SEC-HDR') ? 'SECURITY_HEADER' : undefined,
    evidence: { url, snippet: `${ruleId} @ ${url}` },
    remediation: { explanation: 'Fix it', codeBefore: 'a', codeAfter: 'b' },
    standards: { owasp: ['A05:2021'], cwe: ['CWE-200'] }
  };
}

const pages = [
  'https://example.com/',
  'https://example.com/login',
  'https://example.com/plans',
  'https://example.com/about',
  'https://example.com/capture'
];

const inflated: AuditFinding[] = [];
for (const page of pages) {
  inflated.push(stub('SEC-HDR-CSP-MISSING', page, 'HIGH'));
  inflated.push(stub('SEC-HDR-CLICKJACKING', page, 'MEDIUM'));
  inflated.push(stub('SEC-HDR-NOSNIFF-MISSING', page, 'LOW'));
  inflated.push(stub('PRIV-POLICY-LINK-MISSING', page, 'MEDIUM'));
  inflated.push(stub('PRIV-COOKIE-POLICY-LINK-MISSING', page, 'MEDIUM'));
  // page-level (must NOT merge across pages)
  inflated.push(stub('A11Y-color-contrast', page, 'HIGH'));
  inflated.push(stub('SEC-FORM-MISSING-CSRF-TOKEN', page, 'HIGH'));
}

const consolidator = new FindingConsolidator();
const { findings, stats } = consolidator.consolidate(inflated);

const byRule = (id: string) => findings.filter((f) => f.ruleId === id);
const csp = byRule('SEC-HDR-CSP-MISSING');
const a11y = byRule('A11Y-color-contrast');
const csrf = byRule('SEC-FORM-MISSING-CSRF-TOKEN');

const severityCounts = {
  CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
  HIGH: findings.filter((f) => f.severity === 'HIGH').length,
  MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
  LOW: findings.filter((f) => f.severity === 'LOW').length,
  INFO: findings.filter((f) => f.severity === 'INFO').length
};

const expectedBefore = pages.length * 7; // 35
const expectedSiteUnique = 5; // CSP, CLICK, NOSNIFF, PRIV-POL, PRIV-COOKIE-POL
const expectedPageLevel = pages.length * 2; // A11y + CSRF per page
const expectedAfter = expectedSiteUnique + expectedPageLevel; // 5 + 10 = 15

const checks: Array<{ name: string; ok: boolean; detail: string }> = [
  {
    name: 'beforeCount',
    ok: stats.beforeCount === expectedBefore,
    detail: `${stats.beforeCount} === ${expectedBefore}`
  },
  {
    name: 'afterCount',
    ok: stats.afterCount === expectedAfter,
    detail: `${stats.afterCount} === ${expectedAfter}`
  },
  {
    name: 'CSP merged to 1',
    ok: csp.length === 1,
    detail: `count=${csp.length}`
  },
  {
    name: 'CSP lists 5 pages',
    ok: (csp[0]?.evidence.locations?.length ?? 0) === 5,
    detail: `locations=${csp[0]?.evidence.locations?.length}`
  },
  {
    name: 'A11y remains page-level (5)',
    ok: a11y.length === 5,
    detail: `count=${a11y.length}`
  },
  {
    name: 'CSRF remains page-level (5)',
    ok: csrf.length === 5,
    detail: `count=${csrf.length}`
  },
  {
    name: 'HIGH unique not inflated',
    ok: severityCounts.HIGH === 1 + 5 + 5, // 1 CSP + 5 A11y + 5 CSRF
    detail: `HIGH=${severityCounts.HIGH} (expected 11)`
  },
  {
    name: 'MEDIUM unique not inflated',
    ok: severityCounts.MEDIUM === 3, // CLICK + 2 PRIV
    detail: `MEDIUM=${severityCounts.MEDIUM} (expected 3)`
  },
  {
    name: 'LOW unique not inflated',
    ok: severityCounts.LOW === 1, // NOSNIFF
    detail: `LOW=${severityCounts.LOW} (expected 1)`
  }
];

const failed = checks.filter((c) => !c.ok);
console.log('=== PHASE 1 CONSOLIDATION SIMULATION ===');
console.log(`Input findings: ${stats.beforeCount}`);
console.log(`Output findings: ${stats.afterCount}`);
console.log(`Site-level merged away: ${stats.siteLevelMerged}`);
console.log(`Severity counts:`, severityCounts);
console.log(`CSP title: ${csp[0]?.title}`);
console.log(`CSP snippet head:\n${csp[0]?.evidence.snippet?.split('\n').slice(0, 4).join('\n')}`);
for (const c of checks) {
  console.log(`${c.ok ? 'PASS' : 'FAIL'} · ${c.name}: ${c.detail}`);
}

if (failed.length > 0) {
  console.error(`\nPHASE 1 FAILED: ${failed.length} check(s)`);
  process.exit(1);
}

console.log('\nPHASE 1 SIMULATION: ALL CHECKS PASSED');
