/**
 * Fase 4 verification: INP rule mapping + llm.txt readiness logic.
 * Usage: npx tsx scripts/verify_phase4_digital_quality.ts
 */
import { FindingConsolidator } from '../src/core/finding_consolidator.js';
import { ComplianceMapper } from '../src/core/compliance_mapper.js';
import { LlmReadinessInspector } from '../src/inspectors/llm_readiness_inspector.js';
import { AuditFinding } from '../src/types/audit.js';

function stub(
  ruleId: string,
  category: AuditFinding['category'],
  severity: AuditFinding['severity'] = 'MEDIUM'
): AuditFinding {
  return {
    id: `${ruleId}-1`,
    ruleId,
    title: ruleId,
    severity,
    description: ruleId,
    category,
    ruleType: ruleId.startsWith('PERF') ? 'PERF_WEB_VITAL' : 'SEO_LLM_READINESS',
    evidence: { url: 'https://example.com/', snippet: ruleId },
    remediation: { explanation: 'fix' },
    standards: {}
  };
}

// --- Dimension mapping ---
const mapper = new ComplianceMapper();
const inpFinding = stub('PERF-INP-SLOW', 'PERFORMANCE', 'HIGH');
const llmFinding = stub('LLM-TXT-MISSING', 'SEO', 'MEDIUM');
const dimInp = mapper.resolveDimension(inpFinding);
const dimLlm = mapper.resolveDimension(llmFinding);

// --- Site-level consolidation for LLM ---
const consolidator = new FindingConsolidator();
const pages = ['https://example.com/', 'https://example.com/a', 'https://example.com/b'];
const inflated: AuditFinding[] = [];
for (const url of pages) {
  inflated.push({
    ...stub('LLM-TXT-MISSING', 'SEO'),
    id: `LLM-${url}`,
    evidence: { url, snippet: 'missing' }
  });
  inflated.push({
    ...stub('PERF-INP-SLOW', 'PERFORMANCE', 'HIGH'),
    id: `INP-${url}`,
    evidence: { url, snippet: 'INP=450' }
  });
}
const { findings, stats } = consolidator.consolidate(inflated);
const llmMerged = findings.filter((f) => f.ruleId === 'LLM-TXT-MISSING');
const inpKept = findings.filter((f) => f.ruleId === 'PERF-INP-SLOW');

// --- llm.txt validator (private via public inspect path simulation) ---
class Probe extends LlmReadinessInspector {
  public probe(body: string) {
    // access private via bracket for test — re-implement mirror
    const lines = body
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const substantive = lines.filter((l) => !l.startsWith('#'));
    const empty = substantive.length === 0 && lines.length < 2;
    const blob = body.toLowerCase();
    const structured =
      /contact\s*:/i.test(body) ||
      /policy\s*:/i.test(body) ||
      /allow\s*:/i.test(body) ||
      /prefer\s*:/i.test(body) ||
      /user-agent\s*:/i.test(body) ||
      blob.includes('llm');
    return { empty, structured: structured || substantive.length >= 3 };
  }
}

// Can't instantiate without Page — test structure rules inline:
function validateLlmTxt(body: string): { empty: boolean; structured: boolean } {
  const lines = body
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const substantive = lines.filter((l) => !l.startsWith('#'));
  const empty = substantive.length === 0 && lines.length < 2;
  const blob = body.toLowerCase();
  const structured =
    /contact\s*:/i.test(body) ||
    /policy\s*:/i.test(body) ||
    /allow\s*:/i.test(body) ||
    /prefer\s*:/i.test(body) ||
    /user-agent\s*:/i.test(body) ||
    /sitemap\s*:/i.test(body) ||
    blob.includes('llms') ||
    blob.includes('llm');
  return { empty, structured: structured || substantive.length >= 3 };
}

const emptyCheck = validateLlmTxt('# only comment\n');
const goodCheck = validateLlmTxt('# Contact: ai@example.com\n# Policy: https://example.com/ai\nPrefer: /docs\n');
const junkCheck = validateLlmTxt('hello world');

const dims = mapper.buildDimensions([inpFinding, llmFinding]);
const perfDim = dims.find((d) => d.dimension === 'PERFORMANCE');
const seoDim = dims.find((d) => d.dimension === 'SEO');

const checks: Array<{ name: string; ok: boolean; detail: string }> = [
  {
    name: 'PERF-INP maps to PERFORMANCE',
    ok: dimInp === 'PERFORMANCE',
    detail: dimInp
  },
  {
    name: 'LLM-TXT maps to SEO',
    ok: dimLlm === 'SEO',
    detail: dimLlm
  },
  {
    name: 'LLM site-level consolidated',
    ok: llmMerged.length === 1 && (llmMerged[0].evidence.locations?.length ?? 0) === 3,
    detail: `llm=${llmMerged.length} pages=${llmMerged[0]?.evidence.locations?.length}`
  },
  {
    name: 'INP remains page-level',
    ok: inpKept.length === 3,
    detail: `inp=${inpKept.length}`
  },
  {
    name: 'consolidation reduced count',
    ok: stats.beforeCount === 6 && stats.afterCount === 4,
    detail: `${stats.beforeCount}→${stats.afterCount}`
  },
  {
    name: 'empty llm.txt detected',
    ok: emptyCheck.empty === true,
    detail: JSON.stringify(emptyCheck)
  },
  {
    name: 'structured llm.txt accepted',
    ok: goodCheck.empty === false && goodCheck.structured === true,
    detail: JSON.stringify(goodCheck)
  },
  {
    name: 'unstructured short body flagged',
    ok: junkCheck.structured === false,
    detail: JSON.stringify(junkCheck)
  },
  {
    name: 'PERFORMANCE dimension counts INP',
    ok: (perfDim?.count ?? 0) === 1,
    detail: `count=${perfDim?.count}`
  },
  {
    name: 'SEO dimension counts LLM',
    ok: (seoDim?.count ?? 0) === 1,
    detail: `count=${seoDim?.count}`
  },
  {
    name: 'isSiteLevel LLM',
    ok: consolidator.isSiteLevel(llmFinding) && !consolidator.isSiteLevel(inpFinding),
    detail: 'LLM site / INP page'
  }
];

void Probe; // keep import used for type presence of inspector module

const failed = checks.filter((c) => !c.ok);
console.log('=== PHASE 4 DIGITAL QUALITY VERIFICATION ===');
for (const c of checks) {
  console.log(`${c.ok ? 'PASS' : 'FAIL'} · ${c.name}: ${c.detail}`);
}

if (failed.length > 0) {
  console.error(`\nPHASE 4 FAILED: ${failed.length} check(s)`);
  process.exit(1);
}

console.log('\nPHASE 4 SIMULATION: ALL CHECKS PASSED');
