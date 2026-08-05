/**
 * Fase 3 verification: ticketing dry-run + webhook HMAC signing.
 * Usage: npx tsx scripts/verify_phase3_ticketing.ts
 */
import { TicketClient } from '../src/integrations/ticket_client.js';
import { WebhookNotifier } from '../src/integrations/webhook_notifier.js';
import { buildTicketPayloads } from '../src/integrations/ticket_formatter.js';
import { AuditFinding, AuditReportBundle } from '../src/types/audit.js';

function finding(ruleId: string, severity: AuditFinding['severity']): AuditFinding {
  return {
    id: `${ruleId}-1`,
    ruleId,
    title: `Title ${ruleId}`,
    severity,
    description: `Desc for ${ruleId}`,
    evidence: {
      url: 'https://example.com/login',
      selector: 'form',
      snippet: '<form>...</form>'
    },
    remediation: { explanation: 'Fix it', codeBefore: 'a', codeAfter: 'b' },
    standards: { owasp: ['A01:2021'], cwe: ['CWE-352'] },
    cvss: {
      version: '3.1',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
      baseScore: 6.5,
      severity: 'MEDIUM'
    }
  };
}

const findings = [
  finding('SEC-HDR-CSP-MISSING', 'HIGH'),
  finding('SEC-FORM-MISSING-CSRF-TOKEN', 'HIGH'),
  finding('SEO-H1-MISSING', 'MEDIUM')
];

const highOnly = findings.filter((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL');

const bundle: AuditReportBundle = {
  target: 'https://example.com/',
  timestamp: '2026-08-05T18:00:00.000Z',
  scannedPages: ['https://example.com/', 'https://example.com/login'],
  findings,
  digitalQualityScore: 55,
  maxCvssScore: 6.5,
  severityCounts: { CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 0 },
  dimensions: [],
  compliance: { frameworks: [], mappedFindingCount: 0 },
  gateFailed: true,
  failOn: 'HIGH',
  environment: 'prod',
  attestation: {
    attestationHash: 'abc123'.padEnd(64, '0'),
    auditHash: 'abc123'.padEnd(64, '0'),
    algorithm: 'SHA-256',
    cliVersion: '1.0.0',
    signedAtUtc: '2026-08-05T18:00:00.000Z',
    dashboardUrl: 'file:///tmp/dash.html',
    verificationUrl: 'file:///tmp/dash.html#attestation'
  }
};

const client = new TicketClient();
const jiraPayloads = buildTicketPayloads('jira', highOnly, { projectKey: 'SEC' });

const dry = await client.submit({
  provider: 'jira',
  findings: highOnly,
  context: { projectKey: 'SEC' },
  dryRun: true
});

const dryForcedSubmitNoCreds = await client.submit({
  provider: 'jira',
  findings: highOnly,
  context: { projectKey: 'SEC' },
  dryRun: false // should still dry-run without creds
});

const notifier = new WebhookNotifier();
const generic = notifier.buildPayload('generic', bundle);
const ts = '1710000000';
const body = JSON.stringify(generic);
const sig = notifier.signPayload('phase3-secret', ts, body);
const sig2 = notifier.signPayload('phase3-secret', ts, body);
const sigOther = notifier.signPayload('other', ts, body);

const dryWebhook = await notifier.notify({
  webhookUrl: 'https://example.com/hooks/corecheck',
  bundle,
  signingSecret: 'phase3-secret',
  dryRun: true
});

const checks: Array<{ name: string; ok: boolean; detail: string }> = [
  {
    name: 'Jira payload path',
    ok: jiraPayloads[0]?.path === '/rest/api/3/issue',
    detail: jiraPayloads[0]?.path ?? 'missing'
  },
  {
    name: 'Jira ADF description present',
    ok: Boolean(
      (jiraPayloads[0]?.body as { fields?: { description?: { type?: string } } }).fields
        ?.description?.type === 'doc'
    ),
    detail: 'ADF doc'
  },
  {
    name: 'Only HIGH/CRITICAL queued',
    ok: highOnly.length === 2 && dry.results.length === 2,
    detail: `n=${dry.results.length}`
  },
  {
    name: 'Default dry-run skips HTTP',
    ok: dry.dryRun === true && dry.skipped === 2 && dry.submitted === 0,
    detail: `skipped=${dry.skipped}`
  },
  {
    name: 'No creds forces dry-run even if dryRun=false',
    ok: dryForcedSubmitNoCreds.dryRun === true && dryForcedSubmitNoCreds.submitted === 0,
    detail: `dryRun=${dryForcedSubmitNoCreds.dryRun}`
  },
  {
    name: 'canSubmit false without env',
    ok: client.canSubmit('jira', { provider: 'jira', findings: [] }) === false,
    detail: 'no env'
  },
  {
    name: 'canSubmit true with overrides',
    ok: client.canSubmit('jira', {
      provider: 'jira',
      findings: [],
      jira: {
        domain: 'https://acme.atlassian.net',
        email: 'a@b.com',
        apiToken: 'token',
        projectKey: 'SEC'
      }
    }),
    detail: 'overrides OK'
  },
  {
    name: 'Webhook generic includes attestationHash',
    ok: generic.attestationHash === bundle.attestation?.attestationHash,
    detail: String(generic.attestationHash).slice(0, 12)
  },
  {
    name: 'Webhook HMAC deterministic',
    ok: sig === sig2 && sig.length === 64,
    detail: sig.slice(0, 16)
  },
  {
    name: 'Webhook HMAC secret-sensitive',
    ok: sig !== sigOther,
    detail: 'different secrets'
  },
  {
    name: 'Webhook dry-run signed',
    ok: dryWebhook.ok && dryWebhook.dryRun === true && dryWebhook.signed === true,
    detail: `signed=${dryWebhook.signed}`
  }
];

const failed = checks.filter((c) => !c.ok);
console.log('=== PHASE 3 TICKETING / WEBHOOK VERIFICATION ===');
for (const c of checks) {
  console.log(`${c.ok ? 'PASS' : 'FAIL'} · ${c.name}: ${c.detail}`);
}

if (failed.length > 0) {
  console.error(`\nPHASE 3 FAILED: ${failed.length} check(s)`);
  process.exit(1);
}

console.log('\nPHASE 3 SIMULATION: ALL CHECKS PASSED');
