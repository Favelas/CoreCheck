import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  ControlPlaneHttpClient,
  ControlPlaneHttpError,
  isUploadEnabled,
  resolveReportsApiBaseUrl
} from '../src/http/control_plane_http.ts';
import { buildCreateReportInput } from '../src/services/report_payload.ts';
import { ReportsClient, ReportsClientError } from '../src/services/reports_client.ts';
import { maybeUploadAuditReport } from '../src/services/upload_report.ts';
import type { AuditReportBundle } from '../src/types/audit.ts';

function sampleBundle(overrides?: Partial<AuditReportBundle>): AuditReportBundle {
  return {
    target: 'https://example.com',
    timestamp: '2026-08-14T20:00:00.000Z',
    scannedPages: ['https://example.com'],
    findings: [
      {
        id: 'f1',
        ruleId: 'A11Y_001',
        title: 'Missing alt',
        severity: 'HIGH',
        description: 'Image without alt text',
        evidence: { url: 'https://example.com/a', selector: 'img.hero' },
        remediation: { explanation: 'Add alt' },
        standards: {}
      }
    ],
    digitalQualityScore: 82,
    maxCvssScore: 0,
    severityCounts: {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    },
    dimensions: [
      {
        dimension: 'ACCESSIBILITY',
        count: 1,
        score: 70,
        bySeverity: { HIGH: 1 }
      }
    ],
    compliance: { frameworks: [], mappedFindingCount: 0 },
    gateFailed: true,
    failOn: 'HIGH',
    environment: 'staging',
    ...overrides
  };
}

describe('control_plane_http helpers', () => {
  it('resolveReportsApiBaseUrl prioriza REPORTS > UPLOAD > API_URL', () => {
    assert.equal(
      resolveReportsApiBaseUrl(undefined, {
        CORECHECK_REPORTS_API_URL: 'https://reports.example/',
        CORECHECK_UPLOAD_URL: 'https://upload.example',
        CORECHECK_API_URL: 'https://api.example'
      }),
      'https://reports.example'
    );
    assert.equal(
      resolveReportsApiBaseUrl(undefined, {
        CORECHECK_UPLOAD_URL: 'https://upload.example/',
        CORECHECK_API_URL: 'https://api.example'
      }),
      'https://upload.example'
    );
    assert.equal(
      resolveReportsApiBaseUrl('https://explicit.example/', {}),
      'https://explicit.example'
    );
  });

  it('isUploadEnabled respeta flag y CORECHECK_UPLOAD', () => {
    assert.equal(isUploadEnabled(true, {}), true);
    assert.equal(isUploadEnabled(false, { CORECHECK_UPLOAD: 'true' }), true);
    assert.equal(isUploadEnabled(false, { CORECHECK_UPLOAD: '1' }), true);
    assert.equal(isUploadEnabled(false, { CORECHECK_UPLOAD: 'no' }), false);
    assert.equal(isUploadEnabled(false, {}), false);
  });

  it('ControlPlaneHttpClient inyecta X-API-Key, Bearer y x-request-id', async () => {
    /** @type {Record<string, string> | undefined} */
    let seenHeaders;
    const client = new ControlPlaneHttpClient({
      baseUrl: 'https://cp.example',
      apiKey: 'cc_test_key',
      fetchImpl: async (_url, init) => {
        seenHeaders = init?.headers as Record<string, string>;
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
    });

    await client.get('/health');
    assert.equal(seenHeaders?.Authorization, 'Bearer cc_test_key');
    assert.equal(seenHeaders?.['X-API-Key'], 'cc_test_key');
    assert.ok(seenHeaders?.['x-request-id']);
    assert.match(seenHeaders?.['x-request-id'] ?? '', /^[0-9a-f-]{36}$/i);
  });
});

describe('buildCreateReportInput', () => {
  it('mapea bundle a CreateReportInput sin secretos', () => {
    const payload = buildCreateReportInput(sampleBundle());
    assert.equal(payload.url, 'https://example.com');
    assert.equal(payload.failOn, 'HIGH');
    assert.equal(payload.findingsCount, 1);
    assert.equal(payload.findings?.[0]?.ruleId, 'A11Y_001');
    assert.equal(payload.findings?.[0]?.url, 'https://example.com/a');
    assert.equal(payload.metrics?.[0]?.dimension, 'ACCESSIBILITY');
    assert.equal(payload['gateFailed'], true);
    assert.ok(String(payload.summary).includes('gate=FAIL'));
  });

  it('trunca findings al presupuesto', () => {
    const many = Array.from({ length: 150 }, (_, i) => ({
      id: `f${i}`,
      ruleId: `R_${i}`,
      title: `T${i}`,
      severity: 'LOW' as const,
      description: 'x'.repeat(800),
      evidence: {},
      remediation: { explanation: 'n/a' },
      standards: {}
    }));
    const payload = buildCreateReportInput(sampleBundle({ findings: many }));
    assert.equal(payload.findingsCount, 150);
    assert.equal(payload.findings?.length, 100);
    assert.equal(payload['findingsTruncated'], true);
    assert.ok((payload.findings?.[0]?.description.length ?? 0) <= 500);
  });
});

describe('ReportsClient', () => {
  it('uploadReport → 201 mapea id', async () => {
    const client = new ReportsClient({
      baseUrl: 'http://localhost:3000',
      apiKey: 'cc_dev_local',
      fetchImpl: async (url, init) => {
        assert.equal(String(url), 'http://localhost:3000/api/reports');
        assert.equal(init?.method, 'POST');
        const headers = init?.headers as Record<string, string>;
        assert.equal(headers['X-API-Key'], 'cc_dev_local');
        return new Response(
          JSON.stringify({
            id: '11111111-1111-4111-8111-111111111111',
            createdAt: '2026-08-14T20:01:00.000Z',
            accountId: 'tenant_default',
            contentHash: 'abc123def456',
            url: 'https://example.com'
          }),
          { status: 201 }
        );
      }
    });

    const report = await client.uploadReport(
      buildCreateReportInput(sampleBundle())
    );
    assert.equal(report.id, '11111111-1111-4111-8111-111111111111');
    assert.equal(report.accountId, 'tenant_default');
  });

  it('mapea 401 / 400 / 429 a ReportsClientError tipado', async () => {
    const cases: Array<{ status: number; error: string; check: (e: ReportsClientError) => void }> = [
      {
        status: 401,
        error: 'UNAUTHORIZED',
        check: (e) => assert.equal(e.isUnauthorized, true)
      },
      {
        status: 400,
        error: 'BAD_REQUEST',
        check: (e) => assert.equal(e.isPayloadInvalid, true)
      },
      {
        status: 422,
        error: 'BAD_REQUEST',
        check: (e) => assert.equal(e.isPayloadInvalid, true)
      },
      {
        status: 429,
        error: 'RATE_LIMITED',
        check: (e) => assert.equal(e.isRateLimited, true)
      }
    ];

    for (const c of cases) {
      const client = new ReportsClient({
        baseUrl: 'http://localhost:3000',
        apiKey: 'k',
        fetchImpl: async () =>
          new Response(JSON.stringify({ error: c.error, message: 'nope' }), {
            status: c.status
          })
      });
      await assert.rejects(
        () => client.uploadReport({ url: 'https://example.com' }),
        (err: unknown) => {
          assert.ok(err instanceof ReportsClientError);
          assert.equal(err.status, c.status);
          c.check(err);
          return true;
        }
      );
    }
  });
});

describe('maybeUploadAuditReport (run orchestration mock)', () => {
  it('no-op cuando upload deshabilitado', async () => {
    const result = await maybeUploadAuditReport({
      enabled: false,
      bundle: sampleBundle()
    });
    assert.deepEqual(result, { attempted: false, uploaded: false });
  });

  it('usa client mock y expone reportId', async () => {
    const logs: string[] = [];
    const client = new ReportsClient({
      baseUrl: 'http://reports.test',
      apiKey: 'k',
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            id: 'rid-1',
            createdAt: '2026-08-14T20:01:00.000Z',
            accountId: 't1',
            contentHash: 'hashhashhash',
            url: 'https://example.com'
          }),
          { status: 201 }
        )
    });

    const result = await maybeUploadAuditReport({
      enabled: true,
      bundle: sampleBundle(),
      client,
      log: (m) => logs.push(m)
    });

    assert.equal(result.uploaded, true);
    assert.equal(result.reportId, 'rid-1');
    assert.ok(logs.some((l) => l.includes('rid-1')));
  });

  it('soft-fail en error; strict relanza', async () => {
    const client = new ReportsClient({
      baseUrl: 'http://reports.test',
      apiKey: 'k',
      fetchImpl: async () =>
        new Response(JSON.stringify({ error: 'UNAUTHORIZED', message: 'no' }), {
          status: 401
        })
    });

    const soft = await maybeUploadAuditReport({
      enabled: true,
      strict: false,
      bundle: sampleBundle(),
      client,
      warn: () => undefined
    });
    assert.equal(soft.uploaded, false);
    assert.equal(soft.status, 401);

    await assert.rejects(
      () =>
        maybeUploadAuditReport({
          enabled: true,
          strict: true,
          bundle: sampleBundle(),
          client,
          warn: () => undefined
        }),
      (err: unknown) => err instanceof ReportsClientError || err instanceof ControlPlaneHttpError
    );
  });
});
