'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { JsonFileReportsStore } = require('../src/store/jsonFileReports.store');

describe('JsonFileReportsStore (Phase 3 durable persistence)', () => {
  /** @type {string} */
  let tmpDir;
  /** @type {string} */
  let filePath;

  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'corecheck-api-'));
    filePath = path.join(tmpDir, 'reports.json');
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('persiste y recarga reportes tras "reinicio" (nueva instancia)', async () => {
    const storeA = new JsonFileReportsStore({ filePath });
    await storeA.clear();

    const saved = await storeA.saveReport(
      { url: 'https://example.com', summary: 'durable' },
      'tenant_alpha'
    );

    assert.equal(saved.accountId, 'tenant_alpha');
    assert.ok(saved.contentHash);
    assert.equal(fs.existsSync(filePath), true);

    const storeB = new JsonFileReportsStore({ filePath });
    const listed = await storeB.getAllReports('tenant_alpha');
    assert.equal(listed.total, 1);
    assert.equal(listed.data[0].id, saved.id);
    assert.equal(listed.data[0].summary, 'durable');

    assert.equal((await storeB.getAllReports('tenant_beta')).total, 0);
    assert.equal(await storeB.getReportById(saved.id, 'tenant_beta'), undefined);
  });

  it('documento en disco tiene version=1', () => {
    const raw = fs.readFileSync(filePath, 'utf8');
    const doc = JSON.parse(raw);
    assert.equal(doc.version, 1);
    assert.equal(Array.isArray(doc.reports), true);
  });
});
