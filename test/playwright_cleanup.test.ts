import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';
import { describe, it } from 'node:test';

import { AuditRunner } from '../src/core/audit_runner.ts';

describe('Playwright cleanup resilience', () => {
  it('closes browser after audit and allows a fresh Chromium launch', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-pw-'));

    const runner = new AuditRunner({
      targetUrl: 'https://example.com/',
      concurrency: 2,
      timeoutMs: 45_000,
      maxRetries: 1,
      maxDepth: 0,
      maxPages: 1,
      sameOriginOnly: true,
      outputDir: dir,
      activeFuzzing: false
    });

    const result = await runner.run();
    assert.ok(result.scannedPages.length >= 1);
    assert.ok(Array.isArray(result.findings));

    // Si el finally no cerró Chromium, runners pequeños acumulan procesos y este launch falla/cuelga.
    const browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    assert.equal(browser.isConnected(), true);
    const contexts = browser.contexts();
    assert.equal(contexts.length, 0);
    await browser.close();
    assert.equal(browser.isConnected(), false);

    await fs.rm(dir, { recursive: true, force: true });
  });

  it('survives consecutive runs without leaking connected browsers', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-pw2-'));

    for (let i = 0; i < 2; i++) {
      const runDir = path.join(dir, `run-${i}`);
      await fs.mkdir(runDir, { recursive: true });
      const runner = new AuditRunner({
        targetUrl: 'https://example.com/',
        concurrency: 1,
        timeoutMs: 45_000,
        maxRetries: 1,
        maxDepth: 0,
        maxPages: 1,
        outputDir: runDir,
        activeFuzzing: false
      });
      const result = await runner.run();
      assert.ok(result.scannedPages.length >= 1);
    }

    const probe = await chromium.launch({ headless: true });
    assert.equal(probe.isConnected(), true);
    await probe.close();

    await fs.rm(dir, { recursive: true, force: true });
  });
});
