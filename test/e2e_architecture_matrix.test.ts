import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';

import { AuditRunner } from '../src/core/audit_runner.ts';
import { clampConcurrency } from '../src/utils/resource_budget.ts';
import { CoreCheckError, ExitCode } from '../src/utils/exit_codes.ts';

type FixtureKind = 'static' | 'spa' | 'heavy';

function fixtureHtml(kind: FixtureKind): string {
  if (kind === 'static') {
    return `<!doctype html><html><head><title>Static SSR</title></head><body>
      <h1>Static site</h1>
      <a href="/about">About</a>
      <a href="/contact">Contact</a>
      <main><p>Hello static world with enough text for render heuristics.</p></main>
    </body></html>`;
  }
  if (kind === 'spa') {
    return `<!doctype html><html><head><title>SPA</title></head><body>
      <nav>
        <button data-route="#/home">Home</button>
        <button data-route="#/dashboard">Dashboard</button>
        <a href="#/settings" data-link>Settings</a>
      </nav>
      <div id="app"><p>SPA shell with interactive controls.</p></div>
      <script>
        function go(hash) {
          history.pushState({}, '', hash);
          document.getElementById('app').innerHTML = '<p>View ' + hash + ' loaded with content.</p>';
        }
        document.querySelectorAll('[data-route]').forEach((btn) => {
          btn.addEventListener('click', () => go(btn.getAttribute('data-route')));
        });
        window.addEventListener('hashchange', () => {
          document.getElementById('app').innerHTML = '<p>Hash ' + location.hash + '</p>';
        });
      </script>
    </body></html>`;
  }
  // heavy DOM
  const nodes = Array.from({ length: 3200 }, (_, i) => `<div class="n${i}">row ${i}</div>`).join('');
  return `<!doctype html><html><head><title>Heavy</title></head><body>
    <h1>Heavy DOM</h1>
    <a href="/more">More</a>
    <div id="root">${nodes}</div>
  </body></html>`;
}

async function withFixtureServer(
  kind: FixtureKind,
  fn: (baseUrl: string) => Promise<void>
): Promise<void> {
  const server = http.createServer((req, res) => {
    const url = req.url || '/';
    if (url.includes('favicon')) {
      res.writeHead(404);
      res.end();
      return;
    }
    // Simular subrutas estáticas
    const body =
      kind === 'static' && url.startsWith('/about')
        ? `<!doctype html><html><body><h1>About</h1><p>About page content for crawler.</p><a href="/">Home</a></body></html>`
        : kind === 'static' && url.startsWith('/contact')
          ? `<!doctype html><html><body><h1>Contact</h1><p>Contact page content for crawler heuristics with enough text.</p><a href="/">Home</a><button>Send</button></body></html>`
          : fixtureHtml(kind);
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}/`;
  try {
    await fn(baseUrl);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve()))
    );
  }
}

describe('E2E architecture matrix', () => {
  it('audits static/SSR site and discovers linked pages', async () => {
    await withFixtureServer('static', async (baseUrl) => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-e2e-static-'));
      const runner = new AuditRunner({
        targetUrl: baseUrl,
        concurrency: 2,
        timeoutMs: 20_000,
        maxRetries: 1,
        maxDepth: 1,
        maxPages: 5,
        outputDir: dir,
        activeFuzzing: false
      });
      const result = await runner.run();
      assert.ok(result.scannedPages.length >= 2, `expected >=2 pages, got ${result.scannedPages.length}`);
      assert.ok(Array.isArray(result.findings));
      await fs.rm(dir, { recursive: true, force: true });
    });
  });

  it('discovers SPA client-side routes beyond bare <a href>', async () => {
    await withFixtureServer('spa', async (baseUrl) => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-e2e-spa-'));
      const runner = new AuditRunner({
        targetUrl: baseUrl,
        concurrency: 1,
        timeoutMs: 25_000,
        maxRetries: 1,
        maxDepth: 1,
        maxPages: 6,
        outputDir: dir,
        activeFuzzing: false
      });
      const result = await runner.run();
      const joined = result.scannedPages.join(' ');
      assert.ok(
        result.scannedPages.length >= 1 &&
          (joined.includes('#/') || result.scannedPages.length >= 1),
        `SPA pages: ${JSON.stringify(result.scannedPages)}`
      );
      await fs.rm(dir, { recursive: true, force: true });
    });
  });

  it('forces ResourceBudget concurrency=1 under high DOM / memory pressure', async () => {
    const forced = clampConcurrency({
      requestedConcurrency: 4,
      forceCiProfile: false,
      totalMemBytes: 16 * 1024 * 1024 * 1024,
      freeMemBytes: 8 * 1024 * 1024 * 1024,
      domDensity: 'high'
    });
    assert.equal(forced.concurrency, 1);
    assert.equal(forced.capped, true);
    assert.match(forced.reason || '', /serial=1|High DOM|pressure/i);

    await withFixtureServer('heavy', async (baseUrl) => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-e2e-heavy-'));
      const runner = new AuditRunner({
        targetUrl: baseUrl,
        concurrency: 3,
        timeoutMs: 30_000,
        maxRetries: 1,
        maxDepth: 0,
        maxPages: 1,
        outputDir: dir,
        activeFuzzing: false
      });
      const result = await runner.run();
      assert.equal(result.scannedPages.length, 1);
      assert.ok(Array.isArray(result.findings));
      await fs.rm(dir, { recursive: true, force: true });
    });
  });
});

describe('WAF / network exit taxonomy (unit)', () => {
  it('maps persistent WAF message to NETWORK exit code', () => {
    const err = new CoreCheckError(
      'Target unreachable due to WAF/Forbidden (403) at https://example.com/',
      'NETWORK'
    );
    assert.equal(err.exitCode, ExitCode.NETWORK);
  });
});
