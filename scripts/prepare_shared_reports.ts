#!/usr/bin/env node
/**
 * Prepara un directorio de shared_reports para deploy estático en Vercel.
 *
 * Contrato:
 * - Cualquier `*.html` pegado en la carpeta es publicable (URL /nombre con cleanUrls).
 * - Genera siempre `index.html` como hub (o redirect si hay un único reporte).
 * - Normaliza errores comunes: `*.html.html` → `*.html`.
 * - Copia `templates/shared-reports/vercel.json` al root del deploy.
 *
 * Uso:
 *   npx tsx scripts/prepare_shared_reports.ts
 *   npx tsx scripts/prepare_shared_reports.ts --dir reports/shared_reports/<folder>
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_SHARED = path.join(ROOT, 'reports', 'shared_reports');
const VERCEL_TEMPLATE = path.join(ROOT, 'templates', 'shared-reports', 'vercel.json');

const SKIP_NAMES = new Set(['index.html']);

function parseArgs(argv: string[]): { dir?: string } {
  const out: { dir?: string } = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dir' && argv[i + 1]) {
      out.dir = path.resolve(argv[++i]);
    }
  }
  return out;
}

function listDeployRoots(sharedRoot: string): string[] {
  if (!fs.existsSync(sharedRoot)) return [];
  return fs
    .readdirSync(sharedRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name !== '.vercel' && !d.name.startsWith('.'))
    .map((d) => path.join(sharedRoot, d.name));
}

/** Corrige `report.html.html` → `report.html` (sin pisar un destino existente). */
function normalizeDoubleHtmlExtensions(dir: string): string[] {
  const fixed: string[] = [];
  for (const name of fs.readdirSync(dir)) {
    if (!/\.html\.html$/i.test(name)) continue;
    const src = path.join(dir, name);
    if (!fs.statSync(src).isFile()) continue;

    // Nunca materializar como index.html: ese archivo lo genera el hub.
    let destName = name.replace(/\.html\.html$/i, '.html');
    if (destName.toLowerCase() === 'index.html') {
      destName = 'report.html';
    }

    let dest = path.join(dir, destName);
    if (fs.existsSync(dest)) {
      const base = destName.replace(/\.html$/i, '');
      destName = `${base}.normalized.html`;
      dest = path.join(dir, destName);
    }
    fs.renameSync(src, dest);
    fixed.push(`${name} → ${destName}`);
  }
  return fixed;
}

function listReportHtmlFiles(dir: string): string[] {
  return fs
    .readdirSync(dir)
    .filter((name) => name.toLowerCase().endsWith('.html'))
    .filter((name) => !SKIP_NAMES.has(name.toLowerCase()))
    .filter((name) => fs.statSync(path.join(dir, name)).isFile())
    .sort((a, b) => a.localeCompare(b));
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function cleanPath(fileName: string): string {
  return `/${fileName.replace(/\.html$/i, '')}`;
}

function buildIndexHtml(folderLabel: string, reports: string[]): string {
  if (reports.length === 1) {
    const only = reports[0];
    const href = cleanPath(only);
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="robots" content="noindex, nofollow, noarchive" />
  <meta http-equiv="refresh" content="0; url=${href}" />
  <title>CoreCheck Report</title>
  <link rel="canonical" href="${href}" />
  <script>location.replace(${JSON.stringify(href)});</script>
</head>
<body>
  <p>Redirecting to <a href="${href}">${escapeHtml(only)}</a>…</p>
</body>
</html>
`;
  }

  const items = reports
    .map((name) => {
      const href = cleanPath(name);
      return `      <li><a href="${href}">${escapeHtml(name)}</a></li>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex, nofollow, noarchive" />
  <title>CoreCheck Shared Reports — ${escapeHtml(folderLabel)}</title>
  <style>
    :root {
      --bg: #0f1419;
      --panel: #171d25;
      --text: #e7ecf1;
      --muted: #9aa7b5;
      --accent: #3d9a7a;
      --line: #2a3440;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", "Helvetica Neue", sans-serif;
      background:
        radial-gradient(1200px 600px at 10% -10%, #1a3030 0%, transparent 55%),
        var(--bg);
      color: var(--text);
    }
    main {
      max-width: 720px;
      margin: 0 auto;
      padding: 48px 24px 64px;
    }
    .brand {
      font-size: 0.75rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 12px;
    }
    h1 {
      font-size: 1.75rem;
      font-weight: 600;
      margin: 0 0 8px;
    }
    p {
      color: var(--muted);
      margin: 0 0 28px;
      line-height: 1.5;
    }
    ul {
      list-style: none;
      margin: 0;
      padding: 0;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel);
      overflow: hidden;
    }
    li + li { border-top: 1px solid var(--line); }
    a {
      display: block;
      padding: 14px 16px;
      color: var(--text);
      text-decoration: none;
    }
    a:hover { background: #1e2732; color: #fff; }
    .empty {
      border: 1px dashed var(--line);
      border-radius: 10px;
      padding: 24px;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <main>
    <div class="brand">CoreCheck</div>
    <h1>Shared reports</h1>
    <p>${escapeHtml(folderLabel)} — drop any <code>*.html</code> audit artifact here; each file is reachable by name. This index is generated at prepare time.</p>
    ${
      reports.length === 0
        ? `<div class="empty">No HTML reports found. Copy <code>report.html</code>, <code>interactive-dashboard.html</code>, or any other HTML artifact into this folder and re-run prepare.</div>`
        : `<ul>\n${items}\n    </ul>`
    }
  </main>
</body>
</html>
`;
}

function ensureVercelJson(dir: string): void {
  if (!fs.existsSync(VERCEL_TEMPLATE)) {
    throw new Error(`Missing Vercel template: ${VERCEL_TEMPLATE}`);
  }
  fs.copyFileSync(VERCEL_TEMPLATE, path.join(dir, 'vercel.json'));
}

function prepareDeployDir(dir: string): void {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    throw new Error(`Deploy directory not found: ${dir}`);
  }

  const fixed = normalizeDoubleHtmlExtensions(dir);
  const reports = listReportHtmlFiles(dir);
  const label = path.basename(dir);

  fs.writeFileSync(path.join(dir, 'index.html'), buildIndexHtml(label, reports), 'utf-8');
  ensureVercelJson(dir);

  console.log(`[prepare] ${dir}`);
  if (fixed.length) {
    for (const line of fixed) console.log(`  normalized: ${line}`);
  }
  console.log(`  reports: ${reports.length === 0 ? '(none)' : reports.join(', ')}`);
  console.log(`  wrote: index.html, vercel.json`);
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const targets = args.dir ? [args.dir] : listDeployRoots(DEFAULT_SHARED);

  if (targets.length === 0) {
    console.error(
      `No deploy folders under ${DEFAULT_SHARED}. Create a folder, paste HTML reports, then re-run.`
    );
    process.exit(1);
  }

  for (const dir of targets) {
    prepareDeployDir(dir);
  }
}

main();
