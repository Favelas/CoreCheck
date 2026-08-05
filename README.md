# CoreCheck

Motor CLI de auditoría **DAST** (Dynamic Application Security Testing) y **accesibilidad (A11y / WCAG)** diseñado para actuar como **Quality Gate** en pipelines de CI/CD (GitHub Actions).

CoreCheck navega la aplicación objetivo con Playwright, ejecuta inspectores de seguridad y accesibilidad, y genera reportes accionables (JSON, SARIF, HTML y Markdown) con exit codes estables para bloquear Pull Requests cuando hay hallazgos por encima del umbral configurado.

## Prerrequisitos

- **Node.js** v20 o superior
- **npm**
- **Chromium** vía Playwright (se descarga automáticamente con `npm install` gracias al script `postinstall`)

## Instalación

```bash
npm install
```

## Uso rápido (CLI)

```bash
npx tsx src/cli/index.ts \
  --url https://example.com \
  --fail-on HIGH \
  --formats json,html,sarif,markdown \
  --output-dir ./audit-results
```

Equivalente con scripts npm:

```bash
npm run audit -- --url https://example.com --fail-on HIGH --formats json,html,sarif,markdown
npm run audit:sample
```

### Parámetros principales

| Flag | Descripción | Default |
| --- | --- | --- |
| `-u, --url <string>` | URL objetivo a auditar (requerido) | — |
| `-f, --formats <items>` | Formatos de reporte: `json`, `html`, `sarif`, `markdown` | `json,html,sarif` |
| `-o, --output-dir <path>` | Directorio base de reportes (se crea subcarpeta `dominio_timestamp`) | `./audit-results` |
| `--flat-output` | Escribe directo en `--output-dir` sin subcarpeta fechada (útil en CI) | `false` |
| `--fail-on <severity>` | Severidad mínima para `exit 1`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | `HIGH` |
| `-a, --auth-state <path>` | `storageState.json` de Playwright para sesiones autenticadas | — |
| `-c, --concurrency <number>` | Concurrencia de contextos | `2` |
| `-t, --timeout <number>` | Timeout global por página (ms) | `30000` |
| `--fuzzing` | Habilita fuzzing activo | `false` |

### Salidas

Por defecto los artefactos quedan en:

```text
audit-results/{dominio}_{YYYY-MM-DD_HH-mm-ss}/
  ├── findings.json
  ├── results.sarif
  ├── report.html
  ├── report.md
  └── screenshots/
```

### Quality Gate (exit codes)

- `0` — ningún hallazgo alcanza o supera `--fail-on`
- `1` — hay hallazgos ≥ umbral, o error crítico de ejecución

## CI/CD (GitHub Actions)

El workflow [`.github/workflows/audit.yml`](.github/workflows/audit.yml) ejecuta CoreCheck como Quality Gate:

| Aspecto | Comportamiento |
| --- | --- |
| **Triggers** | `pull_request` hacia `main`/`master` y `workflow_dispatch` (URL configurable) |
| **Runtime** | Node.js 20 + `npm ci` (Chromium vía `postinstall`) + deps OS de Playwright |
| **Auditoría** | CLI con `--fail-on HIGH` y formatos `json,sarif,html,markdown` |
| **Artefactos** | Sube `./audit-results` como artifact descargable |
| **Code Scanning** | Publica `results.sarif` con `github/codeql-action/upload-sarif@v3` |
| **Comentario PR** | Publica `report.md` como comentario sticky (`marocchino/sticky-pull-request-comment`) |

En CI se usa `--flat-output` para rutas de reporte predecibles (`./audit-results/results.sarif`, `./audit-results/report.md`).

## Scripts npm

| Script | Descripción |
| --- | --- |
| `npm run typecheck` | Verifica TypeScript sin emitir (`tsc --noEmit`) |
| `npm run build` | Compila a `dist/` |
| `npm run audit` | Lanza la CLI (pasa flags después de `--`) |
| `npm run audit:sample` | Corrida de ejemplo contra `https://example.com` |
| `npm install` / `postinstall` | Instala dependencias y Chromium de Playwright |

## Inspectores activos (MVP v1.0)

- **HeadersConfigInspector** — cabeceras HTTP de seguridad
- **ConsoleDataInspector** — fugas en `localStorage` / `sessionStorage`
- **VisualMetaInspector** — evidencia visual y meta tags
- **FormActiveInspector** — estructura de formularios, CSRF, inputs (ASVS L3) y A11y inline
- **FuzzingInspector** — fuzzing activo (con `--fuzzing`)

## Licencia

Uso interno / proyecto CoreCheck MVP v1.0.
