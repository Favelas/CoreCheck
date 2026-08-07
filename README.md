# CoreCheck v1.0

**Digital Quality Gate** para pipelines CI/CD: un solo escaneo que combina seguridad (DAST), accesibilidad (WCAG 2.2 AA), rendimiento (Core Web Vitals / INP), privacidad, SEO/GEO y readiness para agentes de IA.

| | |
| :--- | :--- |
| **Versión** | 1.0 Enterprise Hardened |
| **Runtime** | Node.js 20+ · Playwright (Chromium) |
| **Salidas** | HTML · PDF (attestation) · SARIF 2.1.0 · JSON · Markdown |
| **Rol típico** | Quality Gate en Pull Requests (GitHub Actions) |

---

## ¿Qué problema resuelve?

En lugar de encadenar 4–5 herramientas distintas (seguridad, a11y, performance, SEO), CoreCheck ejecuta **una pasada unificada** sobre la URL objetivo y entrega:

1. Un **Score de Calidad Digital (0–100)** accionable para el equipo.
2. Hallazgos con evidencia acotada (máx. 2 KB) y deduplicación a nivel de sitio.
3. Artefactos listos para **PR comments**, **Code Scanning** y reportes ejecutivos firmados.

---

## Las 6 dimensiones de inspección

| # | Dimensión | Qué valida (resumen) |
| :---: | :--- | :--- |
| 1 | **Security (DAST)** | Cabeceras HTTP, CSP/CORS, exposición sensible, formularios |
| 2 | **Accessibility** | WCAG 2.2 AA (contraste, ARIA, teclado, landmarks) |
| 3 | **Performance** | INP, LCP, CLS y optimización de assets |
| 4 | **SEO & GEO** | Canonical, JSON-LD, indexación, Open Graph |
| 5 | **Privacy** | Cookies (`Secure` / `HttpOnly` / `SameSite`), trackers, política |
| 6 | **Network & AI** | Protocolos HTTP/2–3 y readiness `/llm.txt` |

---

## Requisitos previos

- **Node.js** 20 o superior (recomendado; compatible ≥18)
- **npm** (incluido con Node)
- Acceso de red a la URL a auditar (staging / preview / producción)
- En CI: runners GitHub Actions con permiso para instalar Chromium (Playwright)

---

## Instalación local

```bash
git clone https://github.com/Favelas/CoreCheck.git
cd CoreCheck
npm install          # también instala Chromium vía postinstall
npm run build        # genera dist/
npm run typecheck    # debe quedar en 0 errores
npm test             # suite endurecida (contratos, attestation, policy, artefactos, Playwright, budget)
```

---

## Guía rápida del CLI

### Comando canónico

```bash
node dist/index.js run \
  --url https://tu-app.example.com \
  --html --pdf --sarif --json --markdown \
  --output-dir ./audit-results \
  --fail-on HIGH \
  --skip-license
```

> En producción comercial usa `--api-key` o el secreto `CORECHECK_API_KEY`.  
> `--skip-license` es solo para desarrollo / demos locales.

### Flags que más usarás (QA Lead)

| Flag | Para qué sirve | Ejemplo |
| :--- | :--- | :--- |
| `--url` | URL a auditar (obligatorio) | `--url https://staging.acme.com` |
| `--fail-on` | Severidad mínima que **rompe** el pipeline | `--fail-on HIGH` |
| `--formats` | Lista CSV de reportes | `--formats json,html,sarif,pdf` |
| `--html` / `--pdf` / `--sarif` / `--json` | Atajos de formato | `--html --pdf` |
| `--output-dir` | Carpeta de salida (con subcarpeta fechada) | `--output-dir ./audit-results` |
| `--flat-output` | Sin subcarpeta fechada (ideal CI) | `--flat-output` |
| `--max-pages` | Límite de páginas del crawler | `--max-pages 10` |
| `--concurrency` | Workers Playwright (auto-cap en CI/memoria baja) | `--concurrency 2` |
| `--baseline` | Suppressions / excepciones aceptadas | `--baseline .corecheckignore` |

También puedes usar el subcomando explícito: `node dist/index.js run ...` o `npm run audit -- --url ...`.

---

## Reportes generados (qué abrir y para quién)

Por defecto (sin `--flat-output`) los archivos quedan en:

`audit-results/<dominio>_<YYYY-MM-DD_HH-mm-ss>/`

| Archivo | Audiencia | Uso |
| :--- | :--- | :--- |
| `report.html` | QA / Engineering | Reporte visual navegable del escaneo |
| `interactive-dashboard.html` | QA Lead / stakeholders | Dashboard interactivo del Quality Score |
| `executive-report.pdf` | C-Level / Compliance | PDF ejecutivo con **attestation** (hash/QR) |
| `results.sarif` | Security / Platform | GitHub Code Scanning |
| `findings.json` | Automatización | Integraciones, tickets, análisis |
| `report.md` | Pull Requests | Comentario sticky en el PR |

### Exit codes (Quality Gate)

| Código | Significado |
| :---: | :--- |
| `0` | PASS — ningún hallazgo activo ≥ `--fail-on` |
| `1` | GATE FAIL — umbral de severidad superado (o `verify` fallido) |
| `2` | CONFIG — argumentos CLI inválidos / licencia / baseline |
| `3` | NETWORK — target inalcanzable / WAF / timeout de conectividad |
| `4` | ENGINE — fallo interno Playwright / OOM / crash del motor |

Verificación offline de attestation:

```bash
node dist/index.js verify --report ./audit-results/findings.json --key "$CORECHECK_ATTESTATION_SECRET"
```

---

## Integración CI/CD (GitHub Actions)

Este repositorio incluye:

| Workflow | Archivo | Propósito |
| :--- | :--- | :--- |
| CoreCheck CI & Quality Gate | [`.github/workflows/corecheck-ci.yml`](.github/workflows/corecheck-ci.yml) | typecheck, build, tests, smoke **duro** (artefactos obligatorios) |
| CoreCheck Quality Gate (producto) | [`.github/workflows/audit.yml`](.github/workflows/audit.yml) | self-check interno + SARIF |
| **Plantilla cliente (staging)** | [`docs/templates/corecheck-audit.client.yml`](docs/templates/corecheck-audit.client.yml) | gate real `--fail-on HIGH` |

**Para onboarding de un cliente nuevo**, sigue la guía paso a paso:

→ **[docs/ONBOARDING_GUIDE.md](docs/ONBOARDING_GUIDE.md)**

---

## Documentación

| Documento | Contenido |
| :--- | :--- |
| [Onboarding de clientes](docs/ONBOARDING_GUIDE.md) | 5 fases para activar CoreCheck en un repo cliente |
| [Commercial Playbook](docs/COMMERCIAL_PLAYBOOK.md) | Posicionamiento, SLA exit codes, handoff Sales→CS |
| [Escalabilidad Enterprise](docs/ENTERPRISE_SCALING_GUIDE.md) | DoD interno, baselines, roadmap v1.1 |
| [Arquitectura](docs/ARCHITECTURE.md) | Diagrama del motor (CLI → inspectors → exporters) |
| [Contributing](docs/CONTRIBUTING.md) | Reglas para contribuidores internos |
| [Índice docs](docs/README.md) | Mapa de toda la documentación |

---

## Scripts npm útiles

| Script | Descripción |
| :--- | :--- |
| `npm run typecheck` | TypeScript sin emitir (`tsc --noEmit`) — **0 errores obligatorio** |
| `npm run build` | Compila a `dist/` |
| `npm test` | typecheck + suite endurecida (SARIF, attestation, policy, artefactos, Playwright, ResourceBudget, WAF retry, E2E matrix) |
| `npm run audit` | Lanza la CLI vía `tsx` (pasa flags después de `--`) |
| `npm run reports:prepare` | Prepara carpetas `shared_reports` para Vercel |

---

## Alcance v1.0 (congelado)

**Incluido hoy:** Quality Gate unificado, deduplicación site-level, attestation + `verify`, exit codes 0–4, INFRA_FAILURE, CI duro, ResourceBudget, SARIF 2.1.0 validado, SPA crawl acotado, WAF backoff (403/429/503 → exit 3), E2E matrix, ticketing HTTP, webhooks HMAC, INP, `/llm.txt`.

**Fuera de alcance (post-revenue / v1.1+):** MFA/TOTP/Captcha interactivo, Dashboard SaaS multi-tenant, SSO/SAML, DAST ofensivo profundo, Action oficial de Marketplace.  
**Por qué MFA queda pendiente:** no es determinista en CI, induciría anti-patrones de seguridad (secrets 2FA en runners) y el workaround `--auth-state` ya cubre audits autenticados. Detalle en [ENTERPRISE_SCALING_GUIDE §4.1](docs/ENTERPRISE_SCALING_GUIDE.md).

### Runners CI (memoria)

En GitHub Actions (≈ 2 vCPU / 7 GB) CoreCheck aplica **ResourceBudget**:

- Hard cap de concurrencia = **2** (aunque pidas más)
- Chromium con `--disable-dev-shm-usage`
- Log de aviso: `[ResourceBudget] Concurrency capped …`

Para runners pequeños usa `vars.CORECHECK_CONCURRENCY=1` en la plantilla cliente.

---

## Licencia

Uso propietario — CoreCheck v1.0. Contactar al equipo comercial para API keys y planes.
