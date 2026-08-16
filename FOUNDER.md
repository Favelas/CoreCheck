# FOUNDER.md — CoreCheck North Star

**Documento de visión estratégica.** Fuente de verdad para producto, arquitectura y capital.  
**Owner:** Fabian Velasquez — Lead Architect & Founder  
**Código de referencia:** `corecheck` (CLI) · `corecheck-api` (Control Plane) · `src/server` (License Plane)  
**Fecha de anclaje:** 2026-08-15

---

## 1. Visión & Propósito Comercial (The "Why")

### El dolor

Los equipos de QA, Platform y AppSec encadenan 4–5 herramientas distintas (DAST, axe/Lighthouse, privacy scanners, SEO crawlers, reporters ad-hoc) para decidir si un PR o un release es *shippable*. El resultado es ruido, exit codes inconsistentes, evidencia que no cabe en un runner de CI, y un reporte que nadie del C-level puede firmar.

CoreCheck existe para colapsar esa cadena en **un Quality Gate unificado**: una pasada Playwright sobre la URL objetivo, un Digital Quality Score (0–100), hallazgos con evidencia acotada (máx. 2 KB), artefactos listos para PR/Code Scanning, y un Control Plane multi-tenant que **guarda el historial** — no solo el último HTML estático.

### UVP frente a reportadores tradicionales

| Reportador tradicional | CoreCheck |
| :--- | :--- |
| HTML/PDF muerto por corrida | Ingestión a `POST /api/reports` → historial por `accountId` |
| Un dominio (solo a11y, o solo headers) | Seis dimensiones: Security, A11y (WCAG 2.2 AA), Performance, SEO/GEO, Privacy, Network/AI (`/llm.txt`) |
| “El job falló” genérico | Exit codes estables: `0` PASS · `1` GATE_FAIL · `2` CONFIG · `3` NETWORK · `4` ENGINE |
| Evidencia ilimitada (OOM en CI) | Presupuesto de evidencia: snippet ≤ 2 KB; ingest trunca a 100 findings / 500 chars |
| Confianza por captura de pantalla | Attestation SHA-256 / HMAC-SHA256 + `POST /api/reports/:id/verify` |
| Dashboard sin datos | Viewer estático en `/viewer/` que **solo** pinta lo que el tenant autenticó |

### Perfil de Cliente Ideal (ICP)

1. **Primary:** QA Lead / Platform Engineer en SaaS B2B con staging HTTP(S) y GitHub Actions.  
2. **Economic buyer:** VP Engineering / Head of Quality que necesita un gate de release defendible ante compliance (SOC2, ISO 27001, WCAG/ADA).  
3. **Anti-ICP (no vender hoy):** apps con MFA/Captcha/SSO interactivo como único camino; pentest ofensivo profundo; marketplace Action como único canal.

Tiers comerciales ya modelados en `src/types/license.ts`:

| `SubscriptionTier` | `maxPagesPerRun` | `maxRunsPerMonth` | Módulos |
| :--- | ---: | ---: | :--- |
| `GROWTH` | 10 | 50 | `compliance_mapping`, `webhooks` |
| `ENTERPRISE_CORE` | 50 | 500 | + `pdf_report`, `active_fuzzing`, `multi_domain` |
| `ENTERPRISE_GOVERNANCE` | 250 | 5000 | + `ticketing` |

### Modelo de monetización SaaS B2B

- **Licencia por API key** (`--api-key` / `CORECHECK_API_KEY`) → `LicenseInfo.accountId` + entitlements.  
- Keys de desarrollo `cc_dev_*` para demos locales; keys dinámicas de producción vía `POST /api/admin/api-keys` (plaintext **una sola vez**, persistido como SHA-256).  
- Upsell por módulo (`pdf_report`, `ticketing`, `active_fuzzing`) y por cuota (`PAGE_LIMIT_EXCEEDED` auto-cap, no silent fail).  
- Telemetría privacy-preserving (`UsageTelemetryEvent`, hostname hasheado) — no es el producto; es el medidor de cuota.

---

## 2. Arquitectura de Alto Nivel & Tech Stack Core

```text
┌──────────────────────────── CLI (package: corecheck) ────────────────────────────┐
│  Commander · Playwright Chromium · @axe-core/playwright                          │
│  AuditRunner → Inspectors → FindingConsolidator → PolicyEngine → Reporters       │
│  ReportsClient ──POST /api/reports──►  corecheck-api                             │
│  SaaSApiClient ──/v1/licenses|telemetry──►  src/server (License Plane :8787)     │
│  WebhookNotifier (Slack/Teams/generic HMAC) · TicketClient (Jira/Azure/GitLab)   │
└──────────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
     ┌──────────────────────────┐         ┌─────────────────────────────┐
     │ corecheck-api (Express 5)│         │ src/server ControlPlaneRouter│
     │ :3000  Control Plane     │         │ :8787  License / Quota /    │
     │ reports · keys · metrics │         │        Telemetry (http nativo)│
     └────────────┬─────────────┘         └─────────────────────────────┘
                  │
     persistence: InMemoryReportsStore | JsonFileReportsStore | PostgresReportsRepository
     api keys:    InMemoryApiKeyRepository | PostgresApiKeyRepository
                  │
                  ▼
     /viewer/  (HTML/CSS/JS estático — sessionStorage API key, cero secretos en URL)
```

### Stack real (no aspiracional)

| Capa | Tecnología en repo | Notas |
| :--- | :--- | :--- |
| CLI | Node.js ≥18 (README pide 20+), TypeScript 5.4, Commander 15, Playwright 1.42, pdfkit, qrcode | `bin.corecheck` → `dist/index.js` |
| API | Express 5.2, TypeScript 5.8, `pg` 8.23 | Factory `createApp()` con DI |
| Persistencia | `CORECHECK_PERSISTENCE=memory\|file\|postgres` (default **`file`**) | Puerto `ReportsRepository` |
| Postgres | `postgres:16-alpine` en `corecheck-api/docker-compose.yml` | Tablas `reports`, `api_keys`, `schema_migrations` |
| Viewer | Estático en `corecheck-api/public/viewer/` | Servido en `/viewer` |
| Tests | Node test runner + `tsx` | CLI y API en milisegundos con mocks / memory |
| Artefactos estáticos | `reports/shared_reports/vercel.json` | Headers de no-index / CSP para HTML compartidos |

### Contratos de datos (nombres exactos)

**Ingest (`CreateReportInput`)** — CLI `src/services/report_payload.ts` alineado a `corecheck-api/src/types/contracts.ts`:

- `url` (obligatorio) · `failOn?` · `findingsCount?` · `summary?`  
- `findings?: Vulnerability[]` (`id`, `ruleId`, `title`, `severity`, `description`, `url?`, `selector?`)  
- `metrics?: MetricScore[]` (`dimension`, `score`, `maxScore`)  
- Extensiones CLI que viajan como `[key: string]`: `timestamp`, `gateFailed`, `digitalQualityScore`, `maxCvssScore`, `severityCounts`, `scannedPages`, `environment`, `suppressedCount`, `findingsTruncated`

**Persistido (`CoreCheckReport`)** — el servidor es dueño de:

- `id` · `createdAt` · `accountId` · `contentHash` · `integrityAlgorithm` (`SHA-256` \| `HMAC-SHA256`) · `hmacSignature?`

**Auth & correlación**

- Headers: `X-API-Key` **o** `Authorization: Bearer <key>` (`extractBearerOrApiKey`)  
- Binding: `CORECHECK_API_KEYS=key:accountId,...` o `CORECHECK_API_KEY` + `CORECHECK_ACCOUNT_ID` (default `tenant_default`)  
- Correlación: `x-request-id` (inbound o `randomUUID()`; siempre echo en response)  
- Rate limit: `/api` → 120 req / 60s (in-memory por key/IP) · body JSON 1 MB  
- Sanitización edge: `validateReportBody` + denylist `SENSITIVE_REPORT_FIELD_NAMES` / `SERVER_OWNED_FIELD_NAMES` (SEC-API-01)

**Superficie HTTP de `corecheck-api`**

| Método | Ruta | Auth |
| :--- | :--- | :--- |
| `GET` | `/` | público — `HealthResponse` |
| `GET` | `/metrics` | público — `MetricsResponse` (sin PII) |
| `GET`/`POST` | `/api/reports` | tenant |
| `GET` | `/api/reports/insights/trends` | tenant — `TrendsResponse` |
| `GET` | `/api/reports/insights/diff` | tenant — `ReportDiffResponse` |
| `GET`/`POST` | `/api/reports/:id` · `/:id/verify` | tenant — 404 cross-tenant (sin leak) |
| `GET`/`POST`/`DELETE` | `/api/admin/api-keys` · `/:id` | tenant |
| estático | `/viewer/` | assets públicos; **datos solo con API key en el cliente** |

**License Plane (`src/server`)** — proceso separado, no Express:

- `POST /v1/licenses/validate` · `POST /v1/telemetry/usage` · `GET /v1/accounts/:id/status`  
- `POST /v1/accounts/:id/quota/renew` · `POST /v1/accounts/:id/revoke`

### Estándares de seguridad no negociables

1. **HMAC / integridad:** `sealReportIntegrity` / `verifyReportIntegrity`; secret `CORECHECK_REPORT_HMAC_SECRET`.  
2. **Aislamiento multi-tenant:** todo `ReportsRepository.*` y `ApiKeyRepository.*` filtra por `accountId`. Cross-tenant = 404.  
3. **Server-owned fields:** el cliente no puede inyectar `id`, `createdAt`, `accountId`, `contentHash`.  
4. **Attestation CLI:** `buildAttestation` (SHA-256 / HMAC) + comando `verify` offline.  
5. **Docs de due diligence:** `corecheck-api/docs/THREAT_MODEL.md` (STRIDE), `SOC2_CONTROLS.md`, `INCIDENT_RUNBOOK.md`.

---

## 3. Guardrails & Reglas No Negociables

### 1. Zero Product Theater

No se construye UI, dashboard ni “insights” que no consuman un flujo de ingestión real (`ReportsClient.uploadReport` → `POST /api/reports` → `CoreCheckReport`). El Viewer existe **porque** el Control Plane ya lista, filtra, verifica y calcula `TrendPoint` / diffs. Si no hay reporte ingerido, el workspace permanece vacío — no se mockean KPIs de marketing.

### 2. Multi-Tenancy por Diseño

`accountId` se resuelve en `requireApiKey` y se exige en cada controller (`requireAccountId`). Repositorios filtran; tests de contrato cubren 404 cross-tenant. Ningún endpoint de `/api/*` es “global”. Telemetría (`UsageTelemetryEvent`) lleva `accountId`, nunca URLs crudas.

### 3. Tests Fáciles y Deterministas

- CLI: `node --import tsx --test` sobre contratos, SARIF, exit codes, attestation, policy, artefactos, Playwright cleanup, ResourceBudget, HTTP retry, `ReportsClient` — **sin red real**.  
- API: suite en `corecheck-api/test/*` con `createApp({ persistence: 'memory', disableRateLimit })`.  
- `InMemoryReportsStore` / `InMemoryApiKeyRepository` son el default de test. Postgres se prueba contra contrato, no como gate de desarrollo diario.  
- Objetivo: milisegundos, no minutos. Playwright de motor se aísla; ingest se mockea con `fetchImpl`.

### 4. Desarrollo Lean Financiero

Entorno local = **$0 USD** hasta monetización activa:

- Persistencia `file` o `memory` — cero cloud.  
- `docker-compose` Postgres es **opt-in** (dev), no requisito.  
- Keys `cc_dev_*` + `--skip-license` para loops locales.  
- Producción inicial: Fly.io / Render + Neon / Supabase. AWS App Runner / RDS se difiere a Design Partners corporativos.

---

## 4. Roadmap por Slices de Valor

Estado anclado al código del 2026-08-15 — no a un backlog teórico.

### Slices 0–4 (Completados) — Control Plane fundacional

- API Express layered (`createApp`, middlewares, DIP de repositorios).  
- Observabilidad: `requestContext`, logs JSON `http_access`, `GET /metrics`.  
- Rate limit `/api` (120/60s) + body 1 MB.  
- Threat model STRIDE + controles orientados a SOC2 + incident runbook.  
- Viewer estático autenticado por API key (`sessionStorage`, nunca querystring).

### Slice 1 — Ingestión CLI → API (**código aterrizado; flywheel comercial pendiente**)

**Hecho en repo**

- `ReportsClient` → `POST /api/reports` (`User-Agent: CoreCheck-CLI-Reports/1.0`).  
- Flags: `--upload` · `--upload-url` · `--upload-strict` · env `CORECHECK_UPLOAD` / `CORECHECK_REPORTS_API_URL` / `CORECHECK_UPLOAD_URL` / `CORECHECK_API_URL`.  
- `buildCreateReportInput(AuditReportBundle)` + `maybeUploadAuditReport` (soft-fail default; `NETWORK` si `--upload-strict`).  
- Tests: `test/reports_client.test.ts`.

**Pendiente de producto:** desplegar staging del vendedor ([`docs/STAGING_DEPLOY.md`](./docs/STAGING_DEPLOY.md)), configurar secrets `CORECHECK_API_URL` + key en el cliente, y unificar License Plane + Reports Plane (hoy el template usa `--skip-license` cuando hay upload salvo `CORECHECK_REQUIRE_LICENSE=true`).

### Slice 2 — Plataforma: Postgres + API Keys dinámicas (**adaptadores listos; activación prod pendiente**)

**Hecho en repo**

- `PostgresReportsRepository` + `PostgresApiKeyRepository` + migraciones `001_reports.sql` / `002_api_keys.sql`.  
- Admin: `POST/GET/DELETE /api/admin/api-keys` (mint / list / revoke).  
- `docker-compose.yml` local + `npm run db:migrate`.

**Pendiente:** default de staging/prod = `postgres`; keys dinámicas hoy son **efímeras** en `memory`/`file` (solo el bootstrap env sobrevive un restart). Sin esto no hay rotación real de tenants.

### Slice 3 — Analytics (**API + Viewer listos; profundidad comercial pendiente**)

**Hecho en repo**

- `GET /api/reports` con filtros `url`, `failOn`, `gateFailed`, `q`, `since`, `limit`.  
- `GET /api/reports/insights/trends` → `TrendsResponse` (`totalRuns`, `gateFailRate`, `avgScore`, `scoreDelta`, `series: TrendPoint[]`).  
- `GET /api/reports/insights/diff` → `ReportDiffResponse` (`added` / `removed` / `regression`).  
- Viewer: sparkline, Diff last-2, deep-link `#reportId`.

**Pendiente:** portfolios multi-URL, ventanas temporales de negocio, y export ejecutivo desde el dashboard (hoy el PDF sigue siendo artefacto CLI).

### Slice 4 — Integraciones outbound (**CLI listo; Control Plane aún no emite**)

**Hecho en repo (lado CLI)**

- `WebhookNotifier`: Slack / Teams / generic + `X-CoreCheck-Signature` HMAC (`CORECHECK_WEBHOOK_SECRET`).  
- `TicketClient`: Jira Cloud, Azure Boards, GitLab (dry-run default; `--ticket-submit` opt-in).  
- SARIF 2.1.0 → GitHub Code Scanning (artefacto, no Checks API).

**Pendiente:** webhooks **originados en la API** al persistir un `CoreCheckReport`; GitHub Checks API; alerting ops sobre `errors5xx` (PagerDuty/Slack). No hay implementación de GitHub Checks en el repo.

### Slice 5+ (explícitamente fuera de v1)

- MFA / SSO para operadores del Viewer.  
- Field-level encryption at rest.  
- Rate limit Redis / edge WAF.  
- Audit log append-only.  
- Unificación License Plane + Reports Plane en un solo proceso.  
- Marketplace Action oficial.

---

## 5. Ownership

| Rol | Nombre | Responsabilidad |
| :--- | :--- | :--- |
| Lead Architect & Founder | **Fabian Velasquez** | North Star, contratos, Quality Gate, decisión de slice |
| Superficie CLI | `src/cli/index.ts` | Flags, exit codes, upload, license gate |
| Superficie API | `corecheck-api/src/app.ts` | Auth, tenant, persistencia, viewer |
| Contratos | `corecheck-api/src/types/contracts.ts` + `src/types/audit.ts` + `src/types/license.ts` | No romper retrocompatibilidad |

Toda desviación de estos guardrails (UI sin ingest, query sin `accountId`, test que requiera red/Postgres para el happy path, infra cara pre-revenue) requiere decisión explícita del Founder — no un PR “por si acaso”.
