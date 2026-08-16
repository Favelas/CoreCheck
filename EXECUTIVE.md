# EXECUTIVE.md — CoreCheck Executive Summary

**Alineación negocio / inversión / arquitectura.**  
**Producto:** CoreCheck v1.0 — plataforma SaaS B2B de observabilidad y auditoría de calidad E2E.  
**Owner:** Fabian Velasquez — Lead Architect & Founder  
**Anclaje de código:** 2026-08-15

---

## 1. Executive Summary

CoreCheck es un **Quality Gate unificado** para pipelines CI/CD: un motor CLI (Playwright + TypeScript) que audita una URL en seis dimensiones (Security DAST, WCAG 2.2 AA, Performance, Privacy, SEO/GEO, AI readiness) y un Control Plane Express (`corecheck-api`) que ingiere, aísla por tenant y expone historial.

No es un pentest, ni un IdP, ni un dashboard de marketing. Es el sistema que responde, con exit code estable y evidencia firmada, a una sola pregunta de release: **¿este cambio rompe el umbral de calidad digital que acordamos?**

**Lo que un buyer compra hoy**

- Un gate de PR (`ExitCode` 0–4) que no miente en verde.  
- Artefactos accionables: HTML, Markdown, SARIF 2.1.0, JSON, PDF con attestation.  
- Un Control Plane multi-tenant (`accountId`) con integridad SHA-256 / HMAC-SHA256.  
- Un Viewer estático (`/viewer/`) que muestra **solo** reportes ingeridos del tenant autenticado.

**Lo que aún no se debe prometer en un SOW**

- SaaS gestionado en producción con Postgres y keys rotables como default (el código existe; la activación no).  
- SSO/MFA para operadores humanos.  
- Webhooks originados en la API o GitHub Checks API.  
- Sustituto de pentest ofensivo o de un programa de compliance certificado.

---

## 2. Análisis de Madurez del Producto (Gap Analysis)

Escala: **0** = no existe · **3** = código de contrato · **5** = listo para demo local · **7** = listo para Design Partner · **10** = listo para revenue recurrente.

| Dimensión | Score | Estado en código | Brecha que bloquea dinero |
| :--- | :---: | :--- | :--- |
| **Ingestión CLI → API** | **7** | `ReportsClient.uploadReport` → `POST /api/reports`. Flags `--upload` / `--upload-url` / `--upload-strict`. Payload `CreateReportInput` mapeado desde `AuditReportBundle`. Soft-fail por defecto. | El upload es **opt-in**. El template CI canónico aún no lo trata como camino de pago. License Plane (`src/server :8787`) y Reports Plane (`corecheck-api :3000`) son procesos distintos; `SaaSApiClient` default `https://api.corecheck.app` no está unificado. |
| **UX (Viewer / Trends)** | **6** | Viewer HTML/CSS/JS en `public/viewer/`. Consume `GET /api/reports`, `insights/trends` (`TrendsResponse`), `insights/diff` (`ReportDiffResponse`). Sparkline, filtros, Diff last-2, `#reportId`. | Sin SSO. API key en `sessionStorage`. No hay portfolios multi-URL ni export PDF desde el dashboard. `docs/COMMERCIAL_PLAYBOOK.md` aún declara “Dashboard SaaS multi-tenant” fuera de alcance — documento comercial **desactualizado** respecto al Viewer. |
| **Plataforma (Postgres / Keys)** | **6** | DIP `ReportsRepository` + `ApiKeyRepository`. Modos `memory` \| `file` \| `postgres`. Admin `POST/GET/DELETE /api/admin/api-keys`. Migraciones `reports` / `api_keys`. | Default de runtime = **`file`**. Keys dinámicas son efímeras fuera de Postgres. No hay `fly.toml` / Render / Neon en repo. Rate limit in-process (se pierde en multi-instancia). |
| **Integraciones (Webhooks / CI)** | **6** | CLI: `WebhookNotifier` (Slack/Teams/generic + HMAC). `TicketClient` (Jira/Azure/GitLab, dry-run default). SARIF → Code Scanning. Workflows `.github/workflows/*`. | Cero GitHub Checks API. La API **no** emite webhooks al persistir un `CoreCheckReport`. Ticketing HTTP es opt-in y exige credenciales del cliente. |

### Lectura ejecutiva del gap

El **motor CLI está Enterprise Hardened**. El **Control Plane está demo-ready en local**. El producto SaaS (historial + tenant + dashboard + cuota) **ya tiene el flywheel implementado en código**, pero no está empaquetado como el camino por defecto de un cliente de pago.

Eso es una brecha de **go-to-market y activación**, no de invención. El riesgo de inversión no es “¿podemos construir ingestión?” — ya está. El riesgo es “¿el primer Design Partner ve el historial en `/viewer/` a los 45 minutos, o solo un ZIP de HTML?”

### Matriz de decisión (qué financiar ahora)

| Si invertimos en… | Efecto comercial | Dependencia |
| :--- | :--- | :--- |
| Encender upload en el template CI + un secret `CORECHECK_API_URL` | El Viewer deja de ser teatro: cada PR llena el historial | **Hecho en template** — falta deploy staging del vendedor ([`docs/STAGING_DEPLOY.md`](./docs/STAGING_DEPLOY.md)) |
| `CORECHECK_PERSISTENCE=postgres` en staging (Neon/Supabase) | Keys y reportes sobreviven deploys; se puede rotar tenants | Scaffold Fly/Render listo — falta `fly deploy` / Blueprint |
| Narrativa comercial actualizada (playbook + demo script) | Sales deja de vender “solo CLI” | [`docs/DEMO_SCRIPT.md`](./docs/DEMO_SCRIPT.md) |
| Webhooks desde la API / GitHub Checks | Nice-to-have post-primer-contrato | Slice 4 — **después** del flywheel |

---

## 3. Estrategia de Despliegue & Eficiencia de Costos

### Desarrollo: $0 USD

| Recurso | Costo | Cómo |
| :--- | ---: | :--- |
| CLI + tests | $0 | Node + `tsx` + `InMemoryReportsStore` |
| API local | $0 | `CORECHECK_PERSISTENCE=file` · `CORECHECK_API_KEY=cc_dev_local` |
| Viewer | $0 | `http://localhost:3000/viewer/` |
| Postgres opcional | $0 | `corecheck-api/docker-compose.yml` (`postgres:16-alpine`) |
| License Plane demo | $0 | `npm run control-plane` → `:8787` |

No se requiere cuenta cloud, Redis, ni cola para desarrollar ni para CI interno (`corecheck-api.yml` corre typecheck + tests memory + build).

### Staging / primer prod (Lean)

Diferir AWS App Runner / RDS / multi-AZ hasta que existan Design Partners corporativos con NDA y volumen.

| Capa | Opción Lean | Señal para subir de liga |
| :--- | :--- | :--- |
| Compute API | Fly.io o Render (un proceso Node, `PORT`) | >1 región o SLA contractual 99.9% |
| Postgres | Neon o Supabase (un branch staging + un prod) | Retención >90 días + RPO formal |
| Secretos | Env del host: `CORECHECK_API_KEY`, `CORECHECK_REPORT_HMAC_SECRET`, `DATABASE_URL` | Vault / OIDC workload identity |
| Artefactos HTML | Vercel estático (`reports/shared_reports/vercel.json`) o el propio `/viewer/` | CDN + SSO |
| Observabilidad | `GET /metrics` + logs JSON `x-request-id` | PagerDuty cuando `errors5xx` importe |

**RTO/RPO ya documentados** (no certificados): RTO ≤ 60 min; RPO = last fsync (file) o WAL del host (postgres). Ver `corecheck-api/docs/SOC2_CONTROLS.md`.

### Qué no comprar todavía

- Cluster Kubernetes, Redis rate-limiter, bus de eventos, data warehouse.  
- Field-level encryption y audit log WORM — gaps explícitos del threat model, no blockers de primer contrato.  
- Un segundo proveedor de DAST. El motor ya cubre el 80% del ruido de calidad digital por PR.

---

## 4. Definición de Ingestión Activa (Flywheel de Producto)

### Por qué Slice 1 es la prioridad estratégica #1

Sin ingestión, CoreCheck es un **binario de CI** (commodity defendible, pero commodity). Con ingestión, CoreCheck es una **plataforma**: cada corrida incrementa el valor del tenant (`TrendPoint`, `scoreDelta`, `gateFailRate`, diffs de `FindingRef`).

Eso es el flywheel B2B:

```text
CI run (CLI) → CreateReportInput → POST /api/reports
      → CoreCheckReport (id, accountId, contentHash)
            → Viewer trends / diff
                  → conversación de renovación (“el score bajó 12 pts en staging”)
```

El código del flywheel **ya existe**:

1. `isUploadEnabled(--upload | CORECHECK_UPLOAD)`  
2. `buildCreateReportInput(bundle)` — top 100 findings, descriptions ≤ 500, sin secretos  
3. `ReportsClient.fromEnv` — `X-API-Key` + `Authorization: Bearer` + `x-request-id`  
4. `createReport` sella integridad y asigna `accountId`  
5. Viewer llama `GET /api/reports/insights/trends`

**Lo que falta no es un cliente HTTP.** Falta tratar ese camino como el *default comercial*:

- Template `docs/templates/corecheck-audit.client.yml` con `--upload` + `CORECHECK_API_URL`.  
- Demo script de 10 minutos: auditar `example.com` → ver `reportId` → abrir `/viewer/` → Diff last-2.  
- Un solo base URL documentado (hoy hay cuatro candidatos: `CORECHECK_REPORTS_API_URL`, `CORECHECK_UPLOAD_URL`, `CORECHECK_API_URL`, y el default de licencia `https://api.corecheck.app`).

Hasta que un prospecto vea **su** historial, no el HTML de una corrida, no hay tracción SaaS — hay tracción de herramienta.

### Criterio de “ingestión activa”

Se considera activa cuando, en un entorno de staging del vendedor:

1. Un `corecheck run --upload` produce HTTP 201 con `CoreCheckReport.id`.  
2. `GET /api/reports` del mismo `accountId` lista ese id.  
3. Un segundo run de la misma `url` produce `scoreDelta` ≠ null en `TrendsResponse`.  
4. Cross-tenant con otra key devuelve 404, no 403 con leak.  
5. El fallo de upload **no** convierte un GATE PASS en rojo (soft-fail), salvo `--upload-strict`.

---

## 5. Métricas de Éxito Comercial y Criterios de Listo (DoD)

### Métricas de tracción (post-activación)

| Métrica | Definición operativa | Señal de producto-market |
| :--- | :--- | :--- |
| **Runs ingeridos / semana / tenant** | Filas `CoreCheckReport` por `accountId` | ≥ 5 runs/semana = el gate está en el PR real |
| **Gate fail rate** | `TrendsResponse.gateFailRate` | Distinto de 0 y de 1 — el umbral `--fail-on` se usa, no se ignora |
| **Score delta** | `scoreDelta` entre `latest` y `previous` | El buyer abre el Viewer sin que se lo pidamos |
| **Verify OK** | `POST /api/reports/:id/verify` → `valid: true` | Compliance puede firmar el PDF / hash |
| **Time-to-first-report** | Onboarding → primer 201 | ≤ 45 minutos (playbook actual) |
| **Upload error rate** | `maybeUploadAuditReport` `uploaded: false` | < 5% en staging del vendedor; soft-fail no esconde 401 sistemático |

### Definition of Done — listo para demos comerciales B2B

Una demo se puede agendar cuando **todos** estos checks son verdaderos en el ambiente del vendedor (no en la laptop de un ingeniero con flags secretos):

- [ ] `corecheck-api` arriba; `GET /` → `HealthResponse.status = ok` con `persistence` visible.  
- [ ] Bootstrap `CORECHECK_API_KEY` (o key mintada) ligada a un `accountId` de demo.  
- [ ] `npx tsx src/cli/index.ts run --url https://example.com --api-key <demo> --upload --upload-url <api>` → log `[Upload] reportId=…`.  
- [ ] `/viewer/` conecta con esa key, lista el reporte, pinta sparkline y permite Diff.  
- [ ] `POST /api/reports/:id/verify` responde `hashMatches: true`.  
- [ ] Segunda key / segundo tenant **no** ve el reporte (404).  
- [ ] Un run con hallazgo ≥ `--fail-on HIGH` sale `ExitCode.GATE_FAIL` (1) y el Viewer muestra `gateFailed`.  
- [ ] Webhook CLI opcional (`--webhook-url`) notifica Slack/Teams — demostrable, no bloqueante.  
- [ ] Narrativa verbal alineada: “Quality Gate + historial tenant”, no “vamos a construir el dashboard”.  
- [ ] Playbook comercial actualizado (Viewer + upload ya no son “out of scope”).  
- [ ] Scaffold deploy listo (`corecheck-api/Dockerfile`, `fly.toml`, `docs/STAGING_DEPLOY.md`) — **falta** el `fly deploy` / Blueprint del ambiente del vendedor.

### Definition of Done — listo para primer Design Partner (contrato)

Además de la demo:

- [ ] Staging del vendedor en Fly/Render + Neon/Supabase (`CORECHECK_PERSISTENCE=postgres`).  
- [ ] `POST /api/admin/api-keys` emite una key de CI del cliente; `DELETE` la revoca.  
- [ ] `CORECHECK_REPORT_HMAC_SECRET` activo; verify usa `HMAC-SHA256`.  
- [ ] Retention (`CORECHECK_RETENTION_DAYS`) acordada por escrito.  
- [ ] Template CI del cliente con `--upload` y secretos documentados en `docs/ONBOARDING_GUIDE.md`.  
- [ ] License gate real (no solo `cc_dev_*`) o waiver explícito de trial.

### Lo que *no* es DoD de demo

SSO, Redis, GitHub Checks, webhooks desde la API, field-level encryption, marketplace Action. Son Slice 4–5. Venderlos como “incluido en v1” es product theater — exactamente lo que `FOUNDER.md` prohíbe.

---

## 6. Veredicto para inversión / arquitectura

**Invertir en activación, no en invención.** El repositorio ya contiene el motor, el contrato `CreateReportInput`, el cliente de ingestión, el aislamiento por `accountId`, la integridad HMAC, el Viewer con trends/diff, y los adaptadores Postgres. El siguiente dólar debe hacer que **cada corrida de un prospecto aterrice en el Control Plane**. Ese es el único movimiento que convierte un CLI excelente en un SaaS B2B cobrable.

Detalle de ownership, guardrails y slices: [`FOUNDER.md`](./FOUNDER.md).
