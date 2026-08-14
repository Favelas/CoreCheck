# SOC2-oriented controls checklist — CoreCheck API

Narrativa de controles mapeable a TSC (Trust Services Criteria). **No es una certificación**; es evidencia de diseño para due diligence.

| Control area | Criterio TSC (ref.) | Implementación actual | Evidencia |
| :--- | :--- | :--- | :--- |
| **Access control** | CC6.1 | Bearer / `X-API-Key`; `/api/*` exige key; health/metrics/viewer estáticos públicos | `requireApiKey`, contract tests 401 |
| **Tenant isolation** | CC6.1 | `accountId` binding; cross-tenant → **404** (sin leak de existencia) | Phase 1.2 tests |
| **Secret handling** | CC6.1 / C1 | Denylist de campos sensibles en ingest (`apiKey`, tokens, passwords) | SEC-API-01 tests |
| **Change management** | CC8.1 | CI path-filter: typecheck + tests + build en `corecheck-api` | `.github/workflows/corecheck-api.yml` |
| **Logging / monitoring** | CC7.2 | JSON access logs + `x-request-id`; `/metrics` (5xx, latency, 429) | `requestContext`, `metrics` |
| **Availability / DoS** | A1.2 | Rate limit `/api` (default 120/min); body JSON 1mb | `rateLimit`, `express.json` |
| **Integrity** | PI1.1 | SHA-256 `contentHash` + `POST …/verify`; HMAC opcional | Phase 2 |
| **Retention** | C1.2 | `CORECHECK_RETENTION_DAYS` + purge on boot | `ops/retention.ts` |
| **Persistence** | A1.2 | memory / file / Postgres (DIP `ReportsRepository`) | Phase 3.x |

## Gaps explícitos (roadmap)

- Rotación formal de API keys / mTLS en edge
- Audit log append-only inmutable
- Field-level encryption at rest
- Alerting externo (PagerDuty/Slack) sobre `errors5xx`
- MFA / SSO para operadores humanos (viewer hoy usa API key de tenant)

## RTO / RPO (definición operativa)

| Objetivo | Valor target (v1 Control Plane) | Notas |
| :--- | :--- | :--- |
| **RTO** | ≤ 60 min | Redeploy Node + restore volume / Postgres |
| **RPO** | file: last fsync on disk; postgres: WAL / backup policy del host | Sin multi-AZ aún — documentar en cliente |
