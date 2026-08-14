# Threat Model — CoreCheck API Control Plane (STRIDE summary)

**Scope:** `corecheck-api` ingest/query surface (Phases 1–4).  
**Not in scope:** CoreCheck CLI DAST engine, customer target apps.

| Category | Threat | Mitigación actual | Residual |
| :--- | :--- | :--- | :--- |
| **S**poofing | API key robada / reutilizada | Bearer / X-API-Key + tenant binding | Rotación de keys, mTLS edge |
| **T**ampering | Alterar reporte en store | `contentHash` + verify; HMAC opcional | Firmas por tenant, WORM storage |
| **R**epudiation | Negar ingest | Access logs JSON + `x-request-id` | Audit log append-only |
| **I**nfo disclosure | Cross-tenant read / secret echo | accountId scope (404) + denylist secrets | Field-level encryption |
| **D**oS | Flood /api | Rate limit 120/min + body 1mb | Edge WAF, Redis limiter |
| **E**levation | Forjar accountId / id | Server-owned fields stripped | IAM roles / scoped tokens |

**Trust boundaries:** Internet → TLS terminator → Node process → file/Postgres volume.  
**Data classes:** audit URLs, findings JSON, integrity hashes — treat as confidential customer data.

**Ops exit criteria (Fase 4):** ver [INCIDENT_RUNBOOK.md](./INCIDENT_RUNBOOK.md) (RTO/RPO en [SOC2_CONTROLS.md](./SOC2_CONTROLS.md)).  
**UI:** `/viewer/` es superficie pública de assets; **no** expone reportes sin API key en el cliente.
