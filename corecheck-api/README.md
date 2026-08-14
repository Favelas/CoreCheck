# CoreCheck API (Control Plane)

Express Control Plane para ingestión y consulta de reportes CoreCheck: auth por API key, multi-tenant, integridad SHA-256/HMAC, persistencia pluggable y ops (métricas, rate limit, retention).

## Quick start

```powershell
cd corecheck-api
$env:CORECHECK_API_KEY="cc_dev_local"
npm run dev
```

- Health: `GET http://localhost:3000/`
- Metrics: `GET http://localhost:3000/metrics`
- Viewer: `http://localhost:3000/viewer/`
- Reports: `Authorization: Bearer cc_dev_local` en `/api/reports`

## Variables de entorno

| Variable | Rol |
| :--- | :--- |
| `CORECHECK_API_KEY` / `CORECHECK_API_KEYS` | `key` o `key:accountId` (multi) |
| `CORECHECK_PERSISTENCE` | `memory` \| `file` \| `postgres` (default `file`) |
| `CORECHECK_DATA_DIR` | Directorio store file |
| `DATABASE_URL` / `POSTGRES_*` | Postgres |
| `CORECHECK_REPORT_HMAC_SECRET` | HMAC opcional al sellar |
| `CORECHECK_RETENTION_DAYS` | Purge al boot si `>0` |
| `PORT` | Default `3000` |

## Calidad

```powershell
npm run typecheck
npm test
```

CI: `.github/workflows/corecheck-api.yml` (typecheck + tests memory + build).

## Docs ops / compliance

- [Threat model (STRIDE)](docs/THREAT_MODEL.md)
- [SOC2-oriented controls](docs/SOC2_CONTROLS.md)
- [Incident runbook](docs/INCIDENT_RUNBOOK.md)
