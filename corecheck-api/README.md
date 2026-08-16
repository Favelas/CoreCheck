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
- Admin keys: `POST/GET/DELETE /api/admin/api-keys` (mint / list / revoke)

## Staging lean (Fly / Render + Neon)

Scaffold listo en este directorio:

| Archivo | Uso |
| :--- | :--- |
| `Dockerfile` | Imagen multi-stage Node 20 |
| `fly.toml` | Fly.io (auto-stop, health `GET /`) |
| `render.yaml` | Blueprint Render alternativo |
| `../docs/STAGING_DEPLOY.md` | Pasos Neon + secrets + smoke |
| `../docs/DEMO_SCRIPT.md` | Demo Design Partner 10 min |

```powershell
fly secrets set CORECHECK_API_KEY=... DATABASE_URL=... CORECHECK_PERSISTENCE=postgres CORECHECK_REPORT_HMAC_SECRET=...
fly deploy
```

Migraciones SQL corren al boot cuando `CORECHECK_PERSISTENCE=postgres`.

## Variables de entorno

| Variable | Rol |
| :--- | :--- |
| `CORECHECK_API_KEY` / `CORECHECK_API_KEYS` | Bootstrap `key` o `key:accountId` (multi) |
| `CORECHECK_PERSISTENCE` | `memory` \| `file` \| `postgres` (default `file`) |
| `CORECHECK_DATA_DIR` | Directorio store file |
| `DATABASE_URL` / `POSTGRES_*` | Postgres (reportes + api_keys hasheadas) |
| `CORECHECK_REPORT_HMAC_SECRET` | HMAC opcional al sellar |
| `CORECHECK_RETENTION_DAYS` | Purge al boot si `>0` |
| `PORT` | Default `3000` |

## API keys dinámicas (Slice 2)

1. Arranca con bootstrap env (`CORECHECK_API_KEY`).
2. `POST /api/admin/api-keys` `{ "label": "ci-runner" }` → responde `apiKey` **una sola vez**.
3. Usa esa key en CLI (`--api-key` / upload) o viewer.
4. `DELETE /api/admin/api-keys/:id` revoca (hash queda inválido).

En `postgres` las keys persisten en tabla `api_keys` (solo SHA-256). En `memory`/`file` el repo de keys es in-memory (reinicio = pierdes keys dinámicas; el bootstrap env sigue).

## Dashboard insights (Slice 3)

- `GET /api/reports?url=&gateFailed=&failOn=&q=&since=&limit=`
- `GET /api/reports/insights/trends?url=`
- `GET /api/reports/insights/diff?url=` o `?baseId=&targetId=`
- Viewer: `http://localhost:3000/viewer/` (filtros, sparkline, Diff last 2, deep-link `#reportId`)

```powershell
$env:CORECHECK_UPLOAD="true"
$env:CORECHECK_API_URL="http://localhost:3000"
npx tsx ../src/cli/index.ts run --url https://example.com --skip-license --api-key cc_dev_local --upload
```

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
