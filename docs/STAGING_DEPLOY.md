# Staging lean — CoreCheck Control Plane

**Objetivo:** API + Postgres en la nube en menos de 1 hora para demos Design Partner (DoD de `EXECUTIVE.md`).  
**No** es multi-región ni SOC2 certificado — es el camino mínimo: Fly **o** Render + Neon.

## Arquitectura

```text
GitHub Actions (cliente)
  → corecheck run --upload --upload-url https://<api>
       → POST /api/reports  (CORECHECK_API_KEY)
            → Neon Postgres
                 → https://<api>/viewer/
```

## 1. Neon (Postgres)

1. Crea un proyecto Neon (free branch `staging`).
2. Copia el connection string (`postgresql://...`) → será `DATABASE_URL`.
3. No hace falta correr migraciones a mano: al boot con `CORECHECK_PERSISTENCE=postgres`, `index.ts` aplica `001_reports` / `002_api_keys`.

## 2A. Fly.io (recomendado)

Prerrequisitos: [flyctl](https://fly.io/docs/hands-on/install-flyctl/) + cuenta.

```powershell
cd corecheck-api
fly auth login
# Si el nombre está tomado: fly apps create corecheck-api-<suffix> y edita fly.toml → app
fly apps create corecheck-api

fly secrets set `
  CORECHECK_API_KEY="cc_stg_<random>" `
  CORECHECK_PERSISTENCE="postgres" `
  DATABASE_URL="postgresql://..." `
  CORECHECK_REPORT_HMAC_SECRET="<random-32+>" `
  CORECHECK_RETENTION_DAYS="90"

fly deploy
fly status
curl https://corecheck-api.fly.dev/
```

Viewer: `https://<app>.fly.dev/viewer/`

## 2B. Render (alternativa)

1. New → Blueprint → selecciona `corecheck-api/render.yaml`.
2. Rellena secrets: `CORECHECK_API_KEY`, `DATABASE_URL`, `CORECHECK_REPORT_HMAC_SECRET`.
3. Deploy; health check = `GET /`.

## 3. Verificación smoke (DoD mínimo)

```powershell
$API = "https://corecheck-api.fly.dev"   # o tu URL Render
$KEY = "cc_stg_..."

# Health
Invoke-RestMethod "$API/"

# Ingest
$body = @{
  url = "https://example.com"
  score = 80
  summary = @{ critical = 0; high = 0; medium = 1; low = 0; info = 0 }
  findings = @()
  gateFailed = $false
  failOn = "HIGH"
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method POST -Uri "$API/api/reports" `
  -Headers @{ Authorization = "Bearer $KEY" } `
  -ContentType "application/json" `
  -Body $body

# CLI (desde monorepo)
$env:CORECHECK_UPLOAD = "true"
$env:CORECHECK_API_URL = $API
$env:CORECHECK_API_KEY = $KEY
npx tsx src/cli/index.ts run --url https://example.com --skip-license --upload --max-pages 2
```

Checklist completo: [DEMO_SCRIPT.md](./DEMO_SCRIPT.md).

## 4. Secrets del repo cliente (GitHub)

| Secret / var | Uso |
| :--- | :--- |
| `CORECHECK_API_URL` | Base URL del Control Plane (sin path `/api`) |
| `CORECHECK_API_KEY` | Key de tenant (bootstrap o mintada) |
| `vars.CORECHECK_TARGET_URL` | Staging del cliente |
| `vars.CORECHECK_VIEWER_URL` | Opcional: URL del Viewer en el comentario de PR |

Plantilla: [`templates/corecheck-audit.client.yml`](./templates/corecheck-audit.client.yml) — si `CORECHECK_API_URL` está definido, el gate hace `--upload` (soft-fail).

## 5. Coste orientativo

| Recurso | Orden de magnitud |
| :--- | :--- |
| Fly shared 512 MB + auto-stop | ~$0–5/mes en tráfico demo |
| Render free web | $0 (cold starts) |
| Neon free | $0 hasta límites del plan |

Subir de liga (multi-AZ, Redis, PagerDuty) solo con Design Partner firmado — ver `EXECUTIVE.md` §3.
