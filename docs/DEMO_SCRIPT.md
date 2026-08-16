# Demo script — 10 minutos (Design Partner)

**Meta:** el buyer ve *su* historial en `/viewer/`, no un ZIP de HTML.  
Ancla: DoD de `EXECUTIVE.md` §5.

## Antes de la llamada (vendedor)

- [ ] Staging API arriba (`GET /` → `status: ok`, `persistence: postgres`)
- [ ] `CORECHECK_API_KEY` de demo (o key mintada `POST /api/admin/api-keys`)
- [ ] Viewer abre en el browser del presentador
- [ ] Segunda key / segundo tenant lista para mostrar aislamiento (404)

## Minuto a minuto

| Min | Acción | Señal de éxito |
| ---: | :--- | :--- |
| 0–1 | Abrir Viewer vacío / con runs previos del tenant demo | Login con API key en sessionStorage |
| 1–4 | Correr CLI o disparar GHA `workflow_dispatch` con `--upload` | Log `[Upload] reportId=…` |
| 4–5 | Refresh Viewer → aparece el reporte (score, gate) | Misma `url` filtrable |
| 5–7 | Segundo run (mismo URL) → Trends + Diff last-2 | `scoreDelta` ≠ null o diff findings |
| 7–8 | `POST /api/reports/:id/verify` | `hashMatches: true` |
| 8–9 | Cambiar a otra API key / tenant | El `reportId` da **404** (no 403) |
| 9–10 | Mensaje de cierre | “Quality Gate + historial tenant — el CI ya alimenta el dashboard” |

## Comandos copy-paste (local → staging)

```powershell
$API = "https://YOUR-APP.fly.dev"
$KEY = "YOUR_BOOTSTRAP_KEY"

$env:CORECHECK_UPLOAD = "true"
$env:CORECHECK_API_URL = $API
$env:CORECHECK_API_KEY = $KEY

# Run 1
npx tsx src/cli/index.ts run --url https://example.com --skip-license --upload --fail-on HIGH --max-pages 2

# Run 2 (genera delta)
npx tsx src/cli/index.ts run --url https://example.com --skip-license --upload --fail-on HIGH --max-pages 2
```

Abre: `$API/viewer/` → pega la key → filtra `example.com` → Diff.

## Qué no decir

- “Vamos a construir el dashboard” (ya está).
- “Incluye SSO / MFA / Checks API” (Slice 4–5 — fuera de v1 demo).
- “Sustituye pentest” (Quality Gate de release, no AppSec ofensivo).
