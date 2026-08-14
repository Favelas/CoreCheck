# Incident runbook — CoreCheck API Control Plane

## Severidad rápida

| Sev | Señales | Acción inicial |
| :---: | :--- | :--- |
| **SEV-1** | `/` down; 5xx sostenido; data loss sospechada | Aislar tráfico, preservar logs, no rotar storage a ciegas |
| **SEV-2** | Rate limit masivo / abuse; auth 503 por misconfig | Ajustar limit / restaurar `CORECHECK_API_KEYS` |
| **SEV-3** | Integridad `verify` fallando en reportes aislados | Investigar tampering vs bug de canonicalize |

## Triage (5 minutos)

1. `GET /` — ¿`status=ok`? anotar `persistence`, `uptimeSeconds`, `version`.
2. `GET /metrics` — `errors5xx`, `rateLimited`, `avgLatencyMs`.
3. Correlacionar con access logs (`msg=http_access`, `requestId`).
4. Confirmar env: `CORECHECK_PERSISTENCE`, keys configuradas, `DATABASE_URL` si postgres.

## Contención

- **Auth rotura / key leak:** rotar binding en `CORECHECK_API_KEYS`; invalidar key comprometida; no loguear keys.
- **Flood:** bajar `rateLimit.max` en deploy o bloquear en edge; body ya limitado a 1mb.
- **Sospecha de tampering:** `POST /api/reports/:id/verify` por tenant; no reescribir hashes.

## Recuperación

| Persistencia | Restore |
| :--- | :--- |
| `file` | Restaurar `CORECHECK_DATA_DIR` desde backup; reiniciar proceso |
| `postgres` | Restore DB + `npm run db:migrate` (idempotente) |
| `memory` | Datos efímeros — reinicio pierde reportes (esperado) |

Retention: si `CORECHECK_RETENTION_DAYS>0`, el purge corre al boot — no confundir con borrado malicioso.

## Comunicación

- Incluir `requestId` en tickets.
- No pegar API keys ni payloads con findings confidenciales en canales públicos.
- Ver `THREAT_MODEL.md` y `SOC2_CONTROLS.md` para narrativa CISO.
