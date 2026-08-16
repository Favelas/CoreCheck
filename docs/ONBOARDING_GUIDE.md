# Guía de Onboarding de Clientes — CoreCheck v1.0

**Audiencia:** Senior QA Lead (quien presenta e implementa CoreCheck con el cliente).  
**Objetivo:** Dejar el Quality Gate funcionando en el repositorio del cliente en **5 fases**, con lenguaje claro y orientado a validación de calidad.

> Tiempo estimado de activación (cliente preparado): **45–90 minutos**.

---

## Mapa rápido de las 5 fases

```text
[1] Checklist  →  [2] Workflow YAML  →  [3] Secrets
        ↓
[4] PR de prueba (comentario + reportes)  →  [5] Troubleshooting
```

---

## FASE 1 — Requisitos previos e Checklist de inicio

Antes de tocar código, confirma con el cliente estos puntos. Márcalos juntos en la kickoff.

### Checklist del cliente

| # | Ítem | ¿Listo? | Notas |
| :---: | :--- | :---: | :--- |
| 1 | Repo en **GitHub** con Actions habilitadas | ☐ | Org o user account |
| 2 | Permiso para crear archivos en `.github/workflows/` | ☐ | Rol: maintain / admin |
| 3 | Permiso para crear **Secrets** del repositorio | ☐ | Settings → Secrets |
| 4 | **URL objetivo** estable para el primer escaneo | ☐ | Staging o preview (recomendado) |
| 5 | La URL responde **HTTP 200** (no 404) en el navegador | ☐ | Verificar a mano antes del PR |
| 6 | ¿La app está detrás de login? | ☐ | Si sí: usar `--auth-state` (storageState). **MFA no está en v1.0** — ver Enterprise §4.1 |
| 7 | ¿Hay WAF / bot protection (Cloudflare, Akamai…)? | ☐ | Puede devolver 403/429 al crawler |
| 8 | Contacto técnico para el primer PR de prueba | ☐ | Quien abrirá el PR |

### URLs recomendadas (orden de preferencia)

1. **Staging** fijo del cliente (`https://staging.cliente.com`)
2. **Preview efímero** (Vercel / Netlify) de un PR de la app
3. **Producción** solo si staging no existe (avisar ruido y riesgo)

> Tip QA: no uses `localhost` desde GitHub Actions — el runner de GitHub **no** ve la máquina del desarrollador.

---

## FASE 2 — Integración del Workflow

### 2.1 Qué archivo se agrega

Copia la **plantilla de cliente** (no el soft self-check del repo producto):

| | |
| :--- | :--- |
| **Origen** | [`docs/templates/corecheck-audit.client.yml`](../templates/corecheck-audit.client.yml) |
| **Destino (cliente)** | `.github/workflows/corecheck-audit.yml` |

> El workflow [`.github/workflows/audit.yml`](../../.github/workflows/audit.yml) del producto es un **self-check interno** (`example.com` + `fail-on CRITICAL`).  
> En clientes usa siempre la plantilla con **staging real** y **`--fail-on HIGH`**.

### 2.2 Pasos visuales (GitHub UI)

1. Abre el repositorio del cliente en GitHub.
2. Pulsa **Add file → Create new file**.
3. Escribe la ruta exactamente: `.github/workflows/corecheck-audit.yml`
4. Pega el contenido de `docs/templates/corecheck-audit.client.yml`.
5. Commit a una rama (ej. `chore/add-corecheck-gate`) — **no** merges a `main` sin la prueba de la FASE 4.

### 2.3 Variables y secrets del cliente

| Tipo | Nombre | Ejemplo / notas |
| :--- | :--- | :--- |
| Variable | `CORECHECK_TARGET_URL` | `https://staging.cliente.com` (**obligatoria**) |
| Variable | `CORECHECK_VIEWER_URL` | URL del Audit Dashboard (link en comentario de PR) |
| Variable | `CORECHECK_REQUIRE_LICENSE` | `true` solo si usas License Plane; con upload SaaS suele omitirse |
| Variable | `CORECHECK_ENGINE_REPO` | default `Favelas/CoreCheck` |
| Variable | `CORECHECK_ENGINE_REF` | pin de release (`v1.0.0`); default `main` hasta taggear |
| Variable | `CORECHECK_MAX_PAGES` | default `10` |
| Variable | `CORECHECK_CONCURRENCY` | default `1` (runners GHA pequeños) |
| Secret | `CORECHECK_API_KEY` | Key de tenant Control Plane (y/o licencia) |
| Secret | `CORECHECK_API_URL` | Base URL del Control Plane → activa `--upload` (soft-fail) |
| Secret | `CORECHECK_ATTESTATION_SECRET` | opcional; habilita verify HMAC del JSON local |
| Secret | `CORECHECK_ENGINE_TOKEN` | solo si el motor es repo privado |

### 2.4 Cómo se define la URL objetivo

| Modo | Cuándo se usa | Cómo se configura la URL |
| :--- | :--- | :--- |
| **Pull Request** | Cada PR hacia `main`/`master` | `vars.CORECHECK_TARGET_URL` (staging fijo) |
| **Manual (workflow_dispatch)** | “Run workflow” desde Actions | Input `target_url` (override) + `fail_on` |

#### Preview de Vercel / Netlify

- Pide al cliente el enlace del **deploy preview** del PR de la aplicación.
- Pégalo en `target_url` del run manual, o parametrízalo con `CORECHECK_TARGET_URL` si el preview es estable por entorno.

### 2.5 Exit codes (Quality Gate endurecido)

| Código | Significado | ¿Job rojo? |
| :---: | :--- | :---: |
| `0` | PASS | No |
| `1` | GATE_FAIL (umbrales) | Sí |
| `2` | CONFIG / licencia / args | Sí |
| `3` | NETWORK / WAF / unreachable | Sí |
| `4` | ENGINE / Playwright / artefactos incompletos | Sí |

### 2.6 Qué debe producir el workflow (señales de salud)

Tras un run exitoso deberías ver:

- Artifact descargable (`corecheck-audit-results`) con **todos** los archivos canónicos no vacíos:
  `findings.json`, `results.sarif`, `report.html`, `report.md`, `executive-report.pdf`, `interactive-dashboard.html`
- Sticky comment en el PR (si falla por permisos, el gate **sigue** evaluando el exit code)
- SARIF en Code Scanning (best-effort; fallo de upload no tumba el gate)

---

## FASE 3 — Variables y Secretos (GitHub Secrets)

### 3.1 Dónde hacer clic

1. Repo del cliente → **Settings**
2. En el menú izquierdo: **Secrets and variables → Actions**
3. **New repository secret**

### 3.2 Secretos recomendados

| Secret | ¿Obligatorio? | Para qué |
| :--- | :---: | :--- |
| `CORECHECK_API_URL` | **Sí** para SaaS / historial | Base URL Control Plane; sin ella solo hay artefacto local |
| `CORECHECK_API_KEY` | **Sí** con upload | Tenant key (`Bearer` / `X-API-Key`) |
| `CORECHECK_ATTESTATION_SECRET` | Opcional | Verify HMAC del `findings.json` |
| `CORECHECK_WEBHOOK_SECRET` | Opcional | Firma HMAC de webhooks CLI |
| `JIRA_API_TOKEN` (+ domain/email vía vars) | Opcional | Tickets Jira Cloud |
| Credenciales Azure / GitLab | Opcional | Boards / Issues |

> Con `CORECHECK_API_URL`, el template activa `--upload` y, por defecto, `--skip-license` (License Plane y Reports Plane aún son procesos distintos). Para forzar licencia: `vars.CORECHECK_REQUIRE_LICENSE=true`.  
> Deploy del API del vendedor: [`STAGING_DEPLOY.md`](./STAGING_DEPLOY.md). Demo 10 min: [`DEMO_SCRIPT.md`](./DEMO_SCRIPT.md).

### 3.3 Checklist de secrets (QA Lead)

| Paso | Hecho |
| :--- | :---: |
| Abrí Settings → Secrets and variables → Actions | ☐ |
| Creé `CORECHECK_API_URL` (staging Fly/Render del vendedor) | ☐ |
| Creé `CORECHECK_API_KEY` (tenant demo o mintada) | ☐ |
| Opcional: `vars.CORECHECK_VIEWER_URL` | ☐ |
| Verifiqué que el nombre del secret coincide **exactamente** con el del YAML | ☐ |
| No pegué secretos en el chat del PR ni en el código | ☐ |

---

## FASE 4 — Verificación del primer Pull Request (“prueba de fuego”)

### 4.1 Qué pedirle al cliente

1. Abrir un PR de prueba hacia `main`/`master` (puede ser solo el YAML + un README).
2. Esperar a que terminen los checks de Actions (1–3 minutos típicamente).
3. Abrir la pestaña **Conversation** del PR.

### 4.2 Cómo leer el Sticky PR Comment

Busca el comentario automático de CoreCheck. Debe incluir:

- Target URL auditada
- Exit code del gate
- Umbral `--fail-on`
- Resumen / enlace conceptual a hallazgos

**Interpretación rápida para QA:**

| Señal | Significado | Acción |
| :--- | :--- | :--- |
| Check verde + comentario PASS | Gate OK según umbral | Listo para demos |
| Check rojo + hallazgos HIGH/CRITICAL | La app falló el umbral | Priorizar remediación; no es “bug del scanner” por defecto |
| Check rojo sin artifacts | Fallo de infraestructura | Ir a FASE 5 |
| Comentario ausente | Permisos `pull-requests: write` o path summary | FASE 5 → permisos |

### 4.3 Cómo descargar PDF / HTML

1. PR → pestaña **Checks** (o Actions → run concreto)
2. Al final del job: **Artifacts**
3. Descarga `corecheck-audit-results`
4. Abre en local:
   - `report.html` → revisión QA detallada
   - `interactive-dashboard.html` → score y dimensiones
   - `executive-report.pdf` → presentación a stakeholders
   - `results.sarif` → Security / Code Scanning

### 4.4 Criterio de “Onboarding completo”

Marca el onboarding como **DONE** solo si:

- [ ] El workflow corre en PR o `workflow_dispatch`
- [ ] Hay artifact con HTML + JSON (+ PDF si el plan lo permite)
- [ ] El sticky comment aparece en el PR (si el evento fue `pull_request`)
- [ ] El cliente entiende qué significa PASS/FAIL del gate

---

## FASE 5 — Troubleshooting frecuente (para el QA Lead)

### 5.1 El WAF bloquea el escáner (403 / 429)

**Síntomas:** pocas páginas, errores de red, FormInspector 403, score engañoso.

**Qué hacer (en orden):**

1. Confirmar en el navegador que la URL abre bien (200).
2. Pedir al equipo de seguridad del cliente un **allowlist** temporal del user-agent / IP de GitHub-hosted runners **o** un bypass por header compartido.
3. Reducir `--max-pages` y reintentar en ventana acordada.
4. Si el bloqueo es inevitable en prod, auditar **solo staging** sin WAF estricto.

### 5.2 El pipeline falla por permisos / token

**Síntomas:** sticky comment falla; SARIF no sube; “Resource not accessible by integration”.

**Qué hacer:**

1. En el workflow, verifica el bloque:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write
```

2. Si el repo usa reglas de organización, pide a un admin habilitar Actions y Code Scanning.
3. Re-run del job fallido desde Actions → Re-run jobs.

### 5.3 Ajustar el umbral `--fail-on`

| Umbral | Comportamiento | Cuándo usarlo |
| :--- | :--- | :--- |
| `CRITICAL` | Solo bloquea críticos | Primeras semanas / ruido alto / PoC |
| `HIGH` | Bloquea HIGH + CRITICAL | **Estándar recomendado** en staging/prod |
| `MEDIUM` | Muy estricto | Madurez alta del producto auditado |

**Cómo cambiarlo:**

- Run manual: input `fail_on` en Actions.
- YAML del cliente: `--fail-on HIGH` (o el valor acordado en el contrato de calidad).

### 5.4 Solo escanea 1 página

Casi siempre es:

1. URL mal escrita (404), o
2. App SPA sin links `<a href>` discoverables, o
3. WAF/login wall.

Valida la URL a mano y revisa logs del step **Run CoreCheck CLI**.

### 5.5 Falsos positivos / excepciones aceptadas

No “apesantigües” el código del motor. Usa baseline / ignore del cliente:

→ Ver [ENTERPRISE_SCALING_GUIDE.md](./ENTERPRISE_SCALING_GUIDE.md) sección de baselines.

### 5.6 Exit 4 / OOM / runners pequeños (2 vCPU · 7 GB)

**Síntomas:** job rojo con exit `4`, logs Playwright “Target closed”, o falta de artefactos.

**Qué hacer:**

1. Fijar `vars.CORECHECK_CONCURRENCY=1`.
2. Buscar en logs `[ResourceBudget] Concurrency capped …` (cap automático ≤ 2 en GHA).
3. Bajar `CORECHECK_MAX_PAGES` a `3–5` en el primer mes.
4. Re-run; si persiste, abrir incidente interno (no es GATE_FAIL de la app).

---

## Contacto y siguientes pasos

1. Completar FASES 1–4 con el cliente.
2. Acordar umbral (`HIGH` vs `CRITICAL`) por escrito.
3. Agendar revisión del primer PDF ejecutivo con el sponsor de negocio.

Documentación relacionada:

- [README del producto](../README.md)
- [Commercial Playbook](./COMMERCIAL_PLAYBOOK.md)
- [Guía Enterprise / Escalabilidad](./ENTERPRISE_SCALING_GUIDE.md)
- [Arquitectura del motor](./ARCHITECTURE.md)
