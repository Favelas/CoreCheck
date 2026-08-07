# Guía de Escalabilidad y Estándar Enterprise — CoreCheck

**Audiencia:** Tech Leads, Architects y QA Leads que protegen la calidad del producto.  
**Propósito:** Mantener CoreCheck en el nivel **Enterprise v1.0** y preparar el terreno para **v1.1 (post-revenue)** sin romper el Quality Gate.

---

## 1. Protocolo de Mantenimiento de Calidad (DoD interno)

### 1.1 Reglas inamovibles (cada PR interno)

| Regla | Comando / evidencia | Criterio de aceptación |
| :--- | :--- | :--- |
| **0 errores TypeScript** | `npm run typecheck` | Exit code `0`, sin warnings de compilación |
| **Suite endurecida verde** | `npm test` | Contratos + attestation + policy + artefactos + Playwright + ResourceBudget |
| **Build reproducible** | `npm run build` | Genera `dist/` usable (`node dist/index.js run --help`) |
| **CI no miente en verde** | Workflows `corecheck-ci.yml` / template cliente | Smoke/artefactos obligatorios; exit 0–4 |
| **No secrets en git** | Revisión PR | Sin API keys, tokens Jira, `.env` |
| **Scope freeze v1.0** | Review arquitectónico | Sin features de la lista de denegaciones |

### 1.2 Definition of Done (release / hotfix)

- [ ] `npm run typecheck` = 0 errores
- [ ] `npm test` = pass
- [ ] Workflows CI + DAST en verde en el PR
- [ ] Documentación tocada si cambia contrato CLI o artefactos
- [ ] No se introduce ruido de hallazgos sin evidencia ≤ 2 KB

### 1.3 Comandos de higiene diarios

```bash
npm run typecheck
npm test
npm run build
node dist/index.js run --help
```

---

## 2. Gestión de falsos positivos y reglas de excepción

### 2.1 Principio

**Nunca** desactives una regla en el código fuente “porque el cliente se queja”.  
Las excepciones viven en **configuración por cliente / por repo**.

En CoreCheck v1.0 el mecanismo real es:

| Archivo | Formato | Uso |
| :--- | :--- | :--- |
| `.corecheckignore` | Texto (una regla por línea) | Suppressions rápidas |
| `corecheck-baseline.json` | JSON | Baseline formal / auditoría |
| `--baseline <path>` | CLI | Apunta a cualquiera de los anteriores |

> Nombre comercial futuro: unificar en `corecheck.config.json` (v1.1). Hoy usa los archivos de arriba.

### 2.2 Formato `.corecheckignore`

```text
# ruleId|selector opcional|url opcional
SEC-HDR-CSP
SEC-HDR-XFO|#header|https://staging.cliente.com/
A11Y_VIOLATION|button.submit
```

### 2.3 Formato `corecheck-baseline.json`

```json
{
  "version": 1,
  "accepted": [
    {
      "ruleId": "SEC-HDR-CSP",
      "reason": "CSP gestionado en CDN; aceptado por Security hasta Q3",
      "owner": "security@cliente.com",
      "expiresAt": "2026-12-31"
    }
  ]
}
```

### 2.4 Cómo aplicarlo en CI

```bash
node dist/index.js run \
  --url "$TARGET_URL" \
  --fail-on HIGH \
  --baseline ./corecheck-baseline.json \
  --formats json,sarif,html,markdown \
  --output-dir ./audit-results \
  --flat-output
```

### 2.5 Gobernanza de excepciones (QA Lead)

| Pregunta | Respuesta esperada antes de aceptar |
| :--- | :--- |
| ¿Hay dueño nombrado? | Sí (equipo + email) |
| ¿Hay fecha de expiración? | Sí |
| ¿Es ruido del scanner o riesgo real aceptado? | Documentado |
| ¿Se revisará en el próximo quarter? | Sí / ticket abierto |

---

## 3. Contratos que no se rompen (v1.0)

### 3.1 CLI público

- Entrypoint: `node dist/index.js` / `corecheck` → subcomando `run` (default).
- Artefactos canónicos: `report.html`, `findings.json`, `results.sarif`, `executive-report.pdf`, `report.md`.
- SARIF: `security-severity` **numérico** (0.0–10.0) para GitHub Code Scanning.

### 3.2 Carpetas

| Carpeta | Rol |
| :--- | :--- |
| `audit-results/` | Salida canónica de auditorías |
| `reports/shared_reports/` | Hosting estático de reportes compartidos (no mezclar con runs CI) |
| `ci-artifacts/` | Smoke de CI del propio producto |

### 3.3 Suite de tests de contrato

```bash
npm test
# → test/cli_contract.test.ts
# → test/sarif_exporter.test.ts
```

Cualquier cambio en precedencia de flags (`--out`, `--formats`) o en SARIF **debe** actualizar estos tests en el mismo PR.

---

## 4. Roadmap y preparación para v1.1 (Post-Revenue)

> Activar construcción de v1.1 solo con **3+ clientes bajo contrato**.  
> Hasta entonces: estabilizar onboarding, baselines y reportes.

### 4.1 Auth avanzada (Auth Recipes) — MFA pendiente a propósito

**Objetivo v1.1:** auditar zonas autenticadas sin reinventar el crawler.

#### Por qué MFA / Captcha / SSO interactivo NO van en v1.0

| Motivo | Detalle técnico / de producto |
| :--- | :--- |
| **Scope freeze** | v1.0 se congela como Quality Gate de staging/CI; MFA es superficie de identidad, no de calidad digital del render público. |
| **No determinismo en CI** | TOTP/SMS/push/WebAuthn requieren secretos rotativos, dispositivos o intervención humana — rompe runners efímeros y el SLA de exit codes. |
| **Riesgo de seguridad del cliente** | Automatizar bypass de MFA/Captcha en CI induciría anti-patrones (secrets de 2FA en Actions, disable MFA en staging “para el scanner”). |
| **Falsos negativos / flakiness** | Flujos MFA cambian por vendor (Okta, Azure AD, Duo, Cloudflare Turnstile); un “login mágico” frágil tumbaría gates sin señal de calidad real. |
| **Mitigación ya soportada** | `--auth-state` (Playwright `storageState` exportado **después** de un login humano) + `--auth-header` Bearer cubren el 90% de audits autenticados sin tocar MFA. |

**Workaround v1.0 (recomendado a clientes con MFA):**

1. Login manual (o script one-shot fuera de CI) en staging.
2. Exportar `storageState` de Playwright.
3. Guardar el JSON como GitHub Secret / artifact efímero.
4. Ejecutar: `corecheck run --url … --auth-state ./auth.json --fail-on HIGH`.

**Qué sí incluye v1.0 hoy:**

- `storageState` Playwright (`--auth-state`)
- Form login heurístico (`--auth-login-url` + user/pass) — parcial; fall-closed si falla
- Header injection (`--auth-header`)

**Qué queda explícitamente en v1.1+ (Auth Recipes):** MFA/TOTP recipes, Captcha hand-off, SSO/SAML/OIDC interactivo — solo post-revenue y con diseño de vault + recetas versionadas.

Pautas arquitectónicas (cuando se abra v1.1):

1. Mantener `AuthHandler` como único punto de sesión.
2. Recetas versionadas, por ejemplo:
   - `storageState` Playwright exportado (`--auth-state`)
   - Form login (`--auth-login-url` + user/pass) — ya parcialmente en v1.0
   - Header injection (`--auth-header`) — ya en v1.0
   - `mfa_totp.ts` / `sso_oidc.ts` — **no antes de v1.1**
3. Guardar secrets solo en GitHub Secrets / vault del cliente.
4. Prohibir cookies/tokens en el repo o en findings (redact en evidencia).

Estructura sugerida (futura):

```text
src/auth/recipes/
  form_login.ts
  storage_state.ts
  header_bearer.ts
  mfa_totp.ts          # v1.1+
  sso_oidc.ts          # v1.1+
```

### 4.2 Empaquetar como GitHub Action oficial (`corecheck/action@v1`)

Objetivo Marketplace: que el cliente escriba solo:

```yaml
- uses: corecheck/action@v1
  with:
    url: ${{ vars.STAGING_URL }}
    fail-on: HIGH
    api-key: ${{ secrets.CORECHECK_API_KEY }}
```

Checklist de preparación (no implementar aún):

| Ítem | Estado v1.0 | Nota v1.1 |
| :--- | :---: | :--- |
| CLI estable (`run` + exit codes) | ✅ | Base del action |
| SARIF GitHub-compatible | ✅ | Input `upload-sarif: true` |
| Documentación onboarding | ✅ | README del action |
| Action metadata (`action.yml`) | ❌ | Crear repo `corecheck/action` |
| Versionado semver + tags | ❌ | `@v1`, `@v1.1.0` |
| Branding Marketplace | ❌ | Icon + description |

### 4.3 Diccionario de denegaciones (sigue vigente)

No construir hasta post-revenue:

- Dashboard SaaS multi-tenant
- SSO/SAML corporativo
- Fuzzing / DAST ofensivo profundo
- Sync bidireccional Jira con UI propia
- Portal white-label

---

## 5. Playbook de incidente de calidad (interno)

Si un cliente reporta “el gate se rompió sin razón”:

1. Pedir artifact del run (`findings.json` + `summary.md`).
2. Verificar URL (200 vs 404) y WAF.
3. Comparar `--fail-on` y baseline aplicada.
4. Reproducir local:

```bash
npm run build
node dist/index.js run --url <URL> --fail-on HIGH --skip-license --output-dir ./audit-results
```

5. Si es falso positivo legítimo → baseline con owner/expiry (sección 2).  
6. Si es regresión del motor → fix + test de contrato en el mismo PR.

---

## 6. Referencias

- [Onboarding de clientes](./ONBOARDING_GUIDE.md)
- [README producto](../README.md)
- [Arquitectura](./ARCHITECTURE.md)
- [Contributing](./CONTRIBUTING.md)
- Policy engine: `src/core/policy_engine.ts`
- SARIF exporter: `src/utils/sarif_exporter.ts`
