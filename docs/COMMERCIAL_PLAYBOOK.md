# Commercial Playbook — CoreCheck v1.0 Enterprise Hardened

**Audiencia:** Sales Engineering, Customer Success, QA Leads que cierran y activan deals.  
**Estado del producto:** Quality Gate **Enterprise Hardened** — apto para staging CI/CD con SLA operativo (exit codes estables, CI que no miente en verde, attestation verificable).

---

## 1. Posicionamiento honesto (qué vender / qué no)

### Sí — listo para producción guiada

| Caso de uso | Confianza | Notas comerciales |
| :--- | :---: | :--- |
| Staging / preview web HTTP(S) sin MFA | Alta | Caso canónico del gate |
| Headers, WCAG 2.2 AA, perf, privacy, SEO/GEO | Alta | 6 dimensiones en una pasada |
| PR Gate en GitHub Actions | Alta | Plantilla cliente + artefactos obligatorios |
| SARIF → Code Scanning + PDF ejecutivo firmado | Alta | HMAC opcional con secret del cliente |
| Auth vía `storageState` o Bearer header | Media-Alta | Receta soportada en v1.0 |

### No — fuera de alcance v1.0 (no prometer)

- MFA / Captcha / SSO interactivo SAML-OIDC
- Dashboard SaaS multi-tenant
- DAST ofensivo profundo / pentest sustituto
- Marketplace Action oficial (roadmap v1.1)
- Apps SPA sin enlaces `<a href>` descubribles (cobertura limitada)

Script de objeción: *“CoreCheck es el Quality Gate unificado de release; no reemplaza un pentest ni un IdP. Cubre el 80% del ruido de calidad digital en cada PR.”*

---

## 2. Criterios de “listo para firmar” (pre-sales technical)

Antes de comprometer fecha de go-live, el SE valida:

| # | Checkpoint | Evidencia |
| :---: | :--- | :--- |
| 1 | Staging responde HTTP 200 desde internet (o allowlist de runners) | Curl / browser |
| 2 | Sin WAF que bloquee headless (o IP allowlist acordada) | Smoke `workflow_dispatch` |
| 3 | `vars.CORECHECK_TARGET_URL` definida | Settings → Variables |
| 4 | Secret `CORECHECK_API_KEY` (clientes de pago) | Settings → Secrets |
| 5 | Primer PR con artefactos no vacíos + sticky comment | Actions run verde o rojo **explicable** |
| 6 | Exit code interpretado (0–4), no “el check falló” genérico | Tabla §4 |

Si el cliente exige MFA en staging: plan B = exportar `storageState` Playwright post-login humano y usar `--auth-state` (documentado en Enterprise guide).

---

## 3. Paquete de entrega al cliente

| Entregable | Ubicación |
| :--- | :--- |
| Workflow de producción | [`docs/templates/corecheck-audit.client.yml`](./templates/corecheck-audit.client.yml) |
| Onboarding paso a paso | [`ONBOARDING_GUIDE.md`](./ONBOARDING_GUIDE.md) |
| DoD / baselines / roadmap | [`ENTERPRISE_SCALING_GUIDE.md`](./ENTERPRISE_SCALING_GUIDE.md) |
| README producto | [`../README.md`](../README.md) |

**Orden de activación (45–90 min):** Onboarding Fases 1→5. No improvisar YAML desde el self-check del repo producto.

---

## 4. Taxonomía de exit codes (SLA / soporte)

| Code | Label | Quién actúa | Mensaje al cliente |
| :---: | :--- | :--- | :--- |
| `0` | PASS | Nadie | Gate limpio según umbral |
| `1` | GATE_FAIL | App team | Hallazgos ≥ `--fail-on` — remediación o baseline con owner |
| `2` | CONFIG | Platform / SE | Args, licencia, baseline corrupto, URL mal formada |
| `3` | NETWORK | Network / App | WAF, DNS, timeout, target caído |
| `4` | ENGINE | CoreCheck / Platform | Playwright/OOM/artefactos incompletos — **no** es “la app falló calidad” |

Regla de soporte L1: **nunca** reclasificar exit `4` como fallo de calidad de la app.

---

## 5. Arquitectura endurecida (hablar con confianza)

1. **CLI `run` + `verify`** — attestation SHA-256 / HMAC-SHA256 verificable offline.  
2. **Exit codes 0–4** — CI ramifica sin parsear logs.  
3. **`INFRA_FAILURE`** — inspectors que crashean generan hallazgo HIGH visible (no silencio).  
4. **CI duro** — smoke del producto exige artefactos; template cliente exige staging + `fail-on HIGH`.  
5. **ResourceBudget** — concurrencia auto-cap en runners 2 vCPU / 7 GB (`--disable-dev-shm-usage`, hard cap CI = 2).  
6. **Evidence ≤ 2 KB** — spill a disco; runners no se saturan de DOM.

---

## 6. Umbrales recomendados por entorno

| Entorno | `--fail-on` | `max-pages` | `concurrency` |
| :--- | :---: | :---: | :---: |
| PoC / demo | `CRITICAL` | 3 | 1 |
| Staging (default cliente) | `HIGH` | 10 | 1–2 (cap automático en GHA) |
| Pre-prod estricto | `MEDIUM` | 15 | 1–2 |
| Prod (solo si no hay staging) | `HIGH` + baseline | 5–10 | 1 |

---

## 7. Playbook de incidente (cliente dice “se rompió solo”)

1. Descargar artifact `corecheck-audit-results`.  
2. Leer `summary.md` → exit code.  
3. Si `1` → abrir `findings.json` / SARIF; revisar baseline.  
4. Si `3` → WAF / URL / preview expirado.  
5. Si `4` → logs Playwright; bajar `concurrency` a `1`; confirmar ResourceBudget en logs `[ResourceBudget]`.  
6. Verificar attestation:  
   `node dist/index.js verify --report findings.json --key $CORECHECK_ATTESTATION_SECRET`

---

## 8. Mensajes comerciales prohibidos / permitidos

| Evitar | Preferir |
| :--- | :--- |
| “Zero false positives garantizado” | “Zero-FP revalidation + baselines auditables” |
| “Reemplaza el pentest” | “Complementa AppSec en cada PR” |
| “Soporta cualquier login enterprise” | “storageState / headers en v1.0; Auth Recipes en v1.1” |
| “El CI siempre pasa si el motor está sano” | “El CI falla en rojo si el motor o los artefactos fallan” |

---

## 9. Checklist de cierre comercial → handoff CS

- [ ] Scope freeze v1.0 firmado (qué está in/out)  
- [ ] Staging URL + owner técnico  
- [ ] API key emitida / secret en GitHub  
- [ ] Template cliente mergeado  
- [ ] Primer PR de prueba interpretado (PASS o FAIL explicable)  
- [ ] Canal de soporte + playbook §7 compartido  

---

## 10. Referencias rápidas

- Onboarding: [ONBOARDING_GUIDE.md](./ONBOARDING_GUIDE.md)  
- Enterprise / v1.1: [ENTERPRISE_SCALING_GUIDE.md](./ENTERPRISE_SCALING_GUIDE.md)  
- Arquitectura: [ARCHITECTURE.md](./ARCHITECTURE.md)
