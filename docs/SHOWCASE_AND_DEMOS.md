# Showcase & Demos — backlog organizado

**Fuente de verdad** para demos de CoreCheck.  
No mezclar audiencias: **venta ≠ portafolio**.

| Tipo | Audiencia | Qué ve | Repo / URL |
| :--- | :--- | :--- | :--- |
| **Demo comercial** | Buyer, VP Eng, Design Partner | Producto vivo: gate + historial | Staging: `https://corecheck-api.onrender.com/viewer/` |
| **Demo portafolio** | Recruiters, hiring managers, peers | Arquitectura (stubs, sin motor IP) | Repo público futuro: `corecheck-architecture-demo` |

Guion corto comercial: [`DEMO_SCRIPT.md`](./DEMO_SCRIPT.md)  
Deploy staging: [`STAGING_DEPLOY.md`](./STAGING_DEPLOY.md)

---

## 1. Por qué dos demos distintos

| Pregunta | Demo comercial | Demo portafolio |
| :--- | :--- | :--- |
| ¿Cierra deals? | **Sí** (arma principal) | No |
| ¿Muestra Clean Arch / tests? | Secundario | **Sí** |
| ¿Expone inspectors / scoring? | Usa el motor real (privado) | **Nunca** — stubs |
| ¿URL pública de producto? | Viewer + API staging | Solo código scrubbed |
| ¿Proyectos ficticios? | **Sí** (abajo) | N/A (fixtures JSON) |

**Regla:** a un prospecto **nunca** le enseñas el repo stub como “el producto”.  
A un recruiter **nunca** le das acceso al monorepo privado con reglas DAST.

---

## 2. Backlog — por hacer

Estado: `todo` · `doing` · `done`

### A. Demo comercial (prioridad ventas)

| ID | Tarea | Estado | Notas |
| :--- | :--- | :---: | :--- |
| C-01 | Ensayar guion 10 min contra staging Render (2×) | doing | Ensayo 1 en curso (2026-08-21); Diff = same URL only |
| C-02 | Seed de historial: ≥2 runs por cada URL ficticia | **done** | F1 `example.com` + F2 `example.org` (2026-08-21) |
| C-03 | Key de tenant `demo_sales` (mint o bootstrap) distinta de personal | **done** | Bootstrap Render `CORECHECK_API_KEY` (length 31) |
| C-04 | Segunda key / tenant para demo de aislamiento 404 | todo | Requiere `CORECHECK_API_KEYS` con 2 accountIds |
| C-05 | Verify HMAC en un `reportId` de demo (`POST …/verify`) | **done** | `0c83281e-…` → hashMatches + hmacVerified |
| C-06 | One-pager comercial (1 página): problema → gate → Viewer | todo | Enlace desde playbook |
| C-07 | Grabación async 5–7 min (Loom) con proyecto ficticio #1 | todo | Para outbound sin reunión |
| C-08 | Template CI apuntando a staging + secrets de demo (repo ficticio) | todo | `docs/templates/corecheck-audit.client.yml` |
| C-09 | Cold-start Render: checklist “abrir Viewer 60s antes” | todo | Incluir en guion |
| C-10 | Decidir si hace falta un **site demo** propio (HTML estático intencionalmente “roto”) | todo | Ver §3.4 — opcional |

### B. Demo portafolio (prioridad hiring / credibilidad técnica)

| ID | Tarea | Estado | Notas |
| :--- | :--- | :---: | :--- |
| P-01 | Decidir alcance A1 (solo API) vs A2 (monorepo stub) | todo | Recomendado: **A1** |
| P-02 | Crear carpeta/repo `corecheck-architecture-demo` fuera del privado | todo | Sin push hasta scrub |
| P-03 | Scrub: omitir inspectors, core, licensing, docs GTM, deploy real | todo | Ver plan de abstracción en chat 2026-08-21 |
| P-04 | Stubs: analytics fixtures + integrity demo-safe | todo | |
| P-05 | README público (Mermaid, tests, copyright showcase) | todo | |
| P-06 | Tests contrato verdes + push repo **público** | todo | |
| P-07 | Link “Architecture demo” desde perfil / README privado (sin secrets) | todo | |

### C. Higiene (ambos)

| ID | Tarea | Estado |
| :--- | :--- | :---: |
| H-01 | No pegar `CORECHECK_API_KEY` / Neon URL en chats o issues públicos | todo |
| H-02 | Rotar keys si se filtraron | done (Neon password rotada 2026-08-20; revalidar si duda) |
| H-03 | Commit `docs/SESSION_2026-08-20.md` + este archivo si aún no están en `origin` | todo |

---

## 3. Proyectos ficticios (demo comercial)

Usar **nombres inventados** y URLs públicas inocuas o páginas demo propias.  
No auditar sitios de clientes reales sin permiso escrito.

### 3.1 Cast de demos

| Cód. | Proyecto ficticio | ICP que representa | URL objetivo (sugerida) | Historia en la sala |
| :---: | :--- | :--- | :--- | :--- |
| **F1** | **ShopNova** — e-commerce staging | QA Lead retail / DTC | `https://example.com` *(placeholder hasta F1-site)* | “Staging de checkout: headers + a11y antes del Black Friday” |
| **F2** | **AcmeCloud** — marketing SaaS | Platform Eng B2B | `https://example.org` | “Landing de pricing: SEO/GEO + privacy cookies” |
| **F3** | **PayLedger** — onboarding fintech | Head of Quality / compliance-aware | `https://example.net` | “Gate HIGH en onboarding; historial para audit trail” |
| **F4** | **ClinicPortal** — patient portal *staging ficticio* | Healthcare SaaS (cuidado: solo ficción) | Solo si hay **site demo propio** | “WCAG + headers; no datos PHI reales” |

> Hoy `example.com` ya tiene 2 runs en el Viewer (score ~54.7, gate fail). Sirve como **F1 provisional**.

### 3.2 Cómo correr un demo ficticio (copy-paste)

```powershell
cd C:\Users\maryf\Documents\CoreCheck
$API = "https://corecheck-api.onrender.com"
$KEY = "<CORECHECK_API_KEY de Render — tenant demo_sales>"

# F1 — ShopNova (provisional: example.com)
npx tsx src/cli/index.ts run --url https://example.com --skip-license --upload --fail-on HIGH --max-pages 2 --api-key $KEY --upload-url $API

# Repetir 1× para Diff / trends, luego:
# https://corecheck-api.onrender.com/viewer/  → filtrar example.com
```

Narrativa verbal (30 s):

> “Esto no es el sitio del cliente todavía. Es **ShopNova**, un staging ficticio. El mismo flujo es el que cableamos en su GitHub Actions: cada PR sube un reporte y el Viewer muestra si el score bajó.”

### 3.3 Matriz “qué mostrar” por ficticio

| Momento | F1 ShopNova | F2 AcmeCloud | F3 PayLedger |
| :--- | :---: | :---: | :---: |
| Gate FAIL esperado | Sí (umbrales HIGH) | Opcional | Sí (historia compliance) |
| Trends / Δ score | Sí | Sí | Sí |
| Diff last-2 | Sí | Sí | Sí |
| Verify hash | Sí | — | **Sí** (énfasis) |
| Cross-tenant 404 | Una vez por sesión | — | — |

### 3.4 Opcional — site demo propio (C-10)

Si `example.*` se siente pobre en llamadas:

1. Repo público mínimo `shopnova-demo-site` (HTML estático con fallos intencionales: sin CSP, contraste pobre, meta SEO vacía).  
2. Host en Vercel/Netlify free.  
3. Sustituir URL en F1–F3.  
4. **No** meter lógica CoreCheck ahí — solo el blanco de auditoría.

---

## 4. Orden de ejecución sugerido

```text
Semana actual (ventas)
  C-01 → C-02 → C-03 → C-05 → C-09
  (ensayo + seed + key demo + verify + cold-start)

Cuando haya 2 ensayos cómodos
  C-06 → C-07 → C-08

Portafolio (fin de semana / paralelo bajo)
  P-01 → P-02 → … → P-06
```

---

## 5. Definition of Done

### Demo comercial listo para prospecto

- [ ] Guion 10 min ensayado 2× sin leer el doc  
- [ ] Viewer con ≥2 runs en al menos un ficticio (F1)  
- [ ] Diff + trends visibles  
- [ ] Verify OK en un report  
- [ ] Frase de cierre memorizada (Quality Gate + historial tenant)  
- [ ] Cold-start manejado  

### Demo portafolio listo para GitHub público

- [ ] Sin inspectors/core/licensing/docs GTM  
- [ ] Tests contrato verdes  
- [ ] README con copyright “architectural showcase”  
- [ ] Repo **público** distinto del privado  

---

## 6. Anti-patrones

- Enseñar `corecheck-architecture-demo` como si fuera el SaaS.  
- Auditar el staging real de un prospecto en la primera llamada sin NDA/permiso.  
- Mezclar key personal con key `demo_sales` en grabaciones.  
- Prometer SSO / Checks API / pentest en la demo (fuera de v1).
