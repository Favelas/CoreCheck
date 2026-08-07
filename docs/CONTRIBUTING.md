# Contributing to CoreCheck

Gracias por contribuir. Para mantener el listón técnico, la política de **cero errores de tipos** y la estabilidad de producción, todo cambio debe cumplir este flujo.

---

## 1. Principios de desarrollo

1. **Zero TypeScript Errors (`npm run typecheck`):** un solo error de tipos rechaza el PR.
2. **Zero False-Positive Target:** cada regla debe incluir evidencia verificable con presupuesto estricto de **2 KB**.
3. **Scope Discipline:** features fuera de CoreCheck v1.0 se rechazan o se aplazan a post-revenue (ver [ENTERPRISE_SCALING_GUIDE](./ENTERPRISE_SCALING_GUIDE.md)).

---

## 2. Setup local y verificación

```bash
git clone https://github.com/Favelas/CoreCheck.git
cd CoreCheck

npm install
npm run typecheck
npm test
npm run build
```

---

## 3. Definition of Done (PR interno)

- [ ] `npm run typecheck` en verde
- [ ] `npm test` en verde (contratos CLI + SARIF)
- [ ] Workflows CI/DAST en verde si el cambio los afecta
- [ ] Documentación actualizada si cambia el contrato público
- [ ] Sin secretos ni artefactos de `audit-results/` en el commit

Más detalle operativo: [ENTERPRISE_SCALING_GUIDE.md](./ENTERPRISE_SCALING_GUIDE.md).

← [Índice docs](./README.md)
