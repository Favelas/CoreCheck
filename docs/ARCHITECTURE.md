# Arquitectura CoreCheck v1.0

Vista de alto nivel del motor. Para reglas de contribución y DoD, ver [CONTRIBUTING.md](./CONTRIBUTING.md).

```text
┌────────────────────────────────────────────────────────────────────────┐
│                               CLI ENTRY                                │
│                     (Flags, Config & Policy Validation)                │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        CRAWLER & EXECUTION ENGINE                      │
│            (Headless Navigation, Network Interception & DOM Parse)     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                   ┌───────────────┴───────────────┐
                   ▼                               ▼
    ┌─────────────────────────────┐ ┌─────────────────────────────┐
    │     INSPECTORS ENGINE       │ │    PERFORMANCE ENGINE       │
    │  - Security (DAST)          │ │  - Core Web Vitals (INP)    │
    │  - WCAG 2.2 AA (A11y)       │ │  - Asset Footprint          │
    │  - Privacy & Cookies        │ │  - Network / HTTP Protocols │
    │  - SEO / GEO                │ │  - AI Readiness (/llm.txt)  │
    └──────────────┬──────────────┘ └──────────────┬──────────────┘
                                   │ Raw Findings
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FINDING CONSOLIDATOR                            │
│           (Site-Level vs. Page-Level Deduplication Engine)             │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Consolidated Findings
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        ZERO-FP EVIDENCE ENGINE                         │
│             (2 KB Payload Truncation & Proof Validation)               │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   ATTESTATION & SIGNING ENGINE                         │
│            (HMAC SHA-256 Hash + Verification QR Generation)            │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Signed Audit State
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           EXPORTERS HUB                                │
│        ┌──────────────┬──────────────┬──────────────┬──────────────┐   │
│        │  HTML Report │  PDF Audit   │ SARIF 2.1.0  │ JSON Engine  │   │
│        └──────────────┴──────────────┴──────────────┴──────────────┘   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     INTEGRATIONS & TICKETING                           │
│        ┌──────────────┬──────────────┬──────────────┬──────────────┐   │
│        │ Jira Cloud   │ Azure Boards │ GitLab Issue │ Webhook HMAC │   │
│        └──────────────┴──────────────┴──────────────┴──────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

## Módulos clave en el repo

| Área | Ruta |
| :--- | :--- |
| CLI (`run` / `verify`) | `src/cli/index.ts`, `src/cli/verify_command.ts`, `src/cli/cli_contract.ts` |
| Exit codes | `src/utils/exit_codes.ts` |
| Crawler / runner | `src/core/crawler.ts`, `src/core/audit_runner.ts` |
| ResourceBudget (OOM guard) | `src/utils/resource_budget.ts` |
| Policy / baseline | `src/core/policy_engine.ts` |
| Attestation | `src/utils/attestation.ts` |
| SARIF | `src/utils/sarif_exporter.ts` |
| Workflows | `.github/workflows/` + `docs/templates/corecheck-audit.client.yml` |

← [Índice docs](./README.md) · [README producto](../README.md)
