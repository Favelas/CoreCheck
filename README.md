# CoreCheck

> **The Unified Digital Quality & Security Gate for CI/CD Pipelines**
> High-precision DAST, WCAG 2.2 AA Accessibility, Core Web Vitals, Privacy, SEO/GEO, and AI-Agent Readiness in a single zero-noise execution.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](#)
[![Code Scanning](https://img.shields.io/badge/SARIF-2.1.0-green?style=flat-square)](#)
[![Compliance](https://img.shields.io/badge/Compliance-ISO27001%20%7C%20SOC2%20%7C%20PCI--DSS%20v4.0-blue?style=flat-square)](#)

---

## Executive Overview

**CoreCheck** is an enterprise-grade Digital Quality Gate engineered specifically for modern DevSecOps pipelines and Mid-Market engineering teams. Instead of gluing together disparate scanners for security, accessibility, performance, and SEO, CoreCheck executes a unified pass over target Web applications and outputs immediate, actionable, and cryptographically signed audit artifacts.

### Key Capabilities

* **Unified Digital Quality Score (0–100):** Consolidates 6 critical dimensions into a single actionable metric.
* **Site-Level Deduplication Engine:** Automatically merges repetitive site-wide findings (e.g., missing HTTP security headers or cookie flags) into consolidated entities to eliminate alert fatigue.
* **Zero-False-Positive Philosophy:** Enforces evidence budgets (2 KB maximum payload per finding) to guarantee actionable bugs over noise.
* **Cryptographic Attestation:** Signs execution results with HMAC SHA-256 and embeds verification QR codes on PDF executive reports for tamper-proof compliance audits.
* **Native CI/CD & DevSecOps Ecosystem:** Direct export to SARIF 2.1.0, GitHub Code Scanning, Jira Cloud API v3, Azure Boards, GitLab Issues, and signed webhooks.

---

## The 6 Inspection Dimensions

CoreCheck evaluates target environments against six non-overlapping compliance and quality vectors:

| Dimension | Scope & Core Standards Evaluated |
| :--- | :--- |
| **1. Security (DAST)** | Passive & active attack surface analysis, CORS configurations, CSP parsing, TLS cipher suites, sensitive exposure, HTTP security headers (`SEC-HDR-*`). |
| **2. Accessibility (A11y)** | Strict WCAG 2.2 Level AA alignment, DOM tree contrast parsing, ARIA landmarks, keyboard navigation pathing, screen-reader compatibility. |
| **3. Performance** | Core Web Vitals profiling, including Interaction to Next Paint (INP), Largest Contentful Paint (LCP), Cumulative Layout Shift (CLS), and asset optimization. |
| **4. SEO & GEO** | Canonical tags, structured JSON-LD data, search engine indexing directives, localized geotargeting, and open graph schemas. |
| **5. Privacy** | Cookie attribute compliance (`SameSite`, `Secure`, `HttpOnly`), third-party tracker enumeration, privacy policy detection, GDPR/CCPA telemetry leaks (`PRIV-*`). |
| **6. Network & AI Readiness** | HTTP/2 / HTTP/3 protocol negotiation, TLS latency, fallback behaviors, and AI-Agent crawler readiness validation (`/llm.txt`). |

---

## Installation & Setup

### Prerequisites

* **Node.js:** `>=18.0.0`
* **npm / pnpm / yarn**

### Global CLI Installation

```bash
npm install -g @corecheck/cli
# or via local execution
npx @corecheck/cli --help