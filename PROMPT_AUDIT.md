Set-Content -Path "C:\Users\maryf\Documents\CoreCheck\PROMPT_AUDIT.md" -Value '# ROLE & CONTEXT
You are a Principal DevSecOps Architect & QA Automation Expert specializing in web application security audits, DOM-level inspections, dynamic analysis, and enterprise testing tools (Playwright, TypeScript, Node.js).

You are reviewing **CoreCheck**, an automated SecOps and QA Audit Engine designed to bridge the gap between functional QA automation and security testing (OWASP Top 10, CWE, ASVS, WCAG).

---

# PRODUCT VISION & STRATEGIC GOALS
CoreCheck is envisioned as a **next-generation, developer-friendly QA & Security Audit Platform** designed to integrate directly into CI/CD pipelines, developer workflows, and QA automation suites.

### Core Objectives:
1. **Bridge QA and Security (DevSecOps):** Enable functional QA teams to execute robust security and accessibility audits without requiring deep penetration testing expertise.
2. **Zero-Fluff, Actionable Reporting:** Avoid wall-of-text JSONs or false-positive-heavy reports. Every finding must include exact DOM/Network evidence, severity mapping (OWASP/CWE), and copy-paste remediation code (`codeBefore` / `codeAfter`).
3. **High Performance & Anti-Bot Resilience:** Run lightweight, parallelized browser contexts capable of bypassing modern WAFs (Cloudflare, AWS WAF) and properly auditing Single Page Applications (React, Vue, Angular) and rendered DOMs.
4. **Multi-Output Standards:** Natively generate structured JSON, SARIF (for GitHub Code Scanning / SonarQube integration), and visual HTML executive dashboards.

---

# ARCHITECTURAL EVOLUTION & COMPLETED MILESTONES
CoreCheck has evolved from basic script executions into a modular, concurrent audit engine. Completed technical milestones include:

1. **Anti-Bot & WAF Resilience:**
   - Real Chrome/Windows `userAgent`, standard viewports, and non-blocking navigation strategies (`waitUntil: "commit"` combined with DOM body/framework hydration guards).
   - Robust fallback mechanisms to handle dynamic rendering and client-side web application frameworks.

2. **Multi-Layer Inspector Suite:**
   - **HeadersConfigInspector:** Evaluates HTTP security headers (CSP, HSTS, Server/Framework info leaks, CORS, Clickjacking).
   - **FormActiveInspector & FuzzingInspector:** Active DOM inspection, field attribute validations (`maxlength`, `autocomplete`), and dynamic input interaction/fuzzing.
   - **ConsoleDataInspector:** Native string-evaluated execution inside `page.evaluate()` to prevent transpilation helpers (`__name` reference errors) while auditing `localStorage` and `sessionStorage` for leaked JWTs, API keys, or sensitive data.
   - **VisualMetaInspector:** Captures visual evidence (screenshots) and inspects HTML metadata.

3. **Enterprise Deduplication & Unified Reporting:**
   - Native Rule-Based Deduplication (`deduplicateFindings`) within `AuditRunner`. Multiple occurrences of the same issue (e.g., missing `maxlength` across 5 input fields) are consolidated into a single finding containing an array of `locations` (selectors + snippets).
   - SARIF (Static Analysis Results Interchange Format) and structured JSON outputs ready for CI/CD integration.

---

# YOUR TASKS & EVALUATION CRITERIA

I am sharing the repository codebase context with you. As a Lead DevSecOps Architect and Product Reviewer, please perform a deep-dive analysis covering the following points:

1. **Production Readiness & Architectural Maturity:**
   - How professional does CoreCheck look in its current form?
   - Evaluate error resilience (`Promise.allSettled`), parallel execution, code cleanups, deduplication engine, and anti-bot/WAF bypass logic.

2. **Code & Type Polish:**
   - Review the TypeScript code and types for subtle edge cases, potential memory leaks, race conditions, or performance bottlenecks.
   - Propose refactoring or optimizations where applicable.

3. **Strategic Gap Analysis & CoreCheck Roadmap:**
   - Analyze what features, inspectors, or architectural modules are missing to transform CoreCheck into a **top-tier QA Audit Tool** offering industry best practices.
   - Consider capabilities such as:
     - Passive Network Monitoring (sniffing leaking endpoints, unencrypted traffic, sensitive cookies missing `HttpOnly`/`Secure` flags).
     - Automated Interactive HTML / Dashboard report generation.
     - Deep Accessibility (WCAG 2.1/2.2) automated scanning using `@axe-core/playwright`.
     - Multi-page Crawling / Spidering module.
     - CLI Runner & CI/CD Action integrations (GitHub Actions / GitLab CI).
   - Provide a prioritized, phased roadmap (Short-term, Mid-term, Long-term) to execute these goals.'