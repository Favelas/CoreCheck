import { Page, Response } from 'playwright';
import { AuditFinding } from '../types/audit.js';

export class FuzzingInspector {
  private page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  /**
   * Ejecuta pruebas activas de inyección (XSS / SQLi) y monitoreo de errores 500 en campos interactivos.
   */
  public async executeFuzzing(): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];

    try {
      await this.page.waitForSelector('input, textarea', { timeout: 5000 }).catch(() => {});

      const inputs = await this.page.locator(
        'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="image"]):not([type="checkbox"]):not([type="radio"]), textarea'
      ).all();

      const fuzzPayloads = [
        {
          type: 'XSS',
          ruleId: 'SEC-XSS-ACTIVE-INJECTION',
          value: `"><img src=x onerror="window.__corecheck_xss=true">`,
          severity: 'CRITICAL' as const,
          owasp: ['A03:2021-Injection'],
          cwe: ['CWE-79']
        },
        {
          type: 'SQLi',
          ruleId: 'SEC-SQLI-SPECIAL-CHARS',
          value: `' OR '1'='1' -- `,
          severity: 'HIGH' as const,
          owasp: ['A03:2021-Injection'],
          cwe: ['CWE-89']
        }
      ];

      for (let i = 0; i < inputs.length; i++) {
        const input = inputs[i];
        const isVisible = await input.isVisible().catch(() => false);
        if (!isVisible) continue;

        const selector = await input.evaluate((el) => {
          const id = el.id ? `#${el.id}` : '';
          const name = el.getAttribute('name') ? `[name="${el.getAttribute('name')}"]` : '';
          return id || name || el.tagName.toLowerCase();
        }).catch(() => `input[${i}]`);

        for (const payload of fuzzPayloads) {
          let network500Detected = false;

          const responseListener = (response: Response) => {
            if (response.status() >= 500) {
              network500Detected = true;
            }
          };

          this.page.on('response', responseListener);

          try {
            // Inicializar bandera de prueba XSS en el contexto del navegador
            await this.page.evaluate(() => {
              (window as any).__corecheck_xss = false;
            }).catch(() => {});

            // Inyección de payload
            await input.focus();
            await input.fill('');
            await input.fill(payload.value);
            await input.dispatchEvent('input');
            await input.dispatchEvent('change');
            await input.press('Tab');

            await this.page.waitForTimeout(400);

            // 1. Verificación de Inyección XSS Ejecutada
            if (payload.type === 'XSS') {
              const isXssTriggered = await this.page
                .evaluate(() => (window as any).__corecheck_xss === true)
                .catch(() => false);

              if (isXssTriggered) {
                findings.push({
                  id: `XSS-EXEC-${Date.now()}-${i}`,
                  ruleId: payload.ruleId,
                  title: 'Vulnerabilidad Ejecutable XSS Reflejado / DOM en Cliente',
                  severity: payload.severity,
                  description: `El campo \`${selector}\` no sanitizó la entrada del usuario, permitiendo la ejecución arbitraria de JavaScript en el navegador.`,
                  evidence: { selector, requestPayload: payload.value },
                  remediation: {
                    explanation: 'Escape adecuadamente todas las salidas renderizadas en el DOM y defina una política de seguridad de contenido (CSP) que bloquee scripts inline.',
                    codeBefore: `element.innerHTML = userInput;`,
                    codeAfter: `element.textContent = userInput;`
                  },
                  standards: { owasp: payload.owasp, cwe: payload.cwe }
                });
              }
            }

            // 2. Verificación de Errores No Controlados en Servidor (HTTP 500)
            if (network500Detected) {
              findings.push({
                id: `SERVER-500-${Date.now()}-${i}`,
                ruleId: 'SEC-UNHANDLED-EXCEPTION',
                title: `Excepción Interna del Servidor (HTTP 500) tras Fuzzing (${payload.type})`,
                severity: 'HIGH',
                description: `El envío del vector '${payload.type}' en \`${selector}\` provocó una falla interna no controlada en el backend.`,
                evidence: { selector, requestPayload: payload.value, responseStatus: 500 },
                remediation: {
                  explanation: 'Implemente middlewares de validación de esquemas (DTOs) para manejar y denegar peticiones malformadas adecuadamente.',
                  codeBefore: `app.post('/api/endpoint', (req, res) => { ... });`,
                  codeAfter: `app.post('/api/endpoint', validateInput(schema), (req, res) => { ... });`
                },
                standards: { owasp: ['A05:2021-Security Misconfiguration'], cwe: ['CWE-248'] }
              });
            }

            // Limpieza del campo
            await input.fill('').catch(() => {});
          } catch {
            // Manejo de desmonte de elementos dinámicos
          } finally {
            this.page.off('response', responseListener);
          }
        }
      }
    } catch (error) {
      console.error(`[ERROR-FUZZING] Fallo en la ejecución del fuzzing activo: ${(error as Error).message}`);
    }

    return findings;
  }
}