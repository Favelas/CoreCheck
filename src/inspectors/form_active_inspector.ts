import { Page, Response } from 'playwright';
import { AuditFinding } from '../types/audit';

export class FormActiveInspector {
  private page: Page;
  private findings: AuditFinding[] = [];

  constructor(page: Page) {
    this.page = page;
  }

  public async executeActiveFuzzing(): Promise<AuditFinding[]> {
    // Esperar a que al menos un input o formulario esté presente
    await this.page.waitForSelector('input, textarea, form', { timeout: 10000 }).catch(() => {});

    const inputs = await this.page.locator('input:not([type="hidden"]), textarea').all();

    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i];
      const isVisible = await input.isVisible().catch(() => false);
      if (!isVisible) continue;

      const selector = await input.evaluate((el) => {
        const id = el.id ? `#${el.id}` : '';
        const name = el.getAttribute('name') ? `[name="${el.getAttribute('name')}"]` : '';
        const placeholder = el.getAttribute('placeholder') ? `[placeholder="${el.getAttribute('placeholder')}"]` : '';
        return id || name || placeholder || el.tagName.toLowerCase();
      });

      // Verification 1: Structural Defenses (Missing MaxLength)
      const hasMaxLength = await input.getAttribute('maxlength');
      if (!hasMaxLength) {
        this.findings.push({
          id: `MAXLENGTH-MISSING-${Date.now()}-${i}`,
          ruleId: 'SEC-DOM-NO-MAXLENGTH',
          title: 'Ausencia de Atributo HTML maxlength en Campo de Entrada',
          severity: 'LOW',
          description: `El campo \`${selector}\` no limita la entrada de caracteres en el DOM nativo. Confía exclusivamente en validaciones de JavaScript/Backend.`,
          evidence: {
            selector,
            snippet: await input.evaluate((el: HTMLElement) => el.outerHTML).catch(() => '')
          },
          remediation: {
            explanation: 'Declare el atributo `maxlength` explícitamente en el elemento HTML para evitar desbordamientos de buffers visuales en cliente.',
            codeBefore: `<input type="text" name="username" />`,
            codeAfter: `<input type="text" name="username" maxlength="50" />`
          },
          standards: {
            owasp: ['A04:2021-Insecure Design'],
            cwe: ['CWE-20']
          }
        });
      }

      // Verification 2: Active Fuzzing Testing (XSS & Stress)
      await this.testXSSInjection(input, selector);
    }

    return this.findings;
  }

  private async testXSSInjection(inputLocator: any, selector: string): Promise<void> {
    const xssPayload = `"><img src=x onerror="window.__corecheck_xss=true">`;
    let network500Detected = false;

    const responseListener = (response: Response) => {
      if (response.status() >= 500) {
        network500Detected = true;
      }
    };

    this.page.on('response', responseListener);

    try {
      // Limpiar e inyectar el payload simulando eventos de React/Vue
      await inputLocator.focus();
      await inputLocator.fill(xssPayload);
      await inputLocator.dispatchEvent('input');
      await inputLocator.dispatchEvent('change');
      await inputLocator.press('Tab'); // Trigger blur event

      await this.page.waitForTimeout(500); // Dar tiempo al SPA/Framework a procesar

      const isXssTriggered = await this.page.evaluate(() => (window as any).__corecheck_xss === true).catch(() => false);

      if (isXssTriggered) {
        this.findings.push({
          id: `XSS-TRIGGERED-${Date.now()}`,
          ruleId: 'SEC-XSS-ACTIVE-INJECTION',
          title: 'Vulnerabilidad Ejecutable XSS Reflejado en Cliente',
          severity: 'CRITICAL',
          description: `El campo \`${selector}\` interpretó y ejecutó etiquetas scripts/eventos inline inyectados.`,
          evidence: {
            selector,
            requestPayload: xssPayload
          },
          remediation: {
            explanation: 'Sanitice las entradas antes de inyectarlas en el DOM y aplique Content Security Policy (CSP).',
            codeBefore: `element.innerHTML = input;`,
            codeAfter: `element.textContent = input;`
          },
          standards: {
            owasp: ['A03:2021-Injection'],
            cwe: ['CWE-79']
          }
        });
      }

      if (network500Detected) {
        this.findings.push({
          id: `SERVER-ERROR-500-${Date.now()}`,
          ruleId: 'SEC-UNHANDLED-EXCEPTION',
          title: 'Excepción Interna del Servidor (HTTP 500) tras Fuzzing',
          severity: 'HIGH',
          description: `El envío de caracteres sintácticos en el campo \`${selector}\` provocó un fallo no controlado en el servidor.`,
          evidence: {
            selector,
            requestPayload: xssPayload,
            responseStatus: 500
          },
          remediation: {
            explanation: 'Implemente middlewares de validación de esquemas (DTOs) para filtrar entradas anómalas antes de procesarlas.',
            codeBefore: `app.post('/login', (req, res) => { ... });`,
            codeAfter: `app.post('/login', validateDTO(LoginSchema), (req, res) => { ... });`
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-248']
          }
        });
      }
    } catch (e) {
      // Ignorar excepciones de elementos desmontados dinámicamente
    } finally {
      this.page.off('response', responseListener);
    }
  }
}