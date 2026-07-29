import { Page, Request, Response } from 'playwright';
import { AuditFinding } from '../types/audit';

export class FormActiveInspector {
  private page: Page;
  private findings: AuditFinding[] = [];

  constructor(page: Page) {
    this.page = page;
  }

  public async executeActiveFuzzing(): Promise<AuditFinding[]> {
    const inputs = await this.page.locator('input:not([type="hidden"]), textarea').all();

    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i];
      const isVisible = await input.isVisible().catch(() => false);
      if (!isVisible) continue;

      const selector = await input.evaluate((el) => {
        return el.id ? `#${el.id}` : el.getAttribute('name') ? `[name="${el.getAttribute('name')}"]` : el.tagName.toLowerCase();
      });

      // Vector 1: Testing Stored/Reflected XSS Active Injection
      await this.testXSSInjection(input, selector);

      // Vector 2: Boundary / Integer Overflow Stress
      await this.testBoundaryStress(input, selector);
    }

    return this.findings;
  }

  private async testXSSInjection(inputLocator: any, selector: string): Promise<void> {
    const xssPayload = `"><img src=x onerror="window.__corecheck_xss_triggered=true">`;
    let networkErrorDetected = false;

    // Escuchar respuestas de red para capturar fallos 500
    const responseHandler = (response: Response) => {
      if (response.status() >= 500) {
        networkErrorDetected = true;
      }
    };

    this.page.on('response', responseHandler);

    try {
      await inputLocator.fill(xssPayload);
      await inputLocator.press('Tab'); // Trigger blur & validation events

      // Evaluar si el payload ejecutó JS dentro del contexto
      const isXSSExecuted = await this.page.evaluate(() => (window as any).__corecheck_xss_triggered === true);

      if (isXSSExecuted) {
        this.findings.push({
          id: `XSS-ACTIVE-${Date.now()}`,
          ruleId: 'SEC-XSS-ACTIVE-INJECTION',
          title: 'Cross-Site Scripting (XSS) Reflejado/Activo detectado en tiempo de ejecución',
          severity: 'CRITICAL',
          description: `El campo ${selector} no sanitizó correctamente el payload e intentó interpretar atributos de eventos HTML inline.`,
          evidence: {
            selector,
            requestPayload: xssPayload,
            snippet: await inputLocator.evaluate((el: HTMLElement) => el.outerHTML)
          },
          remediation: {
            explanation: 'Sanitice toda entrada de usuario en el servidor usando context-aware encoding y aplique Content Security Policy (CSP) con nonces.',
            codeBefore: `element.innerHTML = userInput;`,
            codeAfter: `element.textContent = userInput;`
          },
          standards: {
            owasp: ['A03:2021-Injection', 'OWASP-WSTG-INPV-01'],
            cwe: ['CWE-79']
          }
        });
      }

      if (networkErrorDetected) {
        this.findings.push({
          id: `ERR-500-${Date.now()}`,
          ruleId: 'SEC-UNHANDLED-INPUT-EXCEPTION',
          title: 'Excepción No Controlada en Servidor (HTTP 500) tras Fuzzing',
          severity: 'HIGH',
          description: `El envío de caracteres especiales en el campo ${selector} provocó un colapso en el backend.`,
          evidence: {
            selector,
            requestPayload: xssPayload,
            responseStatus: 500
          },
          remediation: {
            explanation: 'Implemente un middleware global de manejo de excepciones e impulse la validación estricta de esquemas de entrada (DTOs).',
            codeBefore: `app.post('/api', (req, res) => { process(req.body); });`,
            codeAfter: `app.post('/api', validateDTO(Schema), (req, res, next) => { try { process(req.body); } catch(e) { next(e); } });`
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-248']
          }
        });
      }
    } catch (error) {
      // Manejo silencioso para no interrumpir el flujo si el elemento fue destruido dinámicamente
    } finally {
      this.page.off('response', responseHandler);
    }
  }

  private async testBoundaryStress(inputLocator: any, selector: string): Promise<void> {
    const massivePayload = 'A'.repeat(5000);

    try {
      const startTime = Date.now();
      await inputLocator.fill(massivePayload);
      const duration = Date.now() - startTime;

      if (duration > 2000) {
        this.findings.push({
          id: `PERF-FREEZE-${Date.now()}`,
          ruleId: 'UX-UI-THREAD-FREEZE',
          title: 'Congelamiento del Hilo Principal de UI (Client-Side DoS)',
          severity: 'MEDIUM',
          description: `La inserción de 5,000 caracteres en ${selector} bloqueó el hilo de renderizado durante ${duration}ms.`,
          evidence: {
            selector,
            snippet: `Tiempo de bloqueo: ${duration}ms`
          },
          remediation: {
            explanation: 'Limite la longitud de entrada mediante el atributo `maxlength` e implemente debounce en los event listeners.',
            codeBefore: `<input type="text" onChange={handleChange} />`,
            codeAfter: `<input type="text" maxLength={255} onChange={debouncedHandleChange} />`
          },
          standards: {
            owasp: ['A04:2021-Insecure Design'],
            cwe: ['CWE-400']
          }
        });
      }
    } catch (e) {
      // Captura segura
    }
  }
}