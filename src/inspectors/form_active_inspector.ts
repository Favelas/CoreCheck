import { Page, Response } from 'playwright';
import { AuditFinding } from '../types/audit';

export class FormActiveInspector {
  private page: Page;
  private findings: AuditFinding[] = [];

  constructor(page: Page) {
    this.page = page;
  }

  public async executeActiveFuzzing(): Promise<AuditFinding[]> {
    await this.page.waitForSelector('input, textarea, form', { timeout: 10000 }).catch(() => {});

    // -------------------------------------------------------------------------
    // 1. Verificación Estructural de Formulario (CSRF & Action Endpoint)
    // -------------------------------------------------------------------------
    const forms = await this.page.locator('form').all();
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      const action = (await form.getAttribute('action').catch(() => '')) || '';
      const method = (await form.getAttribute('method').catch(() => 'get') || 'get').toUpperCase();

      // Detección de envío inseguro HTTP
      if (action.startsWith('http://')) {
        this.findings.push({
          id: `FORM-INSECURE-ACTION-${Date.now()}-${i}`,
          ruleId: 'SEC-FORM-INSECURE-TRANSPORT',
          title: 'Envío de Formulario sobre Protocolo Inseguro (HTTP)',
          severity: 'HIGH',
          description: `El formulario con action '${action}' envía credenciales o datos sin cifrado TLS.`,
          evidence: { snippet: await form.evaluate((el: HTMLElement) => el.outerHTML).catch(() => '') },
          remediation: {
            explanation: 'Asegúrese de que todos los endpoints de formularios apunten a esquemas HTTPS cifrados.',
            codeBefore: `<form action="http://api.domain.com/login">`,
            codeAfter: `<form action="https://api.domain.com/login">`
          },
          standards: { owasp: ['A02:2021-Cryptographic Failures'], cwe: ['CWE-319'] }
        });
      }

      // Verificación de Protección CSRF para formularios POST
      if (method === 'POST') {
        const hasCsrfInput = await form.locator('input[name*="csrf" i], input[name*="token" i]').count().catch(() => 0);
        if (hasCsrfInput === 0) {
          this.findings.push({
            id: `FORM-NO-CSRF-${Date.now()}-${i}`,
            ruleId: 'SEC-FORM-MISSING-CSRF-TOKEN',
            title: 'Ausencia de Token Anticlonación/CSRF en Formulario POST',
            severity: 'MEDIUM',
            description: 'El formulario POST no incluye un input oculto con token CSRF de validación.',
            evidence: { snippet: await form.evaluate((el: HTMLElement) => el.outerHTML).catch(() => '') },
            remediation: {
              explanation: 'Inyecte un Anti-CSRF Token único por sesión en los formularios para prevenir falsificación de peticiones.',
              codeBefore: `<form method="POST">`,
              codeAfter: `<form method="POST"><input type="hidden" name="_csrf" value="TOKEN" /></form>`
            },
            standards: { owasp: ['A01:2021-Broken Access Control'], cwe: ['CWE-352'] }
          });
        }
      }
    }

    // -------------------------------------------------------------------------
    // 2. Inspección Activa y Fuzzing sobre Entradas de Texto
    // -------------------------------------------------------------------------
    const inputs = await this.page.locator('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="image"]), textarea').all();

    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i];
      const isVisible = await input.isVisible().catch(() => false);
      if (!isVisible) continue;

      const inputType = (await input.getAttribute('type').catch(() => 'text') || 'text').toLowerCase();
      const selector = await input.evaluate((el) => {
        const id = el.id ? `#${el.id}` : '';
        const name = el.getAttribute('name') ? `[name="${el.getAttribute('name')}"]` : '';
        return id || name || el.tagName.toLowerCase();
      }).catch(() => 'input');

      // Verificación de Autocomplete en Passwords
      if (inputType === 'password') {
        const autocomplete = await input.getAttribute('autocomplete').catch(() => '');
        if (autocomplete !== 'off' && autocomplete !== 'new-password' && autocomplete !== 'current-password') {
          this.findings.push({
            id: `SEC-PWD-AUTOCOMPLETE-${Date.now()}-${i}`,
            ruleId: 'SEC-INPUT-PASSWORD-AUTOCOMPLETE',
            title: 'Configuración Insegura de Autocompletado en Campo de Contraseña',
            severity: 'LOW',
            description: `El campo \`${selector}\` no restringe explícitamente la memoria en caché del navegador para passwords.`,
            evidence: { selector },
            remediation: {
              explanation: 'Especifique autocomplete="current-password" o "new-password" según el flujo de autenticación.',
              codeBefore: `<input type="password" name="password" />`,
              codeAfter: `<input type="password" name="password" autocomplete="current-password" />`
            },
            standards: { owasp: ['A07:2021-Identification and Authentication Failures'], cwe: ['CWE-522'] }
          });
        }
      }

      // Verificación MaxLength
      const hasMaxLength = await input.getAttribute('maxlength').catch(() => null);
      if (!hasMaxLength) {
        this.findings.push({
          id: `MAXLENGTH-MISSING-${Date.now()}-${i}`,
          ruleId: 'SEC-DOM-NO-MAXLENGTH',
          title: 'Ausencia de Atributo HTML maxlength en Campo de Entrada',
          severity: 'LOW',
          description: `El campo \`${selector}\` no limita la entrada de caracteres en el DOM nativo.`,
          evidence: {
            selector,
            snippet: await input.evaluate((el: HTMLElement) => el.outerHTML).catch(() => '')
          },
          remediation: {
            explanation: 'Declare el atributo `maxlength` explícitamente en el elemento HTML.',
            codeBefore: `<input type="text" name="username" />`,
            codeAfter: `<input type="text" name="username" maxlength="50" />`
          },
          standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-20'] }
        });
      }

      // Pruebas Activas de Fuzzing
      await this.executePayloadFuzzing(input, selector);
    }

    return this.findings;
  }

  private async executePayloadFuzzing(inputLocator: any, selector: string): Promise<void> {
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

    for (const payload of fuzzPayloads) {
      let network500Detected = false;
      const responseListener = (response: Response) => {
        if (response.status() >= 500) {
          network500Detected = true;
        }
      };

      this.page.on('response', responseListener);

      try {
        await this.page.evaluate(() => { (window as any).__corecheck_xss = false; }).catch(() => {});

        await inputLocator.focus();
        await inputLocator.fill(''); // Limpiar antes de inyectar
        await inputLocator.fill(payload.value);
        await inputLocator.dispatchEvent('input');
        await inputLocator.dispatchEvent('change');
        await inputLocator.press('Tab');

        await this.page.waitForTimeout(400);

        if (payload.type === 'XSS') {
          const isXssTriggered = await this.page.evaluate(() => (window as any).__corecheck_xss === true).catch(() => false);
          if (isXssTriggered) {
            this.findings.push({
              id: `XSS-TRIGGERED-${Date.now()}`,
              ruleId: payload.ruleId,
              title: 'Vulnerabilidad Ejecutable XSS Reflejado en Cliente',
              severity: payload.severity,
              description: `El campo \`${selector}\` interpretó y ejecutó etiquetas scripts/eventos inline inyectados.`,
              evidence: { selector, requestPayload: payload.value },
              remediation: {
                explanation: 'Sanitice las entradas antes de inyectarlas en el DOM y aplique Content Security Policy (CSP).',
                codeBefore: `element.innerHTML = input;`,
                codeAfter: `element.textContent = input;`
              },
              standards: { owasp: payload.owasp, cwe: payload.cwe }
            });
          }
        }

        if (network500Detected) {
          this.findings.push({
            id: `SERVER-ERROR-500-${Date.now()}`,
            ruleId: 'SEC-UNHANDLED-EXCEPTION',
            title: `Excepción Interna del Servidor (HTTP 500) tras Fuzzing (${payload.type})`,
            severity: 'HIGH',
            description: `El envío del vector '${payload.type}' en \`${selector}\` provocó un fallo no controlado en el servidor.`,
            evidence: { selector, requestPayload: payload.value, responseStatus: 500 },
            remediation: {
              explanation: 'Implemente middlewares de validación de esquemas para filtrar entradas anómalas.',
              codeBefore: `app.post('/login', (req, res) => { ... });`,
              codeAfter: `app.post('/login', validateDTO(LoginSchema), (req, res) => { ... });`
            },
            standards: { owasp: ['A05:2021-Security Misconfiguration'], cwe: ['CWE-248'] }
          });
        }

        // Limpiar el campo al finalizar la prueba
        await inputLocator.fill('').catch(() => {});
      } catch {
        // Ignorar excepciones por desmonte de elementos
      } finally {
        this.page.off('response', responseListener);
      }
    }
  }
}