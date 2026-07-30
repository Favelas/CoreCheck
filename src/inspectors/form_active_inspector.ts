import { Page, Response } from 'playwright';
import { AuditFinding } from '../types/audit';

export class FormActiveInspector {
  private page: Page;
  private findings: AuditFinding[] = [];

  constructor(page: Page) {
    this.page = page;
  }

  public async executeActiveFuzzing(): Promise<AuditFinding[]> {
    this.findings = []; // Reiniciar hallazgos para la ejecución
    await this.page.waitForSelector('input, textarea, form, select', { timeout: 10000 }).catch(() => {});

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
    // 2. Inspección Estática/Atributos sobre Entradas de Texto y Controles HTML5
    // -------------------------------------------------------------------------
    const inputs = await this.page.locator('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="image"]), textarea').all();

    for (let i = 0; i < inputs.length; i++) {
      const input = inputs[i];
      const isVisible = await input.isVisible().catch(() => false);
      if (!isVisible) continue;

      const inputType = (await input.getAttribute('type').catch(() => 'text') || 'text').toLowerCase();
      const inputNameAttr = (await input.getAttribute('name').catch(() => '')) || '';
      const inputIdAttr = (await input.getAttribute('id').catch(() => '')) || '';

      const selector = await input.evaluate((el) => {
        const id = el.id ? `#${el.id}` : '';
        const name = el.getAttribute('name') ? `[name="${el.getAttribute('name')}"]` : '';
        return id || name || el.tagName.toLowerCase();
      }).catch(() => 'input');

      // 2.1 Autocomplete en Contraseñas o Datos Sensibles
      if (inputType === 'password' || inputNameAttr.includes('card') || inputNameAttr.includes('cvv')) {
        const autocomplete = await input.getAttribute('autocomplete').catch(() => '');
        if (!autocomplete || (autocomplete !== 'off' && autocomplete !== 'new-password' && autocomplete !== 'current-password')) {
          this.findings.push({
            id: `SEC-PWD-AUTOCOMPLETE-${Date.now()}-${i}`,
            ruleId: 'SEC-INPUT-PASSWORD-AUTOCOMPLETE',
            title: 'Configuración Insegura de Autocompletado en Campo Sensible',
            severity: 'LOW',
            description: `El campo \`${selector}\` no controla explícitamente el autocompletado en caché del navegador.`,
            evidence: { selector },
            remediation: {
              explanation: 'Especifique autocomplete="current-password", "new-password" u "off".',
              codeBefore: `<input type="password" name="password" />`,
              codeAfter: `<input type="password" name="password" autocomplete="current-password" />`
            },
            standards: { owasp: ['A07:2021-Identification and Authentication Failures'], cwe: ['CWE-522'] }
          });
        }
      }

      // 2.2 Verificación MaxLength
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

      // 2.3 Validación de Patrón en Datos de Contacto (pattern)
      const isContact = ['email', 'phone', 'tel', 'correo', 'telefono'].some(k => inputNameAttr.toLowerCase().includes(k));
      if (isContact && inputType === 'text') {
        const pattern = await input.getAttribute('pattern').catch(() => null);
        if (!pattern) {
          this.findings.push({
            id: `CONTACT-NO-PATTERN-${Date.now()}-${i}`,
            ruleId: 'SEC-INPUT-NO-PATTERN',
            title: 'Campo de Contacto tipo text sin Validación de Patrón (pattern)',
            severity: 'LOW',
            description: `El campo \`${selector}\` recibe datos estructurados pero no aplica una restricción regex en el DOM.`,
            evidence: { selector },
            remediation: {
              explanation: 'Utilice el tipo nativo (type="email", type="tel") o especifique un atributo pattern.',
              codeBefore: `<input type="text" name="${inputNameAttr}">`,
              codeAfter: `<input type="email" name="${inputNameAttr}" pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$">`
            },
            standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-20'] }
          });
        }
      }

      // 2.4 Control de Archivos sin extensión (accept)
      if (inputType === 'file') {
        const acceptAttr = await input.getAttribute('accept').catch(() => null);
        if (!acceptAttr) {
          this.findings.push({
            id: `FILE-NO-ACCEPT-${Date.now()}-${i}`,
            ruleId: 'SEC-FILE-NO-ACCEPT-LIMIT',
            title: 'Selector de Archivos sin Restricción de Extensiones (accept)',
            severity: 'MEDIUM',
            description: `El selector de archivos \`${selector}\` permite seleccionar cualquier tipo de archivo sin filtro previo.`,
            evidence: { selector },
            remediation: {
              explanation: 'Configure el atributo accept para limitar los tipos de archivos permitidos a nivel visual.',
              codeBefore: `<input type="file" name="${inputNameAttr}">`,
              codeAfter: `<input type="file" name="${inputNameAttr}" accept=".pdf,.png,.jpg">`
            },
            standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-434'] }
          });
        }
      }

      // 2.5 Campo Numérico sin Mínimo (min)
      if (inputType === 'number') {
        const hasMin = await input.getAttribute('min').catch(() => null);
        if (!hasMin) {
          this.findings.push({
            id: `NUMBER-NO-MIN-${Date.now()}-${i}`,
            ruleId: 'SEC-INPUT-NUMBER-NO-MIN',
            title: 'Campo Numérico sin Valor Mínimo Definido (min)',
            severity: 'LOW',
            description: `El campo \`${selector}\` permite ingresar valores negativos sin restricción en interfaz.`,
            evidence: { selector },
            remediation: {
              explanation: 'Especifique el límite inferior utilizando el atributo min.',
              codeBefore: `<input type="number" name="${inputNameAttr}">`,
              codeAfter: `<input type="number" name="${inputNameAttr}" min="0">`
            },
            standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-20'] }
          });
        }
      }

      // 2.6 Pruebas Activas de Fuzzing (Solo para inputs interactivos de texto/textarea)
      if (['text', 'search', 'url', 'textarea'].includes(inputType) || !inputType) {
        await this.executePayloadFuzzing(input, selector);
      }
    }

    // -------------------------------------------------------------------------
    // 3. Auditoría de Listas Desplegables (<select>)
    // -------------------------------------------------------------------------
    const selects = await this.page.locator('select').all();
    for (let i = 0; i < selects.length; i++) {
      const select = selects[i];
      if (!(await select.isVisible().catch(() => false))) continue;

      const options = await select.locator('option').all();
      const selectName = (await select.getAttribute('name').catch(() => '')) || `Select #${i + 1}`;

      if (options.length <= 1) {
        this.findings.push({
          id: `SELECT-FEW-OPTIONS-${Date.now()}-${i}`,
          ruleId: 'UX-SELECT-INSUFFICIENT-OPTIONS',
          title: 'Desplegable (select) con Menos de Dos Opciones',
          severity: 'INFO',
          description: `El elemento select \`${selectName}\` solo posee ${options.length} opción(es) disponible(s).`,
          evidence: { snippet: `<select name="${selectName}"></select>` },
          remediation: {
            explanation: 'Verifique si el menú desplegable requiere datos dinámicos o si debe reemplazarse por un control estático.',
            codeBefore: `<select name="${selectName}"><option>Única</option></select>`,
            codeAfter: `<select name="${selectName}"><option value="">Seleccione...</option><option value="1">Opción 1</option></select>`
          },
          standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-1188'] }
        });
      }

      const firstOptionText = (await options[0]?.innerText().catch(() => '')) || '';
      if (firstOptionText.trim() === '' && !(await select.getAttribute('required').catch(() => false))) {
        this.findings.push({
          id: `SELECT-NO-PLACEHOLDER-${Date.now()}-${i}`,
          ruleId: 'UX-SELECT-NO-DEFAULT-LABEL',
          title: 'Desplegable sin Opción Inicial o Placeholder Indicativo',
          severity: 'INFO',
          description: `El menú desplegable \`${selectName}\` posee una opción inicial en blanco sin estar marcado como obligatorio.`,
          evidence: { snippet: `<select name="${selectName}"></select>` },
          remediation: {
            explanation: 'Agregue una opción por defecto con texto descriptivo y atributo disabled.',
            codeBefore: `<select name="${selectName}"><option value=""></option></select>`,
            codeAfter: `<select name="${selectName}"><option value="" disabled selected>Seleccione una opción</option></select>`
          },
          standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-1188'] }
        });
      }
    }

    // -------------------------------------------------------------------------
    // 4. Auditoría Lógica en Campos de Fecha
    // -------------------------------------------------------------------------
    const dateInputs = await this.page
      .locator('input[type="date"], input[type="datetime-local"], input[name*="date" i], input[name*="fecha" i]')
      .all();

    for (let i = 0; i < dateInputs.length; i++) {
      const dateInput = dateInputs[i];
      if (!(await dateInput.isVisible().catch(() => false))) continue;

      const name = ((await dateInput.getAttribute('name').catch(() => '')) || '').toLowerCase();
      const min = await dateInput.getAttribute('min').catch(() => null);
      const max = await dateInput.getAttribute('max').catch(() => null);

      const isBirthDate = name.includes('birth') || name.includes('nacimiento') || name.includes('dob');
      const isBooking = name.includes('checkin') || name.includes('reserva') || name.includes('booking') || name.includes('expir');

      if (isBirthDate && min && new Date(min) > new Date()) {
        this.findings.push({
          id: `DATE-BIRTH-INVALID-MIN-${Date.now()}-${i}`,
          ruleId: 'BIZ-DATE-BIRTH-RESTRICTION-ERROR',
          title: 'Restricción de Fecha de Nacimiento Inválida (min futuro)',
          severity: 'HIGH',
          description: `El campo de fecha de nacimiento \`${name}\` exige un valor mínimo situado en el futuro (\`${min}\`).`,
          evidence: { snippet: `<input type="date" name="${name}" min="${min}">` },
          remediation: {
            explanation: 'Asegúrese de que el límite inferior permita registrar fechas de nacimiento pasadas.',
            codeBefore: `<input type="date" name="${name}" min="2030-01-01">`,
            codeAfter: `<input type="date" name="${name}" max="${new Date().toISOString().split('T')[0]}">`
          },
          standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-840'] }
        });
      }

      if (isBooking && max && new Date(max) < new Date()) {
        this.findings.push({
          id: `DATE-BOOKING-INVALID-MAX-${Date.now()}-${i}`,
          ruleId: 'BIZ-DATE-BOOKING-RESTRICTION-ERROR',
          title: 'Restricción de Fecha de Reserva o Vencimiento Inválida (max pasado)',
          severity: 'HIGH',
          description: `El campo de reserva/expiración \`${name}\` bloquea la selección de fechas futuras (\`${max}\`).`,
          evidence: { snippet: `<input type="date" name="${name}" max="${max}">` },
          remediation: {
            explanation: 'Configure la cota max para permitir seleccionar fechas vigentes o futuras.',
            codeBefore: `<input type="date" name="${name}" max="2010-01-01">`,
            codeAfter: `<input type="date" name="${name}" min="${new Date().toISOString().split('T')[0]}">`
          },
          standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-840'] }
        });
      }
    }

    // -------------------------------------------------------------------------
    // 5. Validación Inline y Accesibilidad (A11y / ARIA Live Alerts)
    // -------------------------------------------------------------------------
    for (let f = 0; f < forms.length; f++) {
      const form = forms[f];
      if (!(await form.isVisible().catch(() => false))) continue;

      const submitBtn = form.locator('button[type="submit"], input[type="submit"]').first();
      const requiredInputs = await form.locator('input[required], select[required], textarea[required]').count().catch(() => 0);

      if ((await submitBtn.count().catch(() => 0)) > 0 && requiredInputs > 0) {
        await submitBtn.click({ force: true }).catch(() => {});
        await this.page.waitForTimeout(300);

        const hasAccessibleAlerts = await this.page
          .locator('[role="alert"], [aria-live="polite"], [aria-live="assertive"], .error-message, .invalid-feedback')
          .count()
          .catch(() => 0);

        if (hasAccessibleAlerts === 0) {
          this.findings.push({
            id: `FORM-A11Y-NO-ALERT-${Date.now()}-${f}`,
            ruleId: 'UX-A11Y-MISSING-ACCESSIBLE-INLINE-ERROR',
            title: 'Ausencia de Mensajes de Error Accesibles (role="alert" / aria-live)',
            severity: 'LOW',
            description: 'Al activar el evento submit en un formulario incompleto, no se detectaron contenedores accesibles para lectores de pantalla.',
            evidence: { snippet: `<form id="form_${f}">` },
            remediation: {
              explanation: 'Asegure que los mensajes de error incluyan role="alert" o aria-live="polite".',
              codeBefore: `<span class="error">Campo requerido</span>`,
              codeAfter: `<span class="error" role="alert" aria-live="polite">Campo requerido</span>`
            },
            standards: { owasp: ['A04:2021-Insecure Design'], cwe: ['CWE-1188'] }
          });
        }
      }
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

        await inputLocator.focus().catch(() => {});
        await inputLocator.fill('').catch(() => {}); // Limpiar antes de inyectar
        await inputLocator.fill(payload.value).catch(() => {});
        await inputLocator.dispatchEvent('input').catch(() => {});
        await inputLocator.dispatchEvent('change').catch(() => {});
        await inputLocator.press('Tab').catch(() => {});

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