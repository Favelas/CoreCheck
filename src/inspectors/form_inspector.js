/**
 * Form Inspector - Advanced Controls, Inline Validation & HTML5 Defensive Attributes
 * CoreCheck Auditor Engine
 */

async function inspectForms(page) {
  const alerts = [];
  const detections = [];

  try {
    const forms = await page.locator('form').all();
    detections.push(`Formularios detectados: ${forms.length}`);

    // --- A. AUDITORÍA DE LÍMITES DE ENTRADA (Maxlength) ---
    const textInputs = await page.locator('input[type="text"], input[type="password"], input[type="email"], input:not([type])').all();
    
    for (const input of textInputs) {
      if (!(await input.isVisible().catch(() => false))) continue;

      const hasMaxLength = await input.getAttribute('maxlength');
      const inputName = (await input.getAttribute('name')) || 
                        (await input.getAttribute('id')) || 
                        (await input.getAttribute('placeholder')) || 
                        'Campo de Texto';

      if (!hasMaxLength) {
        alerts.push(`⚠️ FORMULARIO (Límite de Entrada): El campo \`${inputName}\` no define el atributo HTML \`maxlength\`. Confía únicamente en validación por JS o Backend.`);
      }
    }

    // --- B. AUDITORÍA DE ATRIBUTOS DEFENSIVOS (Pattern, Accept, Min/Max, Autocomplete) ---
    
    // 1. Campos de contacto (email/teléfono) que usan type="text" sin 'pattern'
    const contactInputs = await page.locator('input[name*="email"], input[name*="phone"], input[name*="tel"], input[name*="correo"], input[name*="telefono"]').all();
    for (const input of contactInputs) {
      if (!(await input.isVisible().catch(() => false))) continue;
      const type = await input.getAttribute('type');
      const pattern = await input.getAttribute('pattern');
      const name = (await input.getAttribute('name')) || (await input.getAttribute('id')) || 'Campo de Contacto';

      if (type === 'text' && !pattern) {
        alerts.push(`⚠️ FORMULARIO (Validación de Formato): El campo \`${name}\` usa \`type="text"\` y no define el atributo \`pattern\` para validar la estructura del dato en el DOM.`);
      }
    }

    // 2. Carga de archivos sin restricción de extensiones ('accept')
    const fileInputs = await page.locator('input[type="file"]').all();
    for (const fileInput of fileInputs) {
      if (!(await fileInput.isVisible().catch(() => false))) continue;
      const acceptAttr = await fileInput.getAttribute('accept');
      const name = (await fileInput.getAttribute('name')) || (await fileInput.getAttribute('id')) || 'Upload Input';

      if (!acceptAttr) {
        alerts.push(`🔒 SEGURIDAD / UX: El selector de archivos \`${name}\` no define el atributo \`accept\` para limitar las extensiones permitidas.`);
      }
    }

    // 3. Inputs numéricos sin 'min' / 'max'
    const numberInputs = await page.locator('input[type="number"]').all();
    for (const numInput of numberInputs) {
      if (!(await numInput.isVisible().catch(() => false))) continue;
      const hasMin = await numInput.getAttribute('min');
      const name = (await numInput.getAttribute('name')) || (await numInput.getAttribute('id')) || 'Campo Numérico';

      if (!hasMin) {
        alerts.push(`⚠️ FORMULARIO (Rango Numérico): El campo \`${name}\` no especifica el valor mínimo (\`min\`), permitiendo ingresar valores negativos directamente.`);
      }
    }

    // 4. Campos sensibles sin autocompletado controlado
    const sensitiveInputs = await page.locator('input[type="password"], input[name*="card"], input[name*="cvv"], input[name*="pin"]').all();
    for (const sInput of sensitiveInputs) {
      if (!(await sInput.isVisible().catch(() => false))) continue;
      const autocomplete = await sInput.getAttribute('autocomplete');
      const name = (await sInput.getAttribute('name')) || (await sInput.getAttribute('id')) || 'Campo Sensible';

      if (!autocomplete) {
        alerts.push(`🔒 SEGURIDAD: El campo sensible \`${name}\` no define el atributo \`autocomplete\` (\`current-password\`, \`new-password\` u \`off\`).`);
      }
    }

    // --- C. AUDITORÍA DE DROPDOWNS / SELECTS (DDLs) ---
    const selects = await page.locator('select').all();
    if (selects.length > 0) {
      detections.push(`Dropdowns (select) detectados: ${selects.length}`);
      
      for (let i = 0; i < selects.length; i++) {
        const select = selects[i];
        if (!(await select.isVisible().catch(() => false))) continue;

        const options = await select.locator('option').all();
        const selectName = (await select.getAttribute('name')) || (await select.getAttribute('id')) || `Select #${i + 1}`;

        if (options.length <= 1) {
          alerts.push(`⚠️ FORMULARIO (DDL): El desplegable \`${selectName}\` tiene menos de 2 opciones disponibles.`);
        }

        const firstOptionText = (await options[0]?.innerText().catch(() => '')) || '';
        if (firstOptionText.trim() === '' && !(await select.getAttribute('required'))) {
          alerts.push(`⚠️ FORMULARIO (DDL): El desplegable \`${selectName}\` no tiene una opción inicial o placeholder explícito.`);
        }
      }
    }

    // --- D. AUDITORÍA DE CAMPOS FECHA (DatePickers / Inputs Date) ---
    const dateInputs = await page.locator('input[type="date"], input[type="datetime-local"], input[name*="date"], input[name*="fecha"]').all();
    
    if (dateInputs.length > 0) {
      detections.push(`Campos de Fecha detectados: ${dateInputs.length}`);

      for (const dateInput of dateInputs) {
        if (!(await dateInput.isVisible().catch(() => false))) continue;

        const name = ((await dateInput.getAttribute('name')) || (await dateInput.getAttribute('id')) || '').toLowerCase();
        const min = await dateInput.getAttribute('min');
        const max = await dateInput.getAttribute('max');

        const isBirthDate = name.includes('birth') || name.includes('nacimiento') || name.includes('dob');
        const isBooking = name.includes('checkin') || name.includes('reserva') || name.includes('booking') || name.includes('expir');

        if (isBirthDate && min && new Date(min) > new Date()) {
          alerts.push(`🚨 LÓGICA DE NEGOCIO: El campo de nacimiento \`${name}\` restringe fechas pasadas de forma inválida.`);
        }

        if (isBooking && max && new Date(max) < new Date()) {
          alerts.push(`🚨 LÓGICA DE NEGOCIO: El campo de reserva/expiración \`${name}\` bloquea fechas futuras.`);
        }
      }
    }

    // --- E. AUDITORÍA DE ERRORES INLINE / VALIDACIÓN CLIENTE ---
    for (let f = 0; f < forms.length; f++) {
      const form = forms[f];
      if (!(await form.isVisible().catch(() => false))) continue;

      const submitBtn = await form.locator('button[type="submit"], input[type="submit"]').first();
      const requiredInputs = await form.locator('input[required], select[required], textarea[required]').count();

      if ((await submitBtn.count()) > 0 && requiredInputs > 0) {
        await submitBtn.click({ force: true }).catch(() => {});
        await page.waitForTimeout(300);

        const hasAccessibleAlerts = await page.locator('[role="alert"], [aria-live="polite"], [aria-live="assertive"], .error-message, .invalid-feedback').count();

        if (hasAccessibleAlerts === 0) {
          alerts.push(`⚠️ UX / A11Y (Formularios): Al intentar enviar un formulario incompleto, no se detectaron mensajes de error accesibles (\`role="alert"\` o \`aria-live\`).`);
        }
      }
    }

  } catch (err) {
    alerts.push(`❌ EXCEPCIÓN (Form Inspector): ${err.message}`);
  }

  return { alerts, detections };
}

module.exports = { inspectForms };