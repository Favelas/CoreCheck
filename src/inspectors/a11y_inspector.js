/**
 * Accessibility, DOM & Focus Inspector - CoreCheck Auditor Engine
 */

async function inspectA11yAndDOM(page) {
  const alerts = [];

  try {
    // 1. Título de página
    const title = await page.title();
    if (!title || title.trim() === '') {
      alerts.push('⚠️ ACCESIBILIDAD (A11y): La página no tiene definido un elemento <title>.');
    }

    // 2. Atributo lang en <html>
    const htmlLang = await page.getAttribute('html', 'lang');
    if (!htmlLang) {
      alerts.push('⚠️ ACCESIBILIDAD (A11y): La etiqueta <html> no tiene el atributo "lang" configurado.');
    }

    // 3. Imágenes sin atributo alt
    const imagesWithoutAlt = await page.locator('img:not([alt])').count();
    if (imagesWithoutAlt > 0) {
      alerts.push(`⚠️ ACCESIBILIDAD (A11y): Se encontraron ${imagesWithoutAlt} imágenes sin atributo "alt".`);
    }

    // 4. Navegabilidad y Focus Trap (Keyboard Accessibility)
    const interactiveElements = await page.locator('button:visible, a:visible, input:visible, select:visible, textarea:visible').all();
    
    if (interactiveElements.length > 0) {
      let focusLost = false;
      for (let i = 0; i < Math.min(interactiveElements.length, 5); i++) {
        await page.keyboard.press('Tab');
        const activeTagName = await page.evaluate(() => document.activeElement ? document.activeElement.tagName : null);
        if (!activeTagName || activeTagName === 'BODY') {
          focusLost = true;
          break;
        }
      }

      if (focusLost) {
        alerts.push('⚠️ ACCESIBILIDAD (A11y / Focus): Se detectó pérdida o trampa de foco al navegar secuencialmente con el teclado (Tab key).');
      }
    }

    return {
      title: title || 'Sin Título',
      alerts
    };

  } catch (err) {
    return {
      title: 'ERROR',
      alerts: [`❌ Error en inspección A11y: ${err.message}`]
    };
  }
}

module.exports = { inspectA11yAndDOM };