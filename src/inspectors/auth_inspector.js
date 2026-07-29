/**
 * Auth, User Management & Session Security Inspector
 * CoreCheck Auditor Engine
 */

async function inspectAuth(page) {
  const alerts = [];
  const detections = [];

  try {
    const pageUrl = page.url().toLowerCase();
    const isAuthPage = pageUrl.includes('login') || pageUrl.includes('signin') || pageUrl.includes('register') || pageUrl.includes('auth');

    // --- A. AUDITORÍA DE CONTRASEÑAS & AUTENTICACIÓN ---
    if (isAuthPage) {
      detections.push('🔑 Módulo de Autenticación y Usuarios Activo');

      const passwordInputs = await page.locator('input[type="password"]').all();
      for (const passInput of passwordInputs) {
        const autocomplete = await passInput.getAttribute('autocomplete');
        if (!autocomplete) {
          alerts.push('🔒 SEGURIDAD (Auth): El campo de contraseña no especifica la directiva `autocomplete` ("current-password" o "new-password").');
        }
      }

      if (!pageUrl.startsWith('https://') && !pageUrl.includes('localhost')) {
        alerts.push('🚨 CRÍTICO (Auth): La página de autenticación no se transmite bajo un protocolo cifrado HTTPS.');
      }
    }

    // --- B. AUDITORÍA DE COOKIES Y TIEMPOS DE SESIÓN ---
    const cookies = await page.context().cookies();
    
    for (const cookie of cookies) {
      const isSessionCookie = cookie.name.toLowerCase().includes('session') || 
                              cookie.name.toLowerCase().includes('token') || 
                              cookie.name.toLowerCase().includes('auth') ||
                              cookie.name.toLowerCase().includes('jwt');

      if (isSessionCookie) {
        // Regla 1: HttpOnly (Previene XSS cookie theft)
        if (!cookie.httpOnly) {
          alerts.push(`🚨 CRÍTICO (Seguridad de Sesión): La cookie de autenticación \`${cookie.name}\` carece de la bandera \`HttpOnly\`. Vulnerable a robo de sesión por XSS.`);
        }

        // Regla 2: Secure flag
        if (!cookie.secure && !pageUrl.includes('localhost')) {
          alerts.push(`🔒 SEGURIDAD (Seguridad de Sesión): La cookie \`${cookie.name}\` no exige transmisión cifrada (\`Secure\` flag).`);
        }

        // Regla 3: SameSite (Protección CSRF)
        if (!cookie.sameSite || cookie.sameSite.toLowerCase() === 'none') {
          alerts.push(`⚠️ SEGURIDAD (CSRF): La cookie \`${cookie.name}\` no tiene una directiva \`SameSite\` estricta (Lax o Strict).`);
        }
      }
    }

  } catch (err) {
    alerts.push(`❌ EXCEPCIÓN (Auth Inspector): ${err.message}`);
  }

  return { alerts, detections };
}

module.exports = { inspectAuth };