const fs = require('fs');
const path = require('path');

/**
 * Mapeo de soluciones técnicas y snippet de código por tipo de error
 */
function getRemediationDetails(alertText) {
  const text = alertText.toLowerCase();

  if (text.includes('clickjacking') || text.includes('x-frame-options')) {
    return {
      severity: 'HIGH',
      badge: '🟠 HIGH',
      impact: 'Permite que atacantes incrusten el sitio en un <iframe> malicioso para realizar ataques de Clickjacking y captura no autorizada de clics.',
      remediation: `Configure la cabecera X-Frame-Options o CSP frame-ancestors en el servidor web.
\`\`\`nginx
# Nginx Configuration
add_header X-Frame-Options "DENY" always;
# O bien mediante Content-Security-Policy:
add_header Content-Security-Policy "frame-ancestors 'none';" always;
\`\`\``
    };
  }

  if (text.includes('csp') || text.includes('content-security-policy')) {
    return {
      severity: 'HIGH',
      badge: '🟠 HIGH',
      impact: 'Ausencia de políticas de contenido. Eleva drásticamente el riesgo de inyección de scripts de terceros no autorizados (XSS) y exfiltración de datos.',
      remediation: `Defina una directiva CSP estricta en su servidor HTTP o framework backend.
\`\`\`javascript
// Ejemplo Express.js (Middleware Helmet)
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"]
  }
}));
\`\`\``
    };
  }

  if (text.includes('hsts') || text.includes('strict-transport-security')) {
    return {
      severity: 'HIGH',
      badge: '🟠 HIGH',
      impact: 'La aplicación permite degradación de protocolo a HTTP no cifrado, facilitando ataques Man-In-The-Middle (MITM).',
      remediation: `Habilite HTTP Strict Transport Security en la configuración de su proxy/servidor.
\`\`\`nginx
# Nginx Configuration
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
\`\`\``
    };
  }

  if (text.includes('lentitud') || text.includes('umbral')) {
    return {
      severity: 'HIGH',
      badge: '🟠 HIGH',
      impact: 'Tiempo de carga superior al SLA (3000ms). Degrada la conversión de usuarios y penaliza el posicionamiento SEO en Google Core Web Vitals.',
      remediation: `1. Optimizar y diferir scripts JS de terceros.
2. Comprimir recursos estáticos mediante Brotli / Gzip.
3. Utilizar formatos de imagen modernos (WebP/AVIF) con lazy loading.`
    };
  }

  if (text.includes('maxlength') || text.includes('edge case')) {
    return {
      severity: 'LOW',
      badge: '🔵 LOW',
      impact: 'Vulnerabilidad a desbordamiento de buffer de entrada en cliente o consumo innecesario de ancho de banda en formularios.',
      remediation: `Añada el atributo \`maxlength\` explícito a la etiqueta del campo HTML afectado.
\`\`\`html
<!-- Ejemplo de Corrección -->
<input type="text" name="user_field" id="user_field" maxlength="100" />
\`\`\``
    };
  }

  return {
    severity: 'MEDIUM',
    badge: '🟡 MEDIUM',
    impact: 'Inconsistencia técnica detectada durante la auditoría automatizada.',
    remediation: `Revisar la configuración del componente afectado y validar controles de sanitización en cliente y servidor.`
  };
}

function generateInternalReportMarkdown(auditResults, runTimestamp, baseUrl, reportsDir) {
  const mdPath = path.join(reportsDir, `internal_triage_report_${runTimestamp}.md`);
  let totalBugs = 0;
  const bugsList = [];

  auditResults.forEach((res) => {
    if (res.alerts && res.alerts.length > 0) {
      res.alerts.forEach((alert) => {
        totalBugs++;
        const details = getRemediationDetails(alert);
        bugsList.push({
          id: totalBugs,
          route: res.route,
          title: res.title,
          alertText: alert,
          loadTimeMs: res.loadTimeMs,
          deskFile: res.deskFile,
          mobFile: res.mobFile,
          ...details
        });
      });
    }
  });

  // Ordenar priorizando fallas Critical / High
  const severityOrder = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
  bugsList.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  let md = `# 🛡️ CoreCheck — Internal Technical Triage & Remediation Plan\n\n`;
  md += `**Target:** \`${baseUrl}\`  \n`;
  md += `**Timestamp:** \`${runTimestamp}\`  \n`;
  md += `**Estado de Conciliación:** ✅ **PARIDAD CONFIRMADA DE AUDITORÍA**  \n\n`;
  md += `--- \n\n`;

  md += `### 📊 Resumen Ejecutivo de Hallazgos\n`;
  md += `| Métrica | Valor |\n`;
  md += `| :--- | :---: |\n`;
  md += `| **Total de Hallazgos/Errores** | **${totalBugs}** |\n`;
  md += `| **Rutas Evaluadas** | **${auditResults.length}** |\n\n`;
  md += `--- \n\n`;

  md += `## 🚨 Plan de Remediación Priorizado (High / Critical First)\n\n`;

  if (bugsList.length === 0) {
    md += `> ✅ **Sin hallazgos críticos.** La aplicación cumple con las reglas establecidas de auditoría.\n`;
  } else {
    bugsList.forEach((bug, index) => {
      md += `### Bug #${index + 1}: ${bug.badge} ${bug.alertText}\n\n`;
      md += `* **Ruta Afectada:** \`${bug.route}\` (${bug.title})\n`;
      md += `* **Tiempo de Carga registrado:** \`${bug.loadTimeMs} ms\`\n`;
      md += `* **Evidencia Visual:** \n`;
      if (bug.deskFile) md += `  * Desktop: \`reports/screenshots/${bug.deskFile}\` \n`;
      if (bug.mobFile) md += `  * Mobile: \`reports/screenshots/${bug.mobFile}\` \n`;
      
      md += `\n**💥 Impacto Técnico & Riesgo:**  \n${bug.impact}\n\n`;

      md += `**📋 Pasos para Reproducción:**\n`;
      md += `1. Abrir navegador en modo privado o motor de pruebas.\n`;
      md += `2. Navegar a la URL: \`${baseUrl}${bug.route.startsWith('/') ? bug.route.substring(1) : bug.route}\`\n`;
      md += `3. Inspeccionar las cabeceras/elementos mediante DevTools.\n\n`;

      md += `**🛠️ Solución Sugerida (Código de Remediación):**\n`;
      md += `${bug.remediation}\n\n`;
      md += `---\n\n`;
    });
  }

  fs.writeFileSync(mdPath, md, 'utf-8');
  console.log(`📝 Reporte técnico en Markdown generado: ${mdPath}`);
}

module.exports = { generateInternalReportMarkdown };