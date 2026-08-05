import { AuditFinding } from '../types/audit.js';

export class HeadersConfigInspector {
  /**
   * Inspecciona la respuesta principal HTTP y evalúa la presencia/configuración de cabeceras de seguridad.
   * Recibe el status y las cabeceras directamente para evitar segundas navegaciones en la página.
   */
  public inspectHeadersFromResponse(
    targetUrl: string,
    status: number,
    headers: Record<string, string>
  ): AuditFinding[] {
    const findings: AuditFinding[] = [];

    // Normalizar todas las llaves de cabeceras a minúsculas para comparaciones consistentes
    const lowerHeaders: Record<string, string> = {};
    Object.keys(headers).forEach((key) => {
      lowerHeaders[key.toLowerCase()] = headers[key];
    });

    // 1. Content-Security-Policy (CSP)
    if (!lowerHeaders['content-security-policy']) {
      findings.push(
        this.securityHeaderFinding({
          id: `HDR-CSP-${Date.now()}`,
          ruleId: 'SEC-HDR-CSP-MISSING',
          title: 'Ausencia de Cabecera Content-Security-Policy (CSP)',
          severity: 'HIGH',
          description:
            'La aplicación no define una política de seguridad de contenido (CSP). Esto permite la ejecución ilimitada de scripts de terceros e inyecciones XSS.',
          evidence: {
            responseStatus: status,
            responseHeaders: headers,
            snippet: 'Content-Security-Policy: [NO PRESENT]'
          },
          remediation: {
            explanation:
              'Defina una cabecera CSP restringiendo el origen de scripts, estilos y marcos ejecutables.',
            codeBefore: '// Cabecera omitida',
            codeAfter: "Content-Security-Policy: default-src 'self'; script-src 'self';"
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-1021: Improper Restriction of Rendered UI Layers or Frames']
          }
        })
      );
    }

    // 2. Strict-Transport-Security (HSTS)
    if (targetUrl.startsWith('https://') && !lowerHeaders['strict-transport-security']) {
      findings.push(
        this.securityHeaderFinding({
          id: `HDR-HSTS-${Date.now()}`,
          ruleId: 'SEC-HDR-HSTS-MISSING',
          title: 'Ausencia de Cabecera Strict-Transport-Security (HSTS)',
          severity: 'HIGH',
          description:
            'El servidor responde mediante HTTPS pero no fuerza la conexión cifrada a través de la cabecera HSTS, dejando la sesión vulnerable a ataques de SSL Stripping.',
          evidence: {
            responseStatus: status,
            responseHeaders: headers,
            snippet: 'Strict-Transport-Security: [NO PRESENT]'
          },
          remediation: {
            explanation:
              'Configure la cabecera HSTS con un tiempo de vida (max-age) adecuado de al menos 1 año.',
            codeBefore: '// Cabecera omitida',
            codeAfter: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-319: Cleartext Transmission of Sensitive Information']
          }
        })
      );
    }

    // 3. Protección contra Clickjacking (X-Frame-Options / CSP frame-ancestors)
    const hasXFrame = !!lowerHeaders['x-frame-options'];
    const csp = lowerHeaders['content-security-policy'] || '';
    const hasFrameAncestors = csp.includes('frame-ancestors');

    if (!hasXFrame && !hasFrameAncestors) {
      findings.push(
        this.securityHeaderFinding({
          id: `HDR-CLICK-${Date.now()}`,
          ruleId: 'SEC-HDR-CLICKJACKING',
          title: 'Vulnerabilidad a Clickjacking (Sin Protección de Encuadre)',
          severity: 'MEDIUM',
          description:
            'La aplicación carece de las cabeceras X-Frame-Options o CSP frame-ancestors. Un atacante puede incrustar la aplicación en un iframe invisible para engañar a los usuarios.',
          evidence: {
            responseStatus: status,
            responseHeaders: headers,
            snippet:
              'X-Frame-Options: [NO PRESENT] | CSP frame-ancestors: [NO PRESENT]'
          },
          remediation: {
            explanation: 'Prohíba la incrustación en iframes de dominios no autorizados.',
            codeBefore: '// Cabecera omitida',
            codeAfter:
              "X-Frame-Options: DENY\n// o en CSP:\nContent-Security-Policy: frame-ancestors 'none';"
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-1021: Improper Restriction of Rendered UI Layers or Frames']
          }
        })
      );
    }

    // 4. X-Content-Type-Options
    if (lowerHeaders['x-content-type-options'] !== 'nosniff') {
      findings.push(
        this.securityHeaderFinding({
          id: `HDR-NOSNIFF-${Date.now()}`,
          ruleId: 'SEC-HDR-NOSNIFF-MISSING',
          title: 'Ausencia o Configuración Insegura de X-Content-Type-Options',
          severity: 'LOW',
          description:
            'La cabecera X-Content-Type-Options no está configurada como "nosniff". El navegador podría interpretar archivos de texto/múltiples como scripts ejecutables.',
          evidence: {
            responseStatus: status,
            responseHeaders: headers,
            snippet: `X-Content-Type-Options: ${lowerHeaders['x-content-type-options'] || '[NO PRESENT]'}`
          },
          remediation: {
            explanation:
              'Fuerce al navegador a respetar estrictamente los tipos MIME declarados.',
            codeBefore: `X-Content-Type-Options: ${lowerHeaders['x-content-type-options'] || 'ninguna'}`,
            codeAfter: 'X-Content-Type-Options: nosniff'
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-434: Unrestricted Upload of File with Dangerous Type']
          }
        })
      );
    }

    // 5. Exposición de Servidor / Banner Grabbing (Server / X-Powered-By)
    const serverHeader = lowerHeaders['server'];
    const poweredByHeader = lowerHeaders['x-powered-by'];

    if (serverHeader || poweredByHeader) {
      const leakedInfo = [
        serverHeader ? `Server: ${serverHeader}` : null,
        poweredByHeader ? `X-Powered-By: ${poweredByHeader}` : null
      ]
        .filter(Boolean)
        .join(' | ');

      findings.push(
        this.securityHeaderFinding({
          id: `HDR-LEAK-${Date.now()}`,
          ruleId: 'SEC-HDR-LEAK-INFO',
          title: 'Divulgación de Información de Infraestructura en Cabeceras HTTP',
          severity: 'LOW',
          description:
            'El servidor expone información sobre el software, versión o framework utilizado. Esto facilita la fase de reconocimiento a un atacante.',
          evidence: {
            responseStatus: status,
            responseHeaders: headers,
            snippet: leakedInfo
          },
          remediation: {
            explanation:
              'Configure el servidor web o proxy inverso para remoción o proxy masking de cabeceras informativas.',
            codeBefore: leakedInfo,
            codeAfter:
              '// Remover cabeceras Server y X-Powered-By en la configuración del servidor'
          },
          standards: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-200: Exposure of Sensitive Information to an Unauthorized Actor']
          }
        })
      );
    }

    return findings;
  }

  private securityHeaderFinding(
    finding: Omit<AuditFinding, 'category' | 'ruleType'>
  ): AuditFinding {
    return {
      ...finding,
      category: 'SECURITY',
      ruleType: 'SECURITY_HEADER'
    };
  }
}
