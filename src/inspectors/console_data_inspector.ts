import { Page } from 'playwright';
import { AuditFinding } from '../types/audit.js';

export class ConsoleDataInspector {
  private page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  /**
   * Inspecciona localStorage y sessionStorage buscando exposición de tokens, claves API o PII.
   */
  public async inspectStorage(): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];

    try {
      // Evaluamos como un script de texto puro para evitar que esbuild inyecte el helper '__name'
      const storageDump = await this.page.evaluate(`(() => {
        const getItems = (storage) => {
          const items = [];
          for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i);
            if (key) {
              items.push({ key: key, value: storage.getItem(key) || '' });
            }
          }
          return items;
        };

        return {
          local: getItems(window.localStorage),
          session: getItems(window.sessionStorage)
        };
      })()`) as { local: { key: string; value: string }[]; session: { key: string; value: string }[] };

      // Patrones de búsqueda de información sensible (Tokens, Keys, PII)
      const jwtPattern = /^eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;
      const sensitiveKeysPattern = /(token|auth|bearer|jwt|api_?key|secret|password|cred|session)/i;

      const allItems = [
        ...storageDump.local.map(item => ({ ...item, source: 'localStorage' })),
        ...storageDump.session.map(item => ({ ...item, source: 'sessionStorage' }))
      ];

      for (const item of allItems) {
        const isJwt = jwtPattern.test(item.value.trim());
        const isSensitiveKey = sensitiveKeysPattern.test(item.key);

        if (isJwt || isSensitiveKey) {
          const isHighSeverity = isJwt || /jwt|auth|token/i.test(item.key);

          findings.push({
            id: `STOR-LEAK-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            ruleId: 'SEC-STOR-SENSITIVE-DATA-EXPOSED',
            title: `Exposición de Datos Sensibles en ${item.source} (${item.key})`,
            severity: isHighSeverity ? 'HIGH' : 'MEDIUM',
            description: `Se detectó el almacenamiento de información sensible o tokens de autenticación en '${item.source}' bajo la clave '${item.key}'. Al no estar protegidos por banderas de navegador (como HttpOnly), cualquier script inyectado en la página puede exfiltrar estos datos.`,
            evidence: {
              snippet: `${item.source}.setItem('${item.key}', '${item.value.substring(0, 20)}...')`
            },
            remediation: {
              explanation: 'Migre el almacenamiento de tokens de sesión a Cookies HTTP firmadas con las banderas HttpOnly, Secure y SameSite=Strict.',
              codeBefore: `${item.source}.setItem('${item.key}', token);`,
              codeAfter: '// Responder desde el servidor con la cabecera:\nSet-Cookie: session_token=...; HttpOnly; Secure; SameSite=Strict'
            },
            standards: {
              owasp: ['A01:2021-Broken Access Control', 'A04:2021-Insecure Design'],
              cwe: ['CWE-922: Insecure Storage of Sensitive Information', 'CWE-539']
            }
          });
        }
      }
    } catch (error) {
      console.error(`[ERROR-INSPECTOR] Error al inspeccionar Web Storage: ${(error as Error).message}`);
    }

    return findings;
  }
}