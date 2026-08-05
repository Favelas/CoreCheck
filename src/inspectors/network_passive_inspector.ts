import { Page, Request, Response } from 'playwright';
import { AuditFinding } from '../types/audit.js';

/**
 * Monitoreo pasivo de red: 4xx/5xx API, Mixed Content y cookies inseguras.
 * Debe adjuntarse a la Page ANTES de la navegación.
 */
export class NetworkPassiveInspector {
  private readonly findings: AuditFinding[] = [];
  private readonly seenKeys = new Set<string>();
  private pageUrl = '';
  private attached = false;

  constructor(private readonly page: Page) {}

  /** Registra listeners; invocar antes de page.goto. */
  public attach(pageUrl: string): void {
    this.pageUrl = pageUrl;
    if (this.attached) {
      return;
    }
    this.attached = true;

    this.page.on('response', (response) => {
      void this.onResponse(response);
    });

    this.page.on('requestfailed', (request) => {
      this.onRequestFailed(request);
    });
  }

  /** Consolida hallazgos de red + inspección de cookie jar. */
  public async collect(): Promise<AuditFinding[]> {
    await this.inspectCookies();
    return [...this.findings];
  }

  private pushUnique(finding: AuditFinding): void {
    const key = `${finding.ruleId}::${finding.evidence.url ?? ''}::${finding.evidence.selector ?? finding.evidence.snippet ?? ''}`;
    if (this.seenKeys.has(key)) {
      return;
    }
    this.seenKeys.add(key);
    this.findings.push(finding);
  }

  private isApiLike(url: string, resourceType: string): boolean {
    if (resourceType === 'xhr' || resourceType === 'fetch') {
      return true;
    }
    return /\/api\/|\/graphql|\/v\d+\//i.test(url);
  }

  private async onResponse(response: Response): Promise<void> {
    const request = response.request();
    const url = response.url();
    const status = response.status();
    const resourceType = request.resourceType();

    // Mixed Content: recurso HTTP cargado desde documento HTTPS
    try {
      const pageIsHttps = this.pageUrl.startsWith('https:');
      if (pageIsHttps && url.startsWith('http://')) {
        this.pushUnique({
          id: `NET-MIXED-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          ruleId: 'NET-MIXED-CONTENT',
          title: 'Mixed Content: recurso HTTP en página HTTPS',
          severity: 'HIGH',
          description: `Se solicitó el recurso inseguro '${url}' desde un documento HTTPS.`,
          category: 'NETWORK',
          ruleType: 'NETWORK_MIXED_CONTENT',
          evidence: {
            url: this.pageUrl,
            snippet: url,
            responseStatus: status
          },
          remediation: {
            explanation: 'Sirva todos los subrecursos por HTTPS o use URLs relativas/protocol-relative seguras.',
            codeBefore: `http://...`,
            codeAfter: `https://...`
          },
          standards: {
            owasp: ['A02:2021-Cryptographic Failures'],
            cwe: ['CWE-319']
          }
        });
      }
    } catch {
      // ignore URL parse issues
    }

    // Errores HTTP en endpoints de API
    if (status >= 400 && this.isApiLike(url, resourceType)) {
      const severity = status >= 500 ? 'HIGH' : 'MEDIUM';
      this.pushUnique({
        id: `NET-HTTP-${status}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        ruleId: 'NET-API-HTTP-ERROR',
        title: `Error HTTP ${status} en endpoint de API`,
        severity,
        description: `La petición '${url}' respondió con estado ${status} (${resourceType}).`,
        category: 'NETWORK',
        ruleType: 'NETWORK_HTTP_ERROR',
        evidence: {
          url: this.pageUrl,
          snippet: `${request.method()} ${url}`,
          responseStatus: status,
          responseHeaders: response.headers()
        },
        remediation: {
          explanation:
            'Investigue la causa del error de API (auth, contrato, disponibilidad) y evite exponer stack traces al cliente.',
          codeBefore: `// ${status} en ${url}`,
          codeAfter: '// Manejo resiliente + logging seguro en backend'
        },
        standards: {
          owasp: ['A05:2021-Security Misconfiguration', 'A09:2021-Security Logging and Monitoring Failures'],
          cwe: ['CWE-754']
        }
      });
    }
  }

  private onRequestFailed(request: Request): void {
    const url = request.url();
    const failure = request.failure()?.errorText || 'unknown';
    const resourceType = request.resourceType();

    if (!this.isApiLike(url, resourceType) && resourceType !== 'document') {
      return;
    }

    this.pushUnique({
      id: `NET-FAIL-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      ruleId: 'NET-REQUEST-FAILED',
      title: 'Fallo de red en petición',
      severity: 'MEDIUM',
      description: `La petición '${url}' falló: ${failure}.`,
      category: 'NETWORK',
      ruleType: 'NETWORK_HTTP_ERROR',
      evidence: {
        url: this.pageUrl,
        snippet: `${request.method()} ${url} :: ${failure}`
      },
      remediation: {
        explanation: 'Verifique DNS, CORS, TLS y disponibilidad del backend para la petición fallida.',
        codeAfter: '// Reintentos con backoff + telemetría de errores de red'
      },
      standards: {
        owasp: ['A05:2021-Security Misconfiguration'],
        cwe: ['CWE-400']
      }
    });
  }

  private async inspectCookies(): Promise<void> {
    const cookies = await this.page.context().cookies();
    const pageIsHttps = this.pageUrl.startsWith('https:');

    for (const cookie of cookies) {
      const issues: string[] = [];
      if (pageIsHttps && !cookie.secure) {
        issues.push('Secure');
      }
      if (!cookie.httpOnly) {
        issues.push('HttpOnly');
      }

      if (issues.length === 0) {
        continue;
      }

      this.pushUnique({
        id: `NET-COOKIE-${cookie.name}-${Date.now()}`,
        ruleId: 'NET-COOKIE-INSECURE-FLAGS',
        title: `Cookie sin flags de seguridad: ${cookie.name}`,
        severity: issues.includes('Secure') ? 'HIGH' : 'MEDIUM',
        description: `La cookie '${cookie.name}' no define: ${issues.join(', ')}.`,
        category: 'NETWORK',
        ruleType: 'NETWORK_COOKIE_FLAGS',
        evidence: {
          url: this.pageUrl,
          snippet: `${cookie.name}=…; domain=${cookie.domain}; path=${cookie.path}; secure=${cookie.secure}; httpOnly=${cookie.httpOnly}`
        },
        remediation: {
          explanation: 'Marque cookies de sesión con Secure y HttpOnly; use SameSite=Strict o Lax según el flujo.',
          codeBefore: `Set-Cookie: ${cookie.name}=...`,
          codeAfter: `Set-Cookie: ${cookie.name}=...; Secure; HttpOnly; SameSite=Lax`
        },
        standards: {
          owasp: ['A05:2021-Security Misconfiguration', 'A07:2021-Identification and Authentication Failures'],
          cwe: ['CWE-614', 'CWE-1004']
        }
      });
    }
  }
}
