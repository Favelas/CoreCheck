import { Cookie, Page } from 'playwright';

import { AuditFinding } from '../types/audit.js';

/**
 * Privacidad: cookies de terceros pre-consentimiento y enlaces a políticas.
 */
export class PrivacyInspector {
  private readonly earlyThirdParty: Cookie[] = [];
  private captureStarted = false;
  private pageHost = '';

  constructor(private readonly page: Page) {}

  /**
   * Captura cookies de terceros lo antes posible tras el primer response,
   * antes de cualquier interacción de consentimiento.
   */
  public attach(pageUrl: string): void {
    try {
      this.pageHost = new URL(pageUrl).hostname.replace(/^www\./, '');
    } catch {
      this.pageHost = '';
    }

    if (this.captureStarted) {
      return;
    }
    this.captureStarted = true;

    this.page.on('response', () => {
      void this.snapshotThirdPartyCookies();
    });
  }

  public async inspect(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const uid = () => Math.random().toString(36).slice(2, 7);

    await this.snapshotThirdPartyCookies();
    const consentPresent = await this.detectConsentUi();

    const uniqueThirdParty = this.dedupeCookies(this.earlyThirdParty);
    if (uniqueThirdParty.length > 0 && !consentPresent) {
      const names = uniqueThirdParty
        .slice(0, 12)
        .map((c) => `${c.name}@${c.domain}`)
        .join(', ');

      findings.push({
        id: `PRIV-COOKIE-${Date.now()}-${uid()}`,
        ruleId: 'PRIV-THIRD-PARTY-COOKIE-PRECONSENT',
        title: 'Cookies de terceros sin evidencia de consentimiento previo',
        severity: 'HIGH',
        description: `Se fijaron ${uniqueThirdParty.length} cookie(s) de terceros antes de interacción de consentimiento.`,
        category: 'PRIVACY',
        ruleType: 'PRIVACY_CONSENT',
        evidence: {
          url: pageUrl,
          snippet: names.slice(0, 2048)
        },
        remediation: {
          explanation:
            'Retrase scripts de tracking hasta obtener consentimiento (CMP) y use cookies first-party con base legal clara.',
          codeBefore: '<script src="https://tracker.example/sdk.js"></script>',
          codeAfter:
            '// cargar tracker solo tras accept()\nif (consent.analytics) loadTracker();'
        },
        standards: {
          owasp: ['A02:2021-Cryptographic Failures'],
          cwe: ['CWE-359']
        }
      });
    } else if (uniqueThirdParty.length > 0 && consentPresent) {
      // Banner presente pero cookies ya estaban: posible non-blocking CMP.
      findings.push({
        id: `PRIV-COOKIE-RACE-${Date.now()}-${uid()}`,
        ruleId: 'PRIV-COOKIE-BEFORE-CONSENT-UI',
        title: 'Cookies de terceros coexistiendo con banner de consentimiento',
        severity: 'MEDIUM',
        description:
          'Hay UI de consentimiento, pero ya existen cookies de terceros en el jar (posible carga prematura de tags).',
        category: 'PRIVACY',
        ruleType: 'PRIVACY_COOKIE',
        evidence: {
          url: pageUrl,
          snippet: uniqueThirdParty
            .slice(0, 8)
            .map((c) => `${c.name}@${c.domain}`)
            .join(', ')
            .slice(0, 2048)
        },
        remediation: {
          explanation:
            'Bloquee tags de marketing/analytics hasta el evento de aceptación del CMP.',
          codeBefore: '// tags en <head> sin gate',
          codeAfter: '// GTM/tags gated por consent mode'
        },
        standards: {
          owasp: [],
          cwe: ['CWE-359']
        }
      });
    }

    const policyLinks = await this.findPolicyLinks();
    if (!policyLinks.hasPrivacy) {
      findings.push({
        id: `PRIV-POL-${Date.now()}-${uid()}`,
        ruleId: 'PRIV-POLICY-LINK-MISSING',
        title: 'Enlace a Política de Privacidad no encontrado',
        severity: 'MEDIUM',
        description:
          'No se detectó un enlace visible a Política de Privacidad / Privacy Policy en el DOM.',
        category: 'PRIVACY',
        ruleType: 'PRIVACY_POLICY_LINK',
        evidence: {
          url: pageUrl,
          selector: 'a[href]',
          snippet: '[NO PRIVACY POLICY LINK]'
        },
        remediation: {
          explanation: 'Exposición un enlace accesible a la política de privacidad en footer/nav.',
          codeBefore: '<footer>…</footer>',
          codeAfter: '<footer><a href="/privacy">Política de Privacidad</a></footer>'
        },
        standards: {
          owasp: [],
          cwe: ['CWE-200']
        }
      });
    }

    if (!policyLinks.hasCookies) {
      findings.push({
        id: `PRIV-COOKIES-POL-${Date.now()}-${uid()}`,
        ruleId: 'PRIV-COOKIE-POLICY-LINK-MISSING',
        title: 'Enlace a Política de Cookies no encontrado',
        severity: 'LOW',
        description:
          'No se detectó un enlace a Política de Cookies / Cookie Policy en el DOM.',
        category: 'PRIVACY',
        ruleType: 'PRIVACY_POLICY_LINK',
        evidence: {
          url: pageUrl,
          selector: 'a[href]',
          snippet: '[NO COOKIE POLICY LINK]'
        },
        remediation: {
          explanation: 'Añada un enlace a la política de cookies junto al CMP/footer.',
          codeBefore: '<footer>…</footer>',
          codeAfter: '<footer><a href="/cookies">Política de Cookies</a></footer>'
        },
        standards: {
          owasp: [],
          cwe: []
        }
      });
    }

    findings.push(...(await this.inspectCookieSecurityFlags(pageUrl, uid)));

    return findings;
  }

  private async inspectCookieSecurityFlags(
    pageUrl: string,
    uid: () => string
  ): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    let cookies: Cookie[] = [];
    try {
      cookies = await this.page.context().cookies();
    } catch {
      return findings;
    }

    const pageIsHttps = pageUrl.startsWith('https:');
    const relevant = this.dedupeCookies(cookies).filter((c) => this.isSessionOrTrackingCookie(c));

    for (const cookie of relevant.slice(0, 20)) {
      const missing: string[] = [];
      if (pageIsHttps && !cookie.secure) {
        missing.push('Secure');
      }
      if (this.looksLikeSessionCookie(cookie) && !cookie.httpOnly) {
        missing.push('HttpOnly');
      }
      const sameSite = (cookie.sameSite || '').toString();
      if (!sameSite || sameSite === 'None') {
        if (sameSite === 'None' && !cookie.secure) {
          missing.push('SameSite=None requires Secure');
        } else if (!sameSite) {
          missing.push('SameSite');
        }
      }

      if (missing.length === 0) {
        continue;
      }

      findings.push({
        id: `PRIV-INSECURE-${cookie.name}-${Date.now()}-${uid()}`,
        ruleId: 'PRIV-INSECURE-COOKIE',
        title: `Cookie insegura: ${cookie.name}`,
        severity: missing.includes('Secure') || missing.includes('HttpOnly') ? 'HIGH' : 'MEDIUM',
        description: `La cookie de sesión/rastreo '${cookie.name}' carece de flags: ${missing.join(', ')}.`,
        category: 'PRIVACY',
        ruleType: 'PRIVACY_COOKIE',
        evidence: {
          url: pageUrl,
          snippet:
            `${cookie.name}; domain=${cookie.domain}; path=${cookie.path}; ` +
            `secure=${cookie.secure}; httpOnly=${cookie.httpOnly}; sameSite=${sameSite || '[UNSET]'}`.slice(
              0,
              2048
            )
        },
        remediation: {
          explanation:
            'Configure Secure en HTTPS, HttpOnly en cookies de sesión y SameSite=Lax/Strict (o None+Secure si es cross-site).',
          codeBefore: `Set-Cookie: ${cookie.name}=…`,
          codeAfter: `Set-Cookie: ${cookie.name}=…; Secure; HttpOnly; SameSite=Lax`
        },
        standards: {
          owasp: ['A02:2021-Cryptographic Failures', 'A05:2021-Security Misconfiguration'],
          cwe: ['CWE-614', 'CWE-1004']
        }
      });
    }

    return findings;
  }

  private isSessionOrTrackingCookie(cookie: Cookie): boolean {
    return this.looksLikeSessionCookie(cookie) || this.looksLikeTrackingCookie(cookie);
  }

  private looksLikeSessionCookie(cookie: Cookie): boolean {
    const name = cookie.name.toLowerCase();
    return /^(session|sess|sid|ssid|jsessionid|phpsessid|asp\.net_sessionid|auth|token|jwt|access|refresh)/i.test(
      name
    ) || /session|auth|token|csrf/i.test(name);
  }

  private looksLikeTrackingCookie(cookie: Cookie): boolean {
    const name = cookie.name.toLowerCase();
    return (
      name.startsWith('_ga') ||
      name.startsWith('_gid') ||
      name.startsWith('_gat') ||
      name.startsWith('_fbp') ||
      name.startsWith('_gcl') ||
      name.startsWith('amp_') ||
      name.startsWith('_hj') ||
      name.startsWith('ajs_') ||
      /utm|track|analytics|pixel|marketing/.test(name) ||
      this.isThirdParty(cookie.domain)
    );
  }

  private async snapshotThirdPartyCookies(): Promise<void> {
    if (!this.pageHost) {
      return;
    }
    try {
      const cookies = await this.page.context().cookies();
      for (const cookie of cookies) {
        if (this.isThirdParty(cookie.domain)) {
          this.earlyThirdParty.push(cookie);
        }
      }
    } catch {
      // context may be closing
    }
  }

  private isThirdParty(cookieDomain: string): boolean {
    const domain = cookieDomain.replace(/^\./, '').replace(/^www\./, '').toLowerCase();
    const host = this.pageHost.toLowerCase();
    if (!domain || !host) {
      return false;
    }
    return domain !== host && !host.endsWith(`.${domain}`) && !domain.endsWith(`.${host}`);
  }

  private dedupeCookies(cookies: Cookie[]): Cookie[] {
    const map = new Map<string, Cookie>();
    for (const c of cookies) {
      map.set(`${c.name}::${c.domain}::${c.path}`, c);
    }
    return [...map.values()];
  }

  private async detectConsentUi(): Promise<boolean> {
    return this.page
      .evaluate(`(() => {
        var text = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
        var keywords = [
          'accept cookies',
          'aceptar cookies',
          'cookie consent',
          'we use cookies',
          'utilizamos cookies',
          'manage preferences',
          'privacy preferences',
          'consentimiento'
        ];
        for (var i = 0; i < keywords.length; i++) {
          if (text.indexOf(keywords[i]) !== -1) return true;
        }
        var selectors = [
          '#onetrust-banner-sdk',
          '#cybotCookiebotDialog',
          '.cc-window',
          '[id*="cookie"][class*="banner"]',
          '[class*="cookie-banner"]',
          '[aria-label*="cookie" i]',
          '[id*="consent"]'
        ];
        for (var j = 0; j < selectors.length; j++) {
          try {
            if (document.querySelector(selectors[j])) return true;
          } catch (e) {}
        }
        return false;
      })()`)
      .then((v) => Boolean(v))
      .catch(() => false);
  }

  private async findPolicyLinks(): Promise<{ hasPrivacy: boolean; hasCookies: boolean }> {
    return this.page
      .evaluate(`(() => {
        var anchors = Array.from(document.querySelectorAll('a[href]'));
        var parts = [];
        for (var i = 0; i < anchors.length; i++) {
          var a = anchors[i];
          parts.push(
            ((a.getAttribute('href') || '') + ' ' + (a.textContent || '')).toLowerCase()
          );
        }
        var blob = parts.join('\\n');
        var hasPrivacy = /privacy|privacidad|politica-de-privacidad|política de privacidad|datenschutz/.test(blob);
        var hasCookies = /cookie-policy|cookies-policy|politica-de-cookies|política de cookies|cookie notice|aviso de cookies/.test(blob);
        return { hasPrivacy: hasPrivacy, hasCookies: hasCookies };
      })()`)
      .then((v) => v as { hasPrivacy: boolean; hasCookies: boolean })
      .catch(() => ({ hasPrivacy: false, hasCookies: false }));
  }
}
