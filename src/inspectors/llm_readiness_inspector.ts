import { Page } from 'playwright';

import { AuditFinding } from '../types/audit.js';

/**
 * Readiness para agentes LLM / GEO: presencia y estructura de llm.txt
 * en `/llm.txt` y `/.well-known/llm.txt`.
 */
export class LlmReadinessInspector {
  constructor(private readonly page: Page) {}

  public async inspect(pageUrl: string): Promise<AuditFinding[]> {
    let origin: string;
    try {
      origin = new URL(pageUrl).origin;
    } catch {
      return [];
    }

    const candidates = [`${origin}/llm.txt`, `${origin}/.well-known/llm.txt`];
    const findings: AuditFinding[] = [];
    const uid = () => Math.random().toString(36).slice(2, 7);

    const results: Array<{
      url: string;
      status: number;
      body: string;
      ok: boolean;
    }> = [];

    for (const url of candidates) {
      try {
        const response = await this.page.request.get(url, { timeout: 8000 });
        const status = response.status();
        const body = status < 400 ? (await response.text()).slice(0, 4096) : '';
        results.push({ url, status, body, ok: response.ok() });
      } catch {
        results.push({ url, status: 0, body: '', ok: false });
      }
    }

    const available = results.filter((r) => r.ok && r.body.trim().length > 0);
    if (available.length === 0) {
      const statusLine = results
        .map((r) => `${r.url} → ${r.status || 'ERR'}`)
        .join('\n');
      findings.push({
        id: `LLM-MISSING-${Date.now()}-${uid()}`,
        ruleId: 'LLM-TXT-MISSING',
        title: 'llm.txt ausente (AI / GEO readiness)',
        severity: 'MEDIUM',
        description:
          'No se encontró un llm.txt usable en /llm.txt ni en /.well-known/llm.txt. ' +
          'Los agentes generativos carecen de una guía explícita de uso del sitio.',
        category: 'SEO',
        ruleType: 'SEO_LLM_READINESS',
        evidence: {
          url: pageUrl,
          snippet: statusLine.slice(0, 2048)
        },
        remediation: {
          explanation:
            'Publique un llm.txt en la raíz o en /.well-known/ con contactos, políticas y rutas preferidas para crawlers LLM.',
          codeBefore: '# 404 en /llm.txt y /.well-known/llm.txt',
          codeAfter:
            '# /llm.txt\n# Contact: security@example.com\n# Policy: https://example.com/ai-policy\n# Prefer: /docs /api'
        },
        standards: { owasp: [], cwe: [] }
      });
      return findings;
    }

    for (const hit of available) {
      const validation = this.validateLlmTxt(hit.body);
      if (validation.empty) {
        findings.push({
          id: `LLM-EMPTY-${Date.now()}-${uid()}`,
          ruleId: 'LLM-TXT-EMPTY',
          title: 'llm.txt vacío o sin contenido útil',
          severity: 'LOW',
          description: `${hit.url} responde OK pero el cuerpo está vacío o solo tiene comentarios.`,
          category: 'SEO',
          ruleType: 'SEO_LLM_READINESS',
          evidence: {
            url: pageUrl,
            snippet: `${hit.url}\n${hit.body.slice(0, 512) || '[EMPTY]'}`.slice(0, 2048)
          },
          remediation: {
            explanation:
              'Incluya al menos contact, policy URL y secciones Prefer/Allow para orientar a agentes LLM.',
            codeBefore: '# vacío',
            codeAfter: '# Contact: ai@example.com\n# Policy: https://example.com/terms\nAllow: /'
          },
          standards: { owasp: [], cwe: [] }
        });
        continue;
      }

      if (!validation.structured) {
        findings.push({
          id: `LLM-STRUCT-${Date.now()}-${uid()}`,
          ruleId: 'LLM-TXT-UNSTRUCTURED',
          title: 'llm.txt sin estructura reconocible',
          severity: 'INFO',
          description:
            `${hit.url} existe pero no declara directivas típicas (Contact, Policy, Allow/Prefer, User-Agent).`,
          category: 'SEO',
          ruleType: 'SEO_LLM_READINESS',
          evidence: {
            url: pageUrl,
            snippet: hit.body.slice(0, 2048)
          },
          remediation: {
            explanation:
              'Use un formato legible tipo robots/llms con claves Contact/Policy/Allow/Prefer.',
            codeBefore: hit.body.slice(0, 80),
            codeAfter:
              '# Contact: ai@example.com\n# Policy: https://example.com/ai\nPrefer: /docs'
          },
          standards: { owasp: [], cwe: [] }
        });
      }
    }

    const hasRoot = available.some((r) => r.url.endsWith('/llm.txt'));
    const hasWellKnown = available.some((r) => r.url.includes('/.well-known/llm.txt'));
    if (hasRoot && !hasWellKnown) {
      findings.push({
        id: `LLM-WK-${Date.now()}-${uid()}`,
        ruleId: 'LLM-WELLKNOWN-MISSING',
        title: 'Falta /.well-known/llm.txt',
        severity: 'INFO',
        description:
          'Existe /llm.txt pero no /.well-known/llm.txt. Algunos agentes descubren preferentemente el well-known path.',
        category: 'SEO',
        ruleType: 'SEO_LLM_READINESS',
        evidence: {
          url: pageUrl,
          snippet: `root=ok; well-known=missing\n${candidates.join('\n')}`
        },
        remediation: {
          explanation: 'Duplique o redirija llm.txt también bajo /.well-known/llm.txt.',
          codeBefore: 'GET /.well-known/llm.txt → 404',
          codeAfter: 'GET /.well-known/llm.txt → 200 (mismo contenido que /llm.txt)'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    return findings;
  }

  private validateLlmTxt(body: string): { empty: boolean; structured: boolean } {
    const lines = body
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const substantive = lines.filter((l) => !l.startsWith('#'));
    const empty = substantive.length === 0 && lines.length < 2;
    const blob = body.toLowerCase();
    const structured =
      /contact\s*:/i.test(body) ||
      /policy\s*:/i.test(body) ||
      /allow\s*:/i.test(body) ||
      /prefer\s*:/i.test(body) ||
      /user-agent\s*:/i.test(body) ||
      /sitemap\s*:/i.test(body) ||
      blob.includes('llms') ||
      blob.includes('llm');
    return { empty, structured: structured || substantive.length >= 3 };
  }
}
