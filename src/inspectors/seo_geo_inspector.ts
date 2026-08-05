import { Page } from 'playwright';

import { AuditFinding } from '../types/audit.js';

interface SeoDomSnapshot {
  title: string;
  metaDescription: string;
  canonical: string;
  robotsMeta: string;
  h1Count: number;
  h2Count: number;
  h1Texts: string[];
  jsonLdCount: number;
  jsonLdTypes: string[];
  ogTitle: string;
  ogImage: string;
  ogDescription: string;
  mainLandmark: boolean;
  articleOrMainTextLength: number;
  hasLang: boolean;
  headingOutlineBroken: boolean;
}

/**
 * SEO técnico + GEO (Generative Engine Optimization) para lectura por LLMs.
 */
export class SeoGeoInspector {
  constructor(private readonly page: Page) {}

  public async inspect(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const snap = await this.collectDom(pageUrl);
    const uid = () => Math.random().toString(36).slice(2, 7);

    if (!snap.title || snap.title.trim().length < 3) {
      findings.push(
        this.finding({
          id: `SEO-TITLE-${Date.now()}-${uid()}`,
          ruleId: 'SEO-TITLE-MISSING',
          title: 'Título de página ausente o vacío',
          severity: 'HIGH',
          description: 'La página no define un <title> usable para SERPs / GEO.',
          ruleType: 'SEO_META_TAG',
          pageUrl,
          selector: 'title',
          snippet: '<title></title>',
          remediation:
            'Defina un título único y descriptivo (aprox. 50–60 caracteres) por URL.',
          codeBefore: '<title></title>',
          codeAfter: '<title>Producto X — beneficios clave | Marca</title>'
        })
      );
    } else if (snap.title.trim().length > 70) {
      findings.push(
        this.finding({
          id: `SEO-TITLE-LEN-${Date.now()}-${uid()}`,
          ruleId: 'SEO-TITLE-TOO-LONG',
          title: 'Título demasiado largo',
          severity: 'LOW',
          description: `El <title> tiene ${snap.title.trim().length} caracteres (recomendado ≤ 60–70).`,
          ruleType: 'SEO_META_TAG',
          pageUrl,
          selector: 'title',
          snippet: snap.title.slice(0, 2048),
          remediation: 'Acote el título para evitar truncado en SERPs.',
          codeBefore: `<title>${snap.title.slice(0, 80)}…</title>`,
          codeAfter: '<title>Título conciso y diferenciador</title>'
        })
      );
    }

    if (!snap.metaDescription || snap.metaDescription.trim().length < 20) {
      findings.push(
        this.finding({
          id: `SEO-DESC-${Date.now()}-${uid()}`,
          ruleId: 'SEO-META-DESCRIPTION-MISSING',
          title: 'Meta description ausente o insuficiente',
          severity: 'MEDIUM',
          description: 'Falta <meta name="description"> con texto útil (≥ 20 chars).',
          ruleType: 'SEO_META_TAG',
          pageUrl,
          selector: 'meta[name="description"]',
          snippet: snap.metaDescription || '[MISSING]',
          remediation: 'Añada una meta description única (~120–160 caracteres).',
          codeBefore: '<!-- sin meta description -->',
          codeAfter:
            '<meta name="description" content="Resumen claro del valor de la página.">'
        })
      );
    }

    if (snap.h1Count === 0) {
      findings.push(
        this.finding({
          id: `SEO-H1-${Date.now()}-${uid()}`,
          ruleId: 'SEO-H1-MISSING',
          title: 'Ausencia de H1',
          severity: 'HIGH',
          description: 'No se encontró ningún <h1>; perjudica SEO y comprensión por LLMs.',
          ruleType: 'SEO_STRUCTURE',
          pageUrl,
          selector: 'h1',
          snippet: '[NO H1]',
          remediation: 'Incluya un único H1 que resuma el tema principal de la página.',
          codeBefore: '<h2>Sección</h2>',
          codeAfter: '<h1>Tema principal de la página</h1>'
        })
      );
    } else if (snap.h1Count > 1) {
      findings.push(
        this.finding({
          id: `SEO-H1-MULTI-${Date.now()}-${uid()}`,
          ruleId: 'SEO-H1-MULTIPLE',
          title: 'Múltiples H1 en la página',
          severity: 'MEDIUM',
          description: `Se detectaron ${snap.h1Count} elementos H1: ${snap.h1Texts.slice(0, 3).join(' | ')}`,
          ruleType: 'SEO_STRUCTURE',
          pageUrl,
          selector: 'h1',
          snippet: snap.h1Texts.join(' | ').slice(0, 2048),
          remediation: 'Use un solo H1; el resto de secciones con H2+.',
          codeBefore: '<h1>A</h1><h1>B</h1>',
          codeAfter: '<h1>A</h1><h2>B</h2>'
        })
      );
    }

    if (snap.h2Count === 0 && snap.articleOrMainTextLength > 400) {
      findings.push(
        this.finding({
          id: `SEO-H2-${Date.now()}-${uid()}`,
          ruleId: 'SEO-H2-MISSING',
          title: 'Contenido largo sin H2',
          severity: 'LOW',
          description:
            'Página con cuerpo sustancial sin subtítulos H2; dificulta escaneo humano y GEO.',
          ruleType: 'SEO_STRUCTURE',
          pageUrl,
          selector: 'h2',
          snippet: `textLength≈${snap.articleOrMainTextLength}`,
          remediation: 'Estructure el contenido con H2/H3 semánticos.',
          codeBefore: '<p>…bloque largo…</p>',
          codeAfter: '<h2>Subtema</h2><p>…</p>'
        })
      );
    }

    if (!snap.canonical) {
      findings.push(
        this.finding({
          id: `SEO-CANON-${Date.now()}-${uid()}`,
          ruleId: 'SEO-CANONICAL-MISSING',
          title: 'Canonical ausente',
          severity: 'MEDIUM',
          description: 'No hay <link rel="canonical">; riesgo de contenido duplicado.',
          ruleType: 'SEO_META_TAG',
          pageUrl,
          selector: 'link[rel="canonical"]',
          snippet: '[MISSING]',
          remediation: 'Declare la URL canónica absoluta de la página.',
          codeBefore: '<!-- sin canonical -->',
          codeAfter: `<link rel="canonical" href="${pageUrl}">`
        })
      );
    }

    const robotsDirectives = snap.robotsMeta
      .toLowerCase()
      .split(/[,;\s]+/)
      .map((d) => d.trim())
      .filter(Boolean);

    if (robotsDirectives.includes('noindex')) {
      findings.push(
        this.finding({
          id: `SEO-ROBOTS-NI-${Date.now()}-${uid()}`,
          ruleId: 'SEO-ROBOTS-NOINDEX',
          title: 'Meta robots con noindex',
          severity: 'HIGH',
          description: `La etiqueta <meta name="robots"> bloquea indexación: "${snap.robotsMeta}".`,
          ruleType: 'SEO_META_TAG',
          pageUrl,
          selector: 'meta[name="robots"]',
          snippet: snap.robotsMeta.slice(0, 2048),
          remediation:
            'Elimine noindex en páginas que deban aparecer en SERPs / ser citables por motores generativos.',
          codeBefore: `<meta name="robots" content="${snap.robotsMeta}">`,
          codeAfter: '<meta name="robots" content="index, follow">'
        })
      );
    }

    if (robotsDirectives.includes('nofollow')) {
      findings.push(
        this.finding({
          id: `SEO-ROBOTS-NF-${Date.now()}-${uid()}`,
          ruleId: 'SEO-ROBOTS-NOFOLLOW',
          title: 'Meta robots con nofollow',
          severity: 'MEDIUM',
          description: `La etiqueta <meta name="robots"> bloquea el seguimiento de enlaces: "${snap.robotsMeta}".`,
          ruleType: 'SEO_META_TAG',
          pageUrl,
          selector: 'meta[name="robots"]',
          snippet: snap.robotsMeta.slice(0, 2048),
          remediation:
            'Reserve nofollow para páginas utilitarias; no lo aplique de forma global en contenido público.',
          codeBefore: `<meta name="robots" content="${snap.robotsMeta}">`,
          codeAfter: '<meta name="robots" content="index, follow">'
        })
      );
    }

    const robotsFinding = await this.inspectRobotsTxt(pageUrl, uid);
    if (robotsFinding) {
      findings.push(robotsFinding);
    }

    if (snap.jsonLdCount === 0) {
      findings.push(
        this.finding({
          id: `SEO-JSONLD-${Date.now()}-${uid()}`,
          ruleId: 'SEO-JSONLD-MISSING',
          title: 'Sin datos estructurados JSON-LD',
          severity: 'MEDIUM',
          description: 'No se encontró schema.org vía application/ld+json.',
          ruleType: 'SEO_GEO',
          pageUrl,
          selector: 'script[type="application/ld+json"]',
          snippet: '[MISSING]',
          remediation: 'Añada JSON-LD (Organization, WebPage, Article, Product, FAQPage, etc.).',
          codeBefore: '<!-- sin JSON-LD -->',
          codeAfter:
            '<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"…"}</script>'
        })
      );
    }

    if (!snap.ogTitle || !snap.ogImage) {
      findings.push(
        this.finding({
          id: `SEO-OG-${Date.now()}-${uid()}`,
          ruleId: 'SEO-OPEN-GRAPH-INCOMPLETE',
          title: 'Open Graph incompleto',
          severity: 'MEDIUM',
          description: `Faltan etiquetas OG críticas (og:title=${snap.ogTitle ? 'ok' : 'MISSING'}, og:image=${snap.ogImage ? 'ok' : 'MISSING'}).`,
          ruleType: 'SEO_META_TAG',
          pageUrl,
          selector: 'meta[property^="og:"]',
          snippet: `og:title=${snap.ogTitle || '[MISSING]'}; og:image=${snap.ogImage || '[MISSING]'}`.slice(
            0,
            2048
          ),
          remediation: 'Complete og:title, og:description y og:image para shares y crawlers.',
          codeBefore: '<!-- OG parcial -->',
          codeAfter:
            '<meta property="og:title" content="…">\n<meta property="og:image" content="https://…/share.jpg">'
        })
      );
    }

    // GEO: amigabilidad para LLMs / motores generativos
    if (!snap.hasLang) {
      findings.push(
        this.finding({
          id: `SEO-GEO-LANG-${Date.now()}-${uid()}`,
          ruleId: 'SEO-GEO-LANG-MISSING',
          title: 'Atributo lang ausente en <html>',
          severity: 'MEDIUM',
          description: 'Sin lang el contenido es ambiguo para indexación multilingüe y LLMs.',
          ruleType: 'SEO_GEO',
          pageUrl,
          selector: 'html',
          snippet: '<html>',
          remediation: 'Declare el idioma principal, p.ej. lang="es" o lang="en".',
          codeBefore: '<html>',
          codeAfter: '<html lang="es">'
        })
      );
    }

    if (!snap.mainLandmark) {
      findings.push(
        this.finding({
          id: `SEO-GEO-MAIN-${Date.now()}-${uid()}`,
          ruleId: 'SEO-GEO-MAIN-LANDMARK-MISSING',
          title: 'Sin landmark <main> / role=main',
          severity: 'LOW',
          description:
            'Falta región principal semántica; dificulta extracción de contenido canónico por agentes IA.',
          ruleType: 'SEO_GEO',
          pageUrl,
          selector: 'main',
          snippet: '[NO MAIN]',
          remediation: 'Envuelva el contenido principal en <main>.',
          codeBefore: '<div id="content">…</div>',
          codeAfter: '<main>…</main>'
        })
      );
    }

    if (snap.headingOutlineBroken) {
      findings.push(
        this.finding({
          id: `SEO-GEO-OUTLINE-${Date.now()}-${uid()}`,
          ruleId: 'SEO-GEO-HEADING-OUTLINE',
          title: 'Jerarquía de headings irregular (GEO)',
          severity: 'LOW',
          description:
            'Se detectaron saltos de nivel en headings (p.ej. H1→H3); perjudica el outline semántico para LLMs.',
          ruleType: 'SEO_GEO',
          pageUrl,
          selector: 'h1,h2,h3,h4',
          snippet: 'heading level skip detected',
          remediation: 'Mantenga una secuencia de headings sin saltos (H1→H2→H3).',
          codeBefore: '<h1>…</h1><h3>…</h3>',
          codeAfter: '<h1>…</h1><h2>…</h2>'
        })
      );
    }

    if (snap.articleOrMainTextLength < 80 && snap.h1Count > 0) {
      findings.push(
        this.finding({
          id: `SEO-GEO-THIN-${Date.now()}-${uid()}`,
          ruleId: 'SEO-GEO-THIN-CONTENT',
          title: 'Contenido textual insuficiente (GEO)',
          severity: 'INFO',
          description:
            'Poco texto indexable en main/body; los motores generativos carecen de contexto citables.',
          ruleType: 'SEO_GEO',
          pageUrl,
          selector: 'main, body',
          snippet: `textLength≈${snap.articleOrMainTextLength}`,
          remediation:
            'Añada prosa descriptiva, FAQs o secciones con hechos verificables sobre el tema.',
          codeBefore: '<main><img></main>',
          codeAfter: '<main><h1>…</h1><p>Contexto factual…</p></main>'
        })
      );
    }

    return findings;
  }

  private async collectDom(_pageUrl: string): Promise<SeoDomSnapshot> {
    return this.page.evaluate(() => {
      const meta = (name: string) =>
        document.querySelector(`meta[name="${name}"]`)?.getAttribute('content')?.trim() || '';
      const og = (prop: string) =>
        document.querySelector(`meta[property="${prop}"]`)?.getAttribute('content')?.trim() || '';

      const h1s = Array.from(document.querySelectorAll('h1')).map(
        (el) => (el.textContent || '').trim().slice(0, 80)
      );
      const h2Count = document.querySelectorAll('h2').length;

      const jsonLdNodes = Array.from(
        document.querySelectorAll('script[type="application/ld+json"]')
      );
      const jsonLdTypes: string[] = [];
      for (const node of jsonLdNodes) {
        try {
          const data = JSON.parse(node.textContent || '{}') as { '@type'?: string | string[] };
          const t = data['@type'];
          if (Array.isArray(t)) {
            jsonLdTypes.push(...t.map(String));
          } else if (t) {
            jsonLdTypes.push(String(t));
          }
        } catch {
          // ignore invalid JSON-LD
        }
      }

      const mainEl =
        document.querySelector('main') ||
        document.querySelector('[role="main"]') ||
        document.querySelector('article');
      const textRoot = mainEl || document.body;
      const articleOrMainTextLength = (textRoot?.innerText || '').replace(/\s+/g, ' ').trim()
        .length;

      const headingLevels = Array.from(
        document.querySelectorAll('h1,h2,h3,h4,h5,h6')
      ).map((el) => Number(el.tagName.substring(1)));
      let headingOutlineBroken = false;
      for (let i = 1; i < headingLevels.length; i++) {
        if (headingLevels[i] - headingLevels[i - 1] > 1) {
          headingOutlineBroken = true;
          break;
        }
      }

      return {
        title: document.title || '',
        metaDescription: meta('description'),
        canonical:
          document.querySelector('link[rel="canonical"]')?.getAttribute('href')?.trim() || '',
        robotsMeta: meta('robots'),
        h1Count: h1s.length,
        h2Count,
        h1Texts: h1s,
        jsonLdCount: jsonLdNodes.length,
        jsonLdTypes,
        ogTitle: og('og:title'),
        ogImage: og('og:image'),
        ogDescription: og('og:description'),
        mainLandmark: !!(
          document.querySelector('main') || document.querySelector('[role="main"]')
        ),
        articleOrMainTextLength,
        hasLang: !!(document.documentElement.getAttribute('lang') || '').trim(),
        headingOutlineBroken
      };
    });
  }

  private async inspectRobotsTxt(
    pageUrl: string,
    uid: () => string
  ): Promise<AuditFinding | null> {
    let origin: string;
    try {
      origin = new URL(pageUrl).origin;
    } catch {
      return null;
    }

    const robotsUrl = `${origin}/robots.txt`;
    try {
      const response = await this.page.request.get(robotsUrl, { timeout: 8000 });
      if (response.status() === 404) {
        return this.finding({
          id: `SEO-ROBOTS-${Date.now()}-${uid()}`,
          ruleId: 'SEO-ROBOTS-TXT-MISSING',
          title: 'robots.txt no encontrado (404)',
          severity: 'LOW',
          description: `${robotsUrl} respondió 404.`,
          ruleType: 'SEO_META_TAG',
          pageUrl,
          snippet: `GET ${robotsUrl} → 404`,
          remediation: 'Publique un robots.txt con reglas claras y referencia a sitemap.',
          codeBefore: '# 404',
          codeAfter: 'User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml'
        });
      }
      if (!response.ok()) {
        return null;
      }
      const body = (await response.text()).slice(0, 2048);
      if (!/user-agent/i.test(body)) {
        return this.finding({
          id: `SEO-ROBOTS-EMPTY-${Date.now()}-${uid()}`,
          ruleId: 'SEO-ROBOTS-TXT-INVALID',
          title: 'robots.txt sin directivas User-agent',
          severity: 'LOW',
          description: 'El archivo robots.txt no contiene directivas User-agent reconocibles.',
          ruleType: 'SEO_META_TAG',
          pageUrl,
          snippet: body || '[EMPTY]',
          remediation: 'Incluya al menos un bloque User-agent con Allow/Disallow.',
          codeBefore: body.slice(0, 80) || '# vacío',
          codeAfter: 'User-agent: *\nAllow: /'
        });
      }
    } catch {
      return null;
    }
    return null;
  }

  private finding(args: {
    id: string;
    ruleId: string;
    title: string;
    severity: AuditFinding['severity'];
    description: string;
    ruleType: AuditFinding['ruleType'];
    pageUrl: string;
    selector?: string;
    snippet: string;
    remediation: string;
    codeBefore: string;
    codeAfter: string;
  }): AuditFinding {
    return {
      id: args.id,
      ruleId: args.ruleId,
      title: args.title,
      severity: args.severity,
      description: args.description,
      category: 'SEO',
      ruleType: args.ruleType,
      evidence: {
        url: args.pageUrl,
        selector: args.selector,
        snippet: args.snippet.slice(0, 2048)
      },
      remediation: {
        explanation: args.remediation,
        codeBefore: args.codeBefore,
        codeAfter: args.codeAfter
      },
      standards: { owasp: [], cwe: [] }
    };
  }
}
