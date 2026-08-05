import { Page, Response } from 'playwright';

import { AuditFinding } from '../types/audit.js';

const LCP_BUDGET_MS = 2500;
const CLS_BUDGET = 0.1;
const INP_BUDGET_MS = 200;
const INP_POOR_MS = 500;
const DCL_BUDGET_MS = 3000;
const LOAD_BUDGET_MS = 5000;
const LARGE_ASSET_BYTES = 1024 * 1024;

interface PerfMetrics {
  lcpMs: number | null;
  cls: number | null;
  inpMs: number | null;
  domContentLoadedMs: number | null;
  loadEventMs: number | null;
}

interface ResourceSample {
  url: string;
  resourceType: string;
  encodedBodySize: number;
  transferSize: number;
  contentEncoding: string | null;
}

/**
 * Métricas Web Vitals (LCP/CLS/INP) + optimización de assets.
 */
export class PerformanceInspector {
  private readonly responses: Response[] = [];
  private attached = false;

  constructor(private readonly page: Page) {}

  /** Adjuntar antes de page.goto para capturar respuestas de red y observers. */
  public attach(): void {
    if (this.attached) {
      return;
    }
    this.attached = true;
    this.page.on('response', (response) => {
      this.responses.push(response);
    });

    void this.page.addInitScript(`(() => {
      window.__corecheckLcp = 0;
      window.__corecheckCls = 0;
      window.__corecheckInpMax = 0;
      window.__corecheckInpSamples = [];
      try {
        new PerformanceObserver(function (list) {
          var entries = list.getEntries();
          for (var i = 0; i < entries.length; i++) {
            window.__corecheckLcp = entries[i].startTime;
          }
        }).observe({ type: 'largest-contentful-paint', buffered: true });
      } catch (e) {}
      try {
        new PerformanceObserver(function (list) {
          var entries = list.getEntries();
          for (var i = 0; i < entries.length; i++) {
            var entry = entries[i];
            if (!entry.hadRecentInput) {
              window.__corecheckCls = (window.__corecheckCls || 0) + (entry.value || 0);
            }
          }
        }).observe({ type: 'layout-shift', buffered: true });
      } catch (e) {}
      try {
        new PerformanceObserver(function (list) {
          var entries = list.getEntries();
          for (var i = 0; i < entries.length; i++) {
            var entry = entries[i];
            var dur = entry.duration || 0;
            if (dur > (window.__corecheckInpMax || 0)) {
              window.__corecheckInpMax = dur;
            }
            window.__corecheckInpSamples.push({
              name: entry.name,
              duration: dur,
              startTime: entry.startTime
            });
          }
        }).observe({ type: 'event', buffered: true, durationThreshold: 16 });
      } catch (e) {}
    })()`);
  }

  public async inspect(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];

    await this.page.waitForTimeout(600).catch(() => {});

    // Sintetiza una interacción para alimentar Event Timing / medir latencia.
    await this.synthesizeInteraction().catch(() => {});

    const metrics = await this.collectMetrics();
    findings.push(...this.findingsFromMetrics(pageUrl, metrics));
    findings.push(...(await this.inspectImages(pageUrl)));
    findings.push(...(await this.inspectCompressionAndAssets(pageUrl)));
    findings.push(...(await this.inspectInpHeuristics(pageUrl)));

    return findings;
  }

  /**
   * Dispara un click seguro en un control interactivo same-page para observar INP.
   */
  private async synthesizeInteraction(): Promise<void> {
    const selectorRaw = await this.page
      .evaluate(`(() => {
        var candidates = Array.from(document.querySelectorAll(
          'button:not([disabled]), [role="button"], a[href], input[type="button"], input[type="submit"]'
        ));
        for (var i = 0; i < candidates.length; i++) {
          var el = candidates[i];
          var rect = el.getBoundingClientRect();
          if (rect.width < 8 || rect.height < 8) continue;
          if (rect.bottom < 0 || rect.top > (window.innerHeight || 800)) continue;
          if (el.tagName === 'A') {
            var href = (el.getAttribute('href') || '').trim();
            if (!href || href.startsWith('#') || href.startsWith('javascript:')) {
              // ok
            } else {
              try {
                var u = new URL(href, location.href);
                if (u.origin !== location.origin) continue;
                if (u.pathname !== location.pathname && !href.startsWith('#')) continue;
              } catch (e) { continue; }
            }
          }
          el.setAttribute('data-corecheck-inp', '1');
          return '[data-corecheck-inp="1"]';
        }
        return null;
      })()`)
      .catch(() => null);

    const selector = typeof selectorRaw === 'string' ? selectorRaw : null;
    if (!selector) {
      return;
    }

    const started = Date.now();
    await this.page
      .locator(selector)
      .first()
      .click({ timeout: 1500, noWaitAfter: true })
      .catch(() => {});
    await this.page
      .evaluate(`(() => new Promise(function (resolve) {
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { resolve(true); });
      });
    }))()`)
      .catch(() => {});
    await this.page.waitForTimeout(120).catch(() => {});

    const syntheticMs = Date.now() - started;
    await this.page
      .evaluate(
        `((ms) => {
        if (!window.__corecheckInpMax || ms > window.__corecheckInpMax) {
          window.__corecheckInpMax = ms;
        }
        window.__corecheckInpSamples = window.__corecheckInpSamples || [];
        window.__corecheckInpSamples.push({ name: 'synthetic-click', duration: ms, startTime: 0 });
      })(${JSON.stringify(syntheticMs)})`
      )
      .catch(() => {});
  }

  private async collectMetrics(): Promise<PerfMetrics> {
    return this.page.evaluate(`(() => {
      var w = window;
      var navEntries = performance.getEntriesByType('navigation');
      var nav = navEntries.length > 0 ? navEntries[0] : null;

      var lcpMs = null;
      var lcpEntries = performance.getEntriesByType('largest-contentful-paint');
      if (lcpEntries.length > 0) {
        lcpMs = lcpEntries[lcpEntries.length - 1].startTime;
      } else if (w.__corecheckLcp && w.__corecheckLcp > 0) {
        lcpMs = w.__corecheckLcp;
      } else {
        var paints = performance.getEntriesByType('paint');
        for (var i = 0; i < paints.length; i++) {
          if (paints[i].name === 'first-contentful-paint') {
            lcpMs = paints[i].startTime;
            break;
          }
        }
      }

      var cls = null;
      var layoutShifts = performance.getEntriesByType('layout-shift');
      if (layoutShifts.length > 0) {
        cls = 0;
        for (var j = 0; j < layoutShifts.length; j++) {
          if (!layoutShifts[j].hadRecentInput) {
            cls += layoutShifts[j].value;
          }
        }
      } else if (typeof w.__corecheckCls === 'number') {
        cls = w.__corecheckCls;
      }

      var inpMs = null;
      if (typeof w.__corecheckInpMax === 'number' && w.__corecheckInpMax > 0) {
        inpMs = w.__corecheckInpMax;
      }

      return {
        lcpMs: lcpMs,
        cls: cls,
        inpMs: inpMs,
        domContentLoadedMs: nav ? nav.domContentLoadedEventEnd - nav.startTime : null,
        loadEventMs: nav ? nav.loadEventEnd - nav.startTime : null
      };
    })()`) as Promise<PerfMetrics>;
  }

  private findingsFromMetrics(pageUrl: string, metrics: PerfMetrics): AuditFinding[] {
    const findings: AuditFinding[] = [];
    const uid = () => Math.random().toString(36).slice(2, 7);

    if (metrics.lcpMs !== null && metrics.lcpMs > LCP_BUDGET_MS) {
      findings.push({
        id: `PERF-LCP-${Date.now()}-${uid()}`,
        ruleId: 'PERF-LCP-SLOW',
        title: 'LCP por encima del presupuesto (2.5s)',
        severity: metrics.lcpMs > 4000 ? 'HIGH' : 'MEDIUM',
        description: `Largest Contentful Paint = ${Math.round(metrics.lcpMs)}ms (presupuesto: ${LCP_BUDGET_MS}ms).`,
        category: 'PERFORMANCE',
        ruleType: 'PERF_WEB_VITAL',
        evidence: {
          url: pageUrl,
          snippet: `LCP=${Math.round(metrics.lcpMs)}ms`
        },
        remediation: {
          explanation:
            'Optimice la imagen/elemento LCP (preload, formatos modernos, CDN, SSR del above-the-fold).',
          codeBefore: '<img src="hero.jpg">',
          codeAfter:
            '<link rel="preload" as="image" href="hero.webp">\n<img src="hero.webp" fetchpriority="high">'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    if (metrics.cls !== null && metrics.cls > CLS_BUDGET) {
      findings.push({
        id: `PERF-CLS-${Date.now()}-${uid()}`,
        ruleId: 'PERF-CLS-HIGH',
        title: 'CLS por encima del presupuesto (0.1)',
        severity: metrics.cls > 0.25 ? 'HIGH' : 'MEDIUM',
        description: `Cumulative Layout Shift = ${metrics.cls.toFixed(3)} (presupuesto: ${CLS_BUDGET}).`,
        category: 'PERFORMANCE',
        ruleType: 'PERF_WEB_VITAL',
        evidence: {
          url: pageUrl,
          snippet: `CLS=${metrics.cls.toFixed(3)}`
        },
        remediation: {
          explanation:
            'Reserve espacio (width/height o aspect-ratio) en imágenes/embeds y evite inyecciones late de banners.',
          codeBefore: '<img src="banner.jpg">',
          codeAfter:
            '<img src="banner.jpg" width="1200" height="400" style="aspect-ratio:3/1">'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    if (metrics.inpMs !== null && metrics.inpMs > INP_BUDGET_MS) {
      findings.push({
        id: `PERF-INP-${Date.now()}-${uid()}`,
        ruleId: 'PERF-INP-SLOW',
        title: 'INP por encima del presupuesto (200ms)',
        severity: metrics.inpMs >= INP_POOR_MS ? 'HIGH' : 'MEDIUM',
        description:
          `Interaction to Next Paint (aproximado) = ${Math.round(metrics.inpMs)}ms ` +
          `(bueno ≤ ${INP_BUDGET_MS}ms; pobre ≥ ${INP_POOR_MS}ms). ` +
          'Medido vía Event Timing API y/o click sintético Playwright.',
        category: 'PERFORMANCE',
        ruleType: 'PERF_WEB_VITAL',
        evidence: {
          url: pageUrl,
          snippet: `INP≈${Math.round(metrics.inpMs)}ms`
        },
        remediation: {
          explanation:
            'Rompa long tasks en handlers de input, deferra trabajo no crítico con scheduler.yield/requestIdleCallback y evite re-renders bloqueantes.',
          codeBefore: 'button.onclick = () => { heavySyncWork(); updateUI(); }',
          codeAfter:
            'button.onclick = async () => { await scheduler.yield?.(); updateUI(); queueMicrotask(heavySyncWork); }'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    if (metrics.domContentLoadedMs !== null && metrics.domContentLoadedMs > DCL_BUDGET_MS) {
      findings.push({
        id: `PERF-DCL-${Date.now()}-${uid()}`,
        ruleId: 'PERF-DCL-SLOW',
        title: 'DOMContentLoaded lento',
        severity: 'MEDIUM',
        description: `DOMContentLoaded = ${Math.round(metrics.domContentLoadedMs)}ms (presupuesto: ${DCL_BUDGET_MS}ms).`,
        category: 'PERFORMANCE',
        ruleType: 'PERF_WEB_VITAL',
        evidence: {
          url: pageUrl,
          snippet: `DCL=${Math.round(metrics.domContentLoadedMs)}ms`
        },
        remediation: {
          explanation: 'Reduzca JS bloqueante, defer/async scripts y recorte el HTML inicial.',
          codeBefore: '<script src="bundle.js"></script>',
          codeAfter: '<script src="bundle.js" defer></script>'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    if (metrics.loadEventMs !== null && metrics.loadEventMs > LOAD_BUDGET_MS) {
      findings.push({
        id: `PERF-LOAD-${Date.now()}-${uid()}`,
        ruleId: 'PERF-LOAD-SLOW',
        title: 'window.load lento',
        severity: metrics.loadEventMs > 8000 ? 'HIGH' : 'MEDIUM',
        description: `Load event = ${Math.round(metrics.loadEventMs)}ms (presupuesto: ${LOAD_BUDGET_MS}ms).`,
        category: 'PERFORMANCE',
        ruleType: 'PERF_WEB_VITAL',
        evidence: {
          url: pageUrl,
          snippet: `load=${Math.round(metrics.loadEventMs)}ms`
        },
        remediation: {
          explanation: 'Lazy-load recursos below-the-fold y divida bundles de terceros.',
          codeBefore: '// carga síncrona de todos los assets',
          codeAfter: '// lazy-load + code-splitting por ruta'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    return findings;
  }

  /** Heurísticas de handlers costosos / falta de optimización de input. */
  private async inspectInpHeuristics(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const uid = () => Math.random().toString(36).slice(2, 7);

    const report = (await this.page
      .evaluate(`(() => {
        var scripts = Array.from(document.scripts).map(function (s) {
          return (s.src || '').toLowerCase();
        }).filter(Boolean);
        var nodes = document.querySelectorAll('[onclick], [oninput], [onkeydown], [onscroll]');
        return {
          thirdPartyLikely: scripts.filter(function (s) {
            return /googletagmanager|facebook|hotjar|segment|fullstory|clarity/.test(s);
          }).length,
          inlineHandlers: nodes.length,
          interactiveCount: document.querySelectorAll('button, a[href], input, textarea, select').length
        };
      })()`)
      .catch(() => null)) as {
      thirdPartyLikely: number;
      inlineHandlers: number;
      interactiveCount: number;
    } | null;

    if (!report) return findings;

    if (report.inlineHandlers >= 8) {
      findings.push({
        id: `PERF-INP-HANDLERS-${Date.now()}-${uid()}`,
        ruleId: 'PERF-INP-INLINE-HANDLERS',
        title: 'Muchos handlers inline de input (riesgo INP)',
        severity: 'LOW',
        description:
          `Se detectaron ${report.inlineHandlers} atributos on* inline. ` +
          'Handlers síncronos en el critical path degradan Interaction to Next Paint.',
        category: 'PERFORMANCE',
        ruleType: 'PERF_WEB_VITAL',
        evidence: {
          url: pageUrl,
          snippet: `inlineHandlers=${report.inlineHandlers}; interactive=${report.interactiveCount}`
        },
        remediation: {
          explanation:
            'Migre a addEventListener con lógica asíncrona y evite trabajo pesado en el primer turno del evento.',
          codeBefore: '<button onclick="heavy()">',
          codeAfter: "button.addEventListener('click', () => queueMicrotask(heavy))"
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    if (report.thirdPartyLikely >= 3 && report.interactiveCount > 0) {
      findings.push({
        id: `PERF-INP-3P-${Date.now()}-${uid()}`,
        ruleId: 'PERF-INP-THIRD-PARTY-RISK',
        title: 'Scripts de terceros que pueden degradar INP',
        severity: 'INFO',
        description:
          `${report.thirdPartyLikely} script(s) de analytics/tag managers detectados. ` +
          'Tags síncronos compiten con handlers de interacción.',
        category: 'PERFORMANCE',
        ruleType: 'PERF_WEB_VITAL',
        evidence: {
          url: pageUrl,
          snippet: `thirdPartyLikely=${report.thirdPartyLikely}`
        },
        remediation: {
          explanation:
            'Cargue tags con defer/partytown/worker y retarde hasta después de la primera interacción.',
          codeBefore: '<script src="https://www.googletagmanager.com/gtm.js">',
          codeAfter: '<script src="gtm.js" defer data-priority="low">'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    return findings;
  }

  private async inspectImages(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const uid = () => Math.random().toString(36).slice(2, 7);

    const heavyImages = (await this.page
      .evaluate(`(() => {
        var imgs = Array.from(document.querySelectorAll('img'));
        var heavy = [];
        for (var i = 0; i < imgs.length; i++) {
          var img = imgs[i];
          var pixels = img.naturalWidth * img.naturalHeight;
          if (pixels > 2000000 && !img.srcset) {
            heavy.push({
              src: img.currentSrc || img.src,
              naturalWidth: img.naturalWidth,
              naturalHeight: img.naturalHeight
            });
          }
        }
        return heavy.slice(0, 8);
      })()`)
      .catch(
        () => [] as Array<{ src: string; naturalWidth: number; naturalHeight: number }>
      )) as Array<{ src: string; naturalWidth: number; naturalHeight: number }>;

    for (const img of heavyImages) {
      findings.push({
        id: `PERF-IMG-${Date.now()}-${uid()}`,
        ruleId: 'PERF-IMAGE-OVERSIZED',
        title: 'Imagen sobredimensionada sin srcset',
        severity: 'MEDIUM',
        description: `Imagen ${img.naturalWidth}x${img.naturalHeight} sin responsive srcset: ${img.src.slice(0, 120)}`,
        category: 'PERFORMANCE',
        ruleType: 'PERF_ASSET_OPTIMIZATION',
        evidence: {
          url: pageUrl,
          selector: 'img',
          snippet: img.src.slice(0, 2048)
        },
        remediation: {
          explanation: 'Sirva variantes responsive (srcset/sizes) y formatos AVIF/WebP.',
          codeBefore: `<img src="${img.src.slice(0, 60)}">`,
          codeAfter:
            '<img src="hero-800.webp" srcset="hero-400.webp 400w, hero-800.webp 800w" sizes="100vw">'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    return findings;
  }

  private async inspectCompressionAndAssets(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const uid = () => Math.random().toString(36).slice(2, 7);

    const samples: ResourceSample[] = [];
    for (const response of this.responses.slice(0, 80)) {
      try {
        const req = response.request();
        const type = req.resourceType();
        if (!['script', 'stylesheet', 'document', 'font', 'image'].includes(type)) {
          continue;
        }
        const headers = response.headers();
        const encoding = headers['content-encoding'] ?? null;
        const lengthHeader = headers['content-length'];
        const transferSize = lengthHeader ? parseInt(lengthHeader, 10) : 0;
        samples.push({
          url: response.url(),
          resourceType: type,
          encodedBodySize: transferSize,
          transferSize,
          contentEncoding: encoding
        });
      } catch {
        // ignore closed responses
      }
    }

    const compressible = samples.filter((s) =>
      ['script', 'stylesheet', 'document', 'font'].includes(s.resourceType)
    );
    const uncompressed = compressible.filter((s) => {
      if (s.transferSize > 0 && s.transferSize < 2048) {
        return false;
      }
      const enc = (s.contentEncoding || '').toLowerCase();
      return !enc.includes('br') && !enc.includes('gzip') && !enc.includes('deflate');
    });

    if (uncompressed.length >= 2) {
      const examples = uncompressed
        .slice(0, 3)
        .map((s) => s.url)
        .join('\n');
      findings.push({
        id: `PERF-COMP-${Date.now()}-${uid()}`,
        ruleId: 'PERF-COMPRESSION-MISSING',
        title: 'Assets sin compresión Brotli/Gzip',
        severity: 'MEDIUM',
        description: `${uncompressed.length} recurso(s) text/script/css sin Content-Encoding br/gzip.`,
        category: 'PERFORMANCE',
        ruleType: 'PERF_ASSET_OPTIMIZATION',
        evidence: {
          url: pageUrl,
          snippet: examples.slice(0, 2048),
          responseHeaders: { 'content-encoding': '[MISSING]' }
        },
        remediation: {
          explanation: 'Habilite Brotli (preferido) o Gzip en el CDN/origin para text assets.',
          codeBefore: 'Content-Encoding: (none)',
          codeAfter: 'Content-Encoding: br'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    const huge = samples.filter(
      (s) =>
        s.transferSize >= LARGE_ASSET_BYTES &&
        ['script', 'stylesheet'].includes(s.resourceType)
    );
    for (const asset of huge.slice(0, 5)) {
      findings.push({
        id: `PERF-ASSET-${Date.now()}-${uid()}`,
        ruleId: 'PERF-ASSET-LARGE',
        title: 'Asset JS/CSS > 1MB',
        severity: 'HIGH',
        description: `Recurso ${asset.resourceType} de ~${Math.round(asset.transferSize / 1024)}KB: ${asset.url.slice(0, 140)}`,
        category: 'PERFORMANCE',
        ruleType: 'PERF_ASSET_OPTIMIZATION',
        evidence: {
          url: pageUrl,
          snippet: `${asset.resourceType} ${asset.transferSize}B :: ${asset.url}`.slice(
            0,
            2048
          )
        },
        remediation: {
          explanation:
            'Aplique code-splitting, tree-shaking y elimine dependencias pesadas del critical path.',
          codeBefore: 'import "./monolith-bundle.js"',
          codeAfter: 'const mod = await import("./route-chunk.js")'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    return findings;
  }
}
