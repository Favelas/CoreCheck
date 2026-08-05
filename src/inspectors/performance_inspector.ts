import { Page, Response } from 'playwright';

import { AuditFinding } from '../types/audit.js';

const LCP_BUDGET_MS = 2500;
const CLS_BUDGET = 0.1;
const DCL_BUDGET_MS = 3000;
const LOAD_BUDGET_MS = 5000;
const LARGE_IMAGE_BYTES = 500 * 1024;
const LARGE_ASSET_BYTES = 1024 * 1024;

interface PerfMetrics {
  lcpMs: number | null;
  cls: number | null;
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
 * Métricas Web Vitals básicas + optimización de assets (imágenes / compresión).
 */
export class PerformanceInspector {
  private readonly responses: Response[] = [];
  private attached = false;

  constructor(private readonly page: Page) {}

  /** Adjuntar antes de page.goto para capturar respuestas de red. */
  public attach(): void {
    if (this.attached) {
      return;
    }
    this.attached = true;
    this.page.on('response', (response) => {
      this.responses.push(response);
    });

    void this.page.addInitScript(() => {
      const w = window as unknown as {
        __corecheckLcp?: number;
        __corecheckCls?: number;
      };
      w.__corecheckLcp = 0;
      w.__corecheckCls = 0;
      try {
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            w.__corecheckLcp = entry.startTime;
          }
        }).observe({ type: 'largest-contentful-paint', buffered: true } as PerformanceObserverInit);
      } catch {
        // unsupported
      }
      try {
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries() as Array<
            PerformanceEntry & { value?: number; hadRecentInput?: boolean }
          >) {
            if (!entry.hadRecentInput) {
              w.__corecheckCls = (w.__corecheckCls || 0) + (entry.value || 0);
            }
          }
        }).observe({ type: 'layout-shift', buffered: true } as PerformanceObserverInit);
      } catch {
        // unsupported
      }
    });
  }

  public async inspect(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];

    await this.page.waitForTimeout(600).catch(() => {});

    const metrics = await this.collectMetrics();
    findings.push(...this.findingsFromMetrics(pageUrl, metrics));
    findings.push(...(await this.inspectImages(pageUrl)));
    findings.push(...(await this.inspectCompressionAndAssets(pageUrl)));

    return findings;
  }

  private async collectMetrics(): Promise<PerfMetrics> {
    return this.page.evaluate(() => {
      const w = window as unknown as {
        __corecheckLcp?: number;
        __corecheckCls?: number;
      };
      const nav = performance.getEntriesByType('navigation')[0] as
        | PerformanceNavigationTiming
        | undefined;

      let lcpMs: number | null = null;
      const lcpEntries = performance.getEntriesByType('largest-contentful-paint') as Array<{
        startTime: number;
      }>;
      if (lcpEntries.length > 0) {
        lcpMs = lcpEntries[lcpEntries.length - 1].startTime;
      } else if (w.__corecheckLcp && w.__corecheckLcp > 0) {
        lcpMs = w.__corecheckLcp;
      } else {
        const paints = performance.getEntriesByType('paint');
        const fcp = paints.find((p) => p.name === 'first-contentful-paint');
        if (fcp) {
          lcpMs = fcp.startTime;
        }
      }

      let cls: number | null = null;
      const layoutShifts = performance.getEntriesByType('layout-shift') as unknown as Array<{
        value: number;
        hadRecentInput?: boolean;
      }>;
      if (layoutShifts.length > 0) {
        cls = 0;
        for (const entry of layoutShifts) {
          if (!entry.hadRecentInput) {
            cls += entry.value;
          }
        }
      } else if (typeof w.__corecheckCls === 'number') {
        cls = w.__corecheckCls;
      }

      return {
        lcpMs,
        cls,
        domContentLoadedMs: nav
          ? nav.domContentLoadedEventEnd - nav.startTime
          : null,
        loadEventMs: nav ? nav.loadEventEnd - nav.startTime : null
      };
    });
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
          codeAfter: '<link rel="preload" as="image" href="hero.webp">\n<img src="hero.webp" fetchpriority="high">'
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
          codeAfter: '<img src="banner.jpg" width="1200" height="400" style="aspect-ratio:3/1">'
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

  private async inspectImages(pageUrl: string): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const uid = () => Math.random().toString(36).slice(2, 7);

    const heavyImages = await this.page
      .evaluate((limitBytes) => {
        const imgs = Array.from(document.querySelectorAll('img'));
        const heavy: Array<{ src: string; naturalWidth: number; naturalHeight: number }> = [];
        for (const img of imgs) {
          const pixels = img.naturalWidth * img.naturalHeight;
          // Heurística: > 2MP sin srcset / sizes sugiere asset sobredimensionado.
          if (pixels > 2_000_000 && !img.srcset) {
            heavy.push({
              src: img.currentSrc || img.src,
              naturalWidth: img.naturalWidth,
              naturalHeight: img.naturalHeight
            });
          }
          void limitBytes;
        }
        return heavy.slice(0, 8);
      }, LARGE_IMAGE_BYTES)
      .catch(() => [] as Array<{ src: string; naturalWidth: number; naturalHeight: number }>);

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
          codeAfter: '<img src="hero-800.webp" srcset="hero-400.webp 400w, hero-800.webp 800w" sizes="100vw">'
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
      (s) => s.transferSize >= LARGE_ASSET_BYTES && ['script', 'stylesheet'].includes(s.resourceType)
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
          snippet: `${asset.resourceType} ${asset.transferSize}B :: ${asset.url}`.slice(0, 2048)
        },
        remediation: {
          explanation: 'Aplique code-splitting, tree-shaking y elimine dependencias pesadas del critical path.',
          codeBefore: 'import "./monolith-bundle.js"',
          codeAfter: 'const mod = await import("./route-chunk.js")'
        },
        standards: { owasp: [], cwe: [] }
      });
    }

    return findings;
  }
}
