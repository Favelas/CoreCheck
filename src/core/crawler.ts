import { Page, Response } from 'playwright';

import { CoreCheckError } from '../utils/exit_codes.js';
import {
  formatWafNetworkMessage,
  isRetryableStatus,
  withExponentialBackoff
} from '../utils/http_retry.js';

export interface CrawlOptions {
  startUrl: string;
  maxDepth: number;
  maxPages: number;
  sameOriginOnly: boolean;
  timeoutMs: number;
  /** Tope de candidatos SPA por página (clicks suaves + data-attrs). */
  maxSpaCandidatesPerPage?: number;
}

export interface CrawledPage {
  url: string;
  depth: number;
}

export interface CrawlResult {
  pages: CrawledPage[];
  /** true si alguna navegación recibió 403/429/503 persistente. */
  wafBlocked: boolean;
  lastWafStatus?: number;
}

const DANGEROUS_TEXT =
  /\b(log\s*out|sign\s*out|delete|remove|destroy|unsubscribe|pay|checkout|comprar|eliminar|cerrar sesión)\b/i;

/**
 * Descubridor BFS same-origin:
 * - `<a href>` clásicos + hash-SPA
 * - atributos data-to / data-href / data-route / role=link
 * - clicks suaves acotados (anti side-effect) observando History API
 */
export class SiteCrawler {
  constructor(private readonly page: Page) {}

  public async crawl(options: CrawlOptions): Promise<CrawlResult> {
    const startUrl = this.normalizeUrl(options.startUrl);
    const baseOrigin = new URL(startUrl).origin;
    const maxSpa = options.maxSpaCandidatesPerPage ?? 8;

    const visited = new Set<string>();
    const queued = new Set<string>();
    const pages: CrawledPage[] = [];
    const queue: CrawledPage[] = [{ url: startUrl, depth: 0 }];
    queued.add(this.dedupeKey(startUrl));

    let wafBlocked = false;
    let lastWafStatus: number | undefined;
    let consecutiveWafFailures = 0;

    while (queue.length > 0 && pages.length < options.maxPages) {
      const current = queue.shift()!;
      queued.delete(this.dedupeKey(current.url));

      const visitKey = this.dedupeKey(current.url);
      if (visited.has(visitKey)) {
        continue;
      }
      visited.add(visitKey);

      let settledUrl = current.url;
      try {
        const nav = await this.gotoWithRetry(current.url, options.timeoutMs);
        if (nav.wafStatus !== undefined) {
          wafBlocked = true;
          lastWafStatus = nav.wafStatus;
          consecutiveWafFailures++;
          pages.push({ url: current.url, depth: current.depth });
          if (consecutiveWafFailures >= 2 && pages.length === consecutiveWafFailures) {
            throw new CoreCheckError(
              formatWafNetworkMessage(nav.wafStatus, current.url, nav.attempts),
              'NETWORK'
            );
          }
          continue;
        }
        consecutiveWafFailures = 0;
        settledUrl = this.normalizeUrl(this.page.url());
      } catch (error) {
        if (error instanceof CoreCheckError) {
          throw error;
        }
        console.warn(
          `[Crawler] No se pudo navegar a ${current.url}: ${(error as Error).message}`
        );
        pages.push({ url: current.url, depth: current.depth });
        continue;
      }

      const settledKey = this.dedupeKey(settledUrl);
      if (settledKey !== visitKey) {
        visited.add(settledKey);
      }

      pages.push({ url: settledUrl, depth: current.depth });

      if (pages.length >= options.maxPages) {
        break;
      }
      if (current.depth >= options.maxDepth) {
        continue;
      }

      const hrefs = await this.extractLinks();
      const spaHrefs = await this.discoverSpaRoutes(settledUrl, maxSpa);
      const combined = [...hrefs, ...spaHrefs];

      for (const href of combined) {
        if (pages.length + queue.length >= options.maxPages) {
          break;
        }
        const absolute = this.toAbsolute(href, settledUrl);
        if (!absolute) {
          continue;
        }

        let candidate: URL;
        try {
          candidate = new URL(absolute);
        } catch {
          continue;
        }

        if (options.sameOriginOnly && candidate.origin !== baseOrigin) {
          continue;
        }

        if (this.isNonDocumentUrl(candidate)) {
          continue;
        }

        const normalized = this.normalizeUrl(candidate.toString());
        const key = this.dedupeKey(normalized);
        if (visited.has(key) || queued.has(key)) {
          continue;
        }

        queued.add(key);
        queue.push({ url: normalized, depth: current.depth + 1 });
      }
    }

    if (wafBlocked && pages.length > 0 && pages.every(() => true) && lastWafStatus) {
      // Si la única(s) página(s) inicial(es) fueron WAF y no hay superficie útil.
      const onlyWaf =
        consecutiveWafFailures > 0 && pages.length <= consecutiveWafFailures;
      if (onlyWaf) {
        throw new CoreCheckError(
          formatWafNetworkMessage(lastWafStatus, startUrl, consecutiveWafFailures),
          'NETWORK'
        );
      }
    }

    return { pages, wafBlocked, lastWafStatus };
  }

  private async gotoWithRetry(
    url: string,
    timeoutMs: number
  ): Promise<{ response: Response | null; wafStatus?: number; attempts: number }> {
    const outcome = await withExponentialBackoff(
      async () => {
        const response = await this.page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout: timeoutMs
        });
        await new Promise((resolve) => setTimeout(resolve, 350));
        return response;
      },
      (response) => response?.status(),
      {
        maxAttempts: 4,
        baseDelayMs: 350,
        maxDelayMs: 6_000,
        onRetry: ({ attempt, status, delayMs }) => {
          console.warn(
            `[Crawler] Retry ${attempt} for ${url} (HTTP ${status}) — backoff ${delayMs}ms`
          );
        }
      }
    );

    const status = outcome.value?.status();
    if (isRetryableStatus(status)) {
      return {
        response: outcome.value,
        wafStatus: status,
        attempts: outcome.attempts
      };
    }

    return { response: outcome.value, attempts: outcome.attempts };
  }

  private async extractLinks(): Promise<string[]> {
    return this.page.$$eval(
      'a[href], [data-href], [data-to], [data-route], [data-url], [routerlink], [role="link"][href]',
      (nodes) =>
        nodes
          .map((node) => {
            const el = node as HTMLElement;
            return (
              el.getAttribute('href') ||
              el.getAttribute('data-href') ||
              el.getAttribute('data-to') ||
              el.getAttribute('data-route') ||
              el.getAttribute('data-url') ||
              el.getAttribute('routerlink') ||
              ''
            );
          })
          .map((href) => href.trim())
          .filter((href) => href.length > 0)
    );
  }

  /**
   * Descubre rutas SPA: observa pushState/hashchange y hace clicks suaves acotados.
   * Nunca hace click en logout/delete/submit peligrosos.
   */
  private async discoverSpaRoutes(
    baseUrl: string,
    maxCandidates: number
  ): Promise<string[]> {
    const discovered = new Set<string>();

    await this.page.evaluate(`(() => {
      const w = window;
      w.__corecheckRoutes = w.__corecheckRoutes || [];
      const push = (url) => {
        if (!w.__corecheckRoutes.includes(url)) w.__corecheckRoutes.push(url);
      };
      const wrap = (fn) => function () {
        try { push(String(arguments[2] || location.href)); } catch (e) {}
        return fn.apply(this, arguments);
      };
      if (!history.pushState.__cc) {
        history.pushState = wrap(history.pushState.bind(history));
        history.pushState.__cc = true;
      }
      if (!history.replaceState.__cc) {
        history.replaceState = wrap(history.replaceState.bind(history));
        history.replaceState.__cc = true;
      }
      window.addEventListener('hashchange', () => push(location.href));
    })()`);

    const candidates = this.page.locator(
      'a[href^="#"], button[data-route], [data-nav], [data-link], nav a, [role="link"], [role="menuitem"]'
    );
    const count = Math.min(await candidates.count().catch(() => 0), maxCandidates);

    for (let i = 0; i < count; i++) {
      const el = candidates.nth(i);
      const text = ((await el.innerText().catch(() => '')) || '').trim();
      if (DANGEROUS_TEXT.test(text)) {
        continue;
      }
      const before = this.page.url();
      try {
        await el.click({ timeout: 1_500, force: false });
        await new Promise((r) => setTimeout(r, 200));
        const after = this.page.url();
        if (after !== before) {
          discovered.add(after);
          if (this.dedupeKey(after) !== this.dedupeKey(baseUrl)) {
            await this.page
              .goto(baseUrl, {
                waitUntil: 'domcontentloaded',
                timeout: 10_000
              })
              .catch(() => undefined);
          }
        }
      } catch {
        /* click no navegable — ignorar */
      }
    }

    const hooked = (await this.page
      .evaluate(`(() => (window.__corecheckRoutes || []).slice())()`)
      .catch(() => [])) as string[];

    for (const route of hooked) {
      discovered.add(route);
    }

    return [...discovered];
  }

  private toAbsolute(href: string, baseUrl: string): string | null {
    const lower = href.toLowerCase();
    if (
      lower.startsWith('mailto:') ||
      lower.startsWith('tel:') ||
      lower.startsWith('javascript:') ||
      lower.startsWith('data:')
    ) {
      return null;
    }

    try {
      return new URL(href, baseUrl).toString();
    } catch {
      return null;
    }
  }

  private isNonDocumentUrl(url: URL): boolean {
    const path = url.pathname.toLowerCase();
    return /\.(png|jpe?g|gif|svg|webp|ico|pdf|zip|css|js|map|woff2?|ttf|mp4|mp3)$/i.test(path);
  }

  private dedupeKey(url: string): string {
    const parsed = new URL(url);
    const path = parsed.pathname.replace(/\/+$/, '') || '/';
    return `${parsed.origin}${path}${parsed.search}${parsed.hash}`;
  }

  private normalizeUrl(url: string): string {
    const parsed = new URL(url);
    if (parsed.pathname.length > 1) {
      parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    }
    return parsed.toString();
  }
}
