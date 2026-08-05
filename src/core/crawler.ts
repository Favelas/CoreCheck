import { Page } from 'playwright';

export interface CrawlOptions {
  startUrl: string;
  maxDepth: number;
  maxPages: number;
  sameOriginOnly: boolean;
  timeoutMs: number;
}

export interface CrawledPage {
  url: string;
  depth: number;
}

export interface CrawlResult {
  pages: CrawledPage[];
}

/**
 * Descubridor BFS same-origin de rutas HTML / hash-SPA.
 * Extrae `<a href>`, respeta maxDepth/maxPages y deduplica con Set.
 */
export class SiteCrawler {
  constructor(private readonly page: Page) {}

  public async crawl(options: CrawlOptions): Promise<CrawlResult> {
    const startUrl = this.normalizeUrl(options.startUrl);
    const baseOrigin = new URL(startUrl).origin;

    const visited = new Set<string>();
    const queued = new Set<string>();
    const pages: CrawledPage[] = [];
    const queue: CrawledPage[] = [{ url: startUrl, depth: 0 }];
    queued.add(this.dedupeKey(startUrl));

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
        await this.page.goto(current.url, {
          waitUntil: 'domcontentloaded',
          timeout: options.timeoutMs
        });
        await new Promise((resolve) => setTimeout(resolve, 400));
        settledUrl = this.normalizeUrl(this.page.url());
      } catch (error) {
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
      for (const href of hrefs) {
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

    return { pages };
  }

  private async extractLinks(): Promise<string[]> {
    return this.page.$$eval('a[href]', (anchors) =>
      anchors
        .map((anchor) => anchor.getAttribute('href') || '')
        .map((href) => href.trim())
        .filter((href) => href.length > 0)
    );
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
