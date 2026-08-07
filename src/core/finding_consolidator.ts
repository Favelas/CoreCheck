import { AuditFinding, FindingLocation } from '../types/audit.js';

export type FindingScope = 'SITE' | 'PAGE';

export interface ConsolidationStats {
  beforeCount: number;
  afterCount: number;
  siteLevelMerged: number;
  uniqueSiteRules: number;
  affectedPageRefs: number;
}

export interface ConsolidationResult {
  findings: AuditFinding[];
  stats: ConsolidationStats;
}

/**
 * Reglas de alcance de sitio: la misma misconfiguración se observa en todas
 * (o muchas) páginas del origin. Se consolidan a 1 hallazgo + lista de URLs.
 */
const SITE_LEVEL_RULE_TESTS: RegExp[] = [
  /^SEC-HDR-/i,
  /^PRIV-POLICY-LINK-MISSING$/i,
  /^PRIV-COOKIE-POLICY-LINK-MISSING$/i,
  /^PRIV-THIRD-PARTY-COOKIE-PRECONSENT$/i,
  /^PRIV-COOKIE-BEFORE-CONSENT-UI$/i,
  /^SEO-ROBOTS-TXT-/i,
  /^LLM-/i,
  /^SEO-LLM-/i
];

/**
 * Consolida hallazgos site-level (headers, privacy policy, robots.txt)
 * en un único finding por ruleId, listando páginas afectadas.
 * Los hallazgos page-level (A11y, forms, SEO por URL, etc.) se preservan.
 */
export class FindingConsolidator {
  public isSiteLevel(finding: AuditFinding): boolean {
    return SITE_LEVEL_RULE_TESTS.some((re) => re.test(finding.ruleId));
  }

  public resolveScope(finding: AuditFinding): FindingScope {
    return this.isSiteLevel(finding) ? 'SITE' : 'PAGE';
  }

  public consolidate(findings: AuditFinding[]): ConsolidationResult {
    const beforeCount = findings.length;
    const pageLevel: AuditFinding[] = [];
    const siteBuckets = new Map<string, AuditFinding[]>();

    for (const finding of findings) {
      if (this.isSiteLevel(finding)) {
        const key = this.siteMergeKey(finding);
        const bucket = siteBuckets.get(key) ?? [];
        bucket.push(finding);
        siteBuckets.set(key, bucket);
      } else {
        pageLevel.push(finding);
      }
    }

    const consolidatedSite: AuditFinding[] = [];
    let siteLevelMerged = 0;
    let affectedPageRefs = 0;

    for (const [, group] of siteBuckets) {
      if (group.length === 1) {
        const single = this.annotateSiteFinding(group[0], this.collectUrls(group));
        consolidatedSite.push(single);
        affectedPageRefs += this.collectUrls(group).length;
        continue;
      }

      siteLevelMerged += group.length - 1;
      const merged = this.mergeSiteGroup(group);
      consolidatedSite.push(merged);
      affectedPageRefs += (merged.evidence.locations ?? []).filter((l) => l.url).length;
    }

    const findingsOut = [...consolidatedSite, ...pageLevel];

    return {
      findings: findingsOut,
      stats: {
        beforeCount,
        afterCount: findingsOut.length,
        siteLevelMerged,
        uniqueSiteRules: consolidatedSite.length,
        affectedPageRefs
      }
    };
  }

  /** Clave de fusión: ruleId (+ fingerprint de evidencia estable si aplica). */
  private siteMergeKey(finding: AuditFinding): string {
    // Headers / policy / robots: un único issue por regla en el sitio.
    return finding.ruleId;
  }

  private mergeSiteGroup(group: AuditFinding[]): AuditFinding {
    const primary = group[0];
    const urls = this.collectUrls(group);
    const locations = this.mergeLocations(group);

    const pathList = urls.map((u) => this.toPathLabel(u));
    const preview = pathList.slice(0, 8).join(', ');
    const more = pathList.length > 8 ? ` (+${pathList.length - 8} más)` : '';

    const affectedBlock =
      urls.length > 0
        ? `Afecta a ${urls.length} página(s): ${preview}${more}.`
        : 'Afecta a múltiples páginas del sitio.';

    const titleBase = primary.title.replace(/\s*\(\d+\s+elementos?\s+detectados\)\s*$/i, '');

    return {
      ...primary,
      id: `SITE-${primary.ruleId}-${this.stableShortHash(primary.ruleId + urls.join('|'))}`,
      title:
        urls.length > 1
          ? `${titleBase} (${urls.length} páginas afectadas)`
          : titleBase,
      description: `${primary.description} ${affectedBlock}`,
      evidence: {
        ...primary.evidence,
        // URL representativa = primera página; el detalle vive en locations.
        url: urls[0] ?? primary.evidence.url,
        snippet: this.buildAffectedSnippet(urls, primary.evidence.snippet),
        locations
      }
    };
  }

  private annotateSiteFinding(finding: AuditFinding, urls: string[]): AuditFinding {
    if (urls.length <= 1) {
      return {
        ...finding,
        evidence: {
          ...finding.evidence,
          locations:
            finding.evidence.locations ??
            (finding.evidence.url
              ? [{ url: finding.evidence.url, snippet: finding.evidence.snippet }]
              : undefined)
        }
      };
    }
    return this.mergeSiteGroup([finding]);
  }

  private collectUrls(group: AuditFinding[]): string[] {
    const set = new Set<string>();
    for (const f of group) {
      if (f.evidence.url) set.add(f.evidence.url);
      for (const loc of f.evidence.locations ?? []) {
        if (loc.url) set.add(loc.url);
      }
    }
    return [...set];
  }

  private mergeLocations(group: AuditFinding[]): FindingLocation[] {
    const byUrl = new Map<string, FindingLocation>();
    for (const f of group) {
      const url = f.evidence.url;
      if (url && !byUrl.has(url)) {
        byUrl.set(url, {
          url,
          selector: f.evidence.selector,
          snippet: f.evidence.snippet
        });
      }
      for (const loc of f.evidence.locations ?? []) {
        const key = loc.url ?? '';
        if (key && !byUrl.has(key)) {
          byUrl.set(key, { ...loc });
        }
      }
    }
    return [...byUrl.values()];
  }

  private buildAffectedSnippet(urls: string[], original?: string): string {
    const lines = [
      `Affected pages (${urls.length}):`,
      ...urls.map((u) => ` - ${u}`)
    ];
    if (original && original.trim() && !original.startsWith('Affected pages')) {
      lines.push('', 'Evidence sample:', original.slice(0, 512));
    }
    return lines.join('\n').slice(0, 2048);
  }

  private toPathLabel(url: string): string {
    try {
      const u = new URL(url);
      return u.pathname + u.search || '/';
    } catch {
      return url;
    }
  }

  private stableShortHash(input: string): string {
    let h = 0;
    for (let i = 0; i < input.length; i++) {
      h = (h * 31 + input.charCodeAt(i)) >>> 0;
    }
    return h.toString(36).slice(0, 7);
  }
}

/** Helper exportado para reporters: lista compacta de páginas afectadas. */
export function formatAffectedPages(finding: AuditFinding, max = 12): string {
  const urls = [
    ...new Set(
      [
        ...(finding.evidence.locations?.map((l) => l.url).filter(Boolean) ?? []),
        ...(finding.evidence.url ? [finding.evidence.url] : [])
      ].filter((u): u is string => Boolean(u))
    )
  ];
  if (urls.length === 0) return '';
  const labels = urls.map((u) => {
    try {
      const parsed = new URL(u);
      return parsed.pathname + parsed.search || '/';
    } catch {
      return u;
    }
  });
  const head = labels.slice(0, max).join(', ');
  const more = labels.length > max ? ` (+${labels.length - max} más)` : '';
  return `Afecta a ${labels.length} página(s): ${head}${more}`;
}
