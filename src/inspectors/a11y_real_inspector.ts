import { AxeBuilder } from '@axe-core/playwright';
import type { Result as AxeResult, NodeResult } from 'axe-core';
import { Page } from 'playwright';
import { AuditFinding, SeverityLevel } from '../types/audit.js';

function mapAxeImpact(impact: string | null | undefined): SeverityLevel {
  switch ((impact || '').toLowerCase()) {
    case 'critical':
      return 'CRITICAL';
    case 'serious':
      return 'HIGH';
    case 'moderate':
      return 'MEDIUM';
    case 'minor':
    default:
      return 'LOW';
  }
}

function extractWcagTags(tags: string[]): string[] {
  const wcag: string[] = [];
  const tagSet = new Set(tags.map((t) => t.toLowerCase()));

  if (tagSet.has('wcag21a') || tagSet.has('wcag2a')) {
    wcag.push('WCAG 2.1 A');
  }
  if (tagSet.has('wcag21aa') || tagSet.has('wcag2aa')) {
    wcag.push('WCAG 2.1 AA');
  }
  if (tagSet.has('wcag22aa')) {
    wcag.push('WCAG 2.2 AA');
  }
  if (tagSet.has('wcag22aaa') || tagSet.has('wcag2aaa')) {
    wcag.push('WCAG 2.2 AAA');
  }

  for (const tag of tags) {
    const match = /^wcag(\d)(\d)(\d+)$/i.exec(tag);
    if (match) {
      wcag.push(`${match[1]}.${match[2]}.${match[3]}`);
    }
  }

  if (wcag.length === 0) {
    wcag.push('WCAG 2.1 AA', 'WCAG 2.2 AA');
  }

  return [...new Set(wcag)];
}

/**
 * Inspector de accesibilidad real basado en axe-core (WCAG 2.1 / 2.2 AA).
 */
export class A11yRealInspector {
  constructor(private readonly page: Page) {}

  public async inspect(): Promise<AuditFinding[]> {
    const pageUrl = this.page.url();
    const results = await new AxeBuilder({ page: this.page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze();

    const findings: AuditFinding[] = [];

    for (const violation of results.violations as AxeResult[]) {
      const severity = mapAxeImpact(violation.impact);
      const wcag = extractWcagTags(violation.tags || []);
      const nodes: NodeResult[] = violation.nodes || [];
      const primary = nodes[0];
      const selector = primary?.target?.join(' ') || undefined;
      const snippet = (primary?.html || primary?.failureSummary || '').slice(0, 2048);

      findings.push({
        id: `A11Y-${violation.id}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        ruleId: `A11Y-${violation.id}`,
        title: violation.help || `Violación de accesibilidad: ${violation.id}`,
        severity,
        description: `${violation.description} Nodos afectados: ${nodes.length}.`,
        category: 'A11Y',
        ruleType: 'A11Y_VIOLATION',
        evidence: {
          url: pageUrl,
          selector,
          snippet,
          locations: nodes.slice(0, 10).map((node: NodeResult) => ({
            url: pageUrl,
            selector: node.target?.join(' '),
            snippet: (node.html || '').slice(0, 512)
          }))
        },
        remediation: {
          explanation:
            violation.help ||
            'Corrija la violación WCAG reportada por axe-core para cumplir el nivel AA.',
          codeBefore: snippet || undefined,
          codeAfter: primary?.failureSummary
            ? `/* Remediación sugerida */\n${primary.failureSummary}`
            : undefined
        },
        standards: {
          wcag,
          cwe: ['CWE-1021']
        }
      });
    }

    return findings;
  }
}
