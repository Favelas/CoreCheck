import * as fs from 'node:fs';
import * as path from 'node:path';
import PDFDocument from 'pdfkit';

import {
  AuditFinding,
  AuditReportBundle,
  DimensionBreakdown,
  SeverityLevel
} from '../types/audit.js';

type PDFDoc = InstanceType<typeof PDFDocument>;

const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const DIM_LABELS: Record<string, string> = {
  SECURITY: 'Security (DAST)',
  ACCESSIBILITY: 'Accessibility (WCAG)',
  NETWORK: 'Network',
  PERFORMANCE: 'Performance',
  SEO: 'SEO / GEO',
  PRIVACY: 'Privacy'
};

function severityColor(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return '#b91c1c';
    case 'HIGH':
      return '#c2410c';
    case 'MEDIUM':
      return '#1d4ed8';
    case 'LOW':
      return '#0e7490';
    default:
      return '#4b5563';
  }
}

function scoreColor(score: number): string {
  if (score >= 85) return '#15803d';
  if (score >= 70) return '#ca8a04';
  return '#b91c1c';
}

/**
 * Generador de PDF ejecutivo C-Level / Auditores (pdfkit).
 * Branding CoreCheck · Score · Top Risks · 6 dimensiones · Compliance · Roadmap.
 */
export class PdfReporter {
  public async generate(bundle: AuditReportBundle, outputPath: string): Promise<void> {
    await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });

    const doc = new PDFDocument({
      size: 'A4',
      bufferPages: true,
      margins: { top: 48, bottom: 52, left: 48, right: 48 },
      info: {
        Title: 'CoreCheck Executive Audit Report',
        Author: 'CoreCheck DevSecOps Engine',
        Subject: bundle.target,
        Keywords: 'CoreCheck, DAST, WCAG, Compliance, CVSS'
      }
    });

    const stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);

    this.drawBrandedHeader(doc, bundle);
    this.drawCover(doc, bundle);
    this.drawExecutiveSummary(doc, bundle);
    this.drawTopRisks(doc, bundle);
    this.drawDimensions(doc, bundle);
    this.drawCompliance(doc, bundle);
    this.drawCriticalFindings(doc, bundle);
    this.drawRemediationRoadmap(doc, bundle);
    this.drawFooter(doc);

    doc.end();
    await new Promise<void>((resolve, reject) => {
      stream.on('finish', () => resolve());
      stream.on('error', reject);
    });
  }

  private drawBrandedHeader(doc: PDFDoc, bundle: AuditReportBundle): void {
    const left = doc.page.margins.left;
    const right = doc.page.width - doc.page.margins.right;
    doc.rect(left - 48, 0, doc.page.width, 36).fill('#0f172a');
    doc
      .fillColor('#f8fafc')
      .fontSize(11)
      .text('CoreCheck  ·  Enterprise Digital Quality Gate', left, 12, {
        width: right - left - 120,
        continued: false
      });
    doc
      .fillColor('#94a3b8')
      .fontSize(8)
      .text('v3.0 Enterprise', right - 80, 14, { width: 80, align: 'right' });
    doc.y = 52;
    void bundle;
  }

  private drawCover(doc: PDFDoc, bundle: AuditReportBundle): void {
    doc.fillColor('#0f172a').fontSize(18).text('Executive Audit Report');
    doc.moveDown(0.3);
    doc.fontSize(9).fillColor('#475569');
    doc.text(`Target: ${bundle.target}`);
    doc.text(`Generated: ${bundle.timestamp}`);
    doc.text(`Pages scanned: ${bundle.scannedPages.length}`);
    doc.text(
      `Environment: ${bundle.environment ?? 'prod'}  ·  Gate (${bundle.failOn}): ${
        bundle.gateFailed ? 'FAIL' : 'PASS'
      }`
    );
    if (bundle.suppressedCount) {
      doc.text(`Baseline suppressions: ${bundle.suppressedCount}`);
    }

    doc.moveDown(0.8);
    const score = bundle.digitalQualityScore;
    doc
      .fontSize(32)
      .fillColor(scoreColor(score))
      .text(`${score.toFixed(1)}`, { continued: false });
    doc.fontSize(9).fillColor('#64748b').text('Digital Quality Score (0–100, CVSS-adjusted)');
    if (bundle.maxCvssScore > 0) {
      doc
        .fontSize(8)
        .fillColor('#b91c1c')
        .text(`Max CVSS base score: ${bundle.maxCvssScore.toFixed(1)}`);
    }

    doc.moveDown(0.8);
    doc
      .strokeColor('#e2e8f0')
      .lineWidth(1)
      .moveTo(doc.page.margins.left, doc.y)
      .lineTo(doc.page.width - doc.page.margins.right, doc.y)
      .stroke();
    doc.moveDown(0.8);
  }

  private drawExecutiveSummary(doc: PDFDoc, bundle: AuditReportBundle): void {
    this.ensureSpace(doc, 120);
    doc.fontSize(13).fillColor('#0f172a').text('1. Executive Summary');
    doc.moveDown(0.35);
    doc.fontSize(8).fillColor('#334155');
    doc.text(
      'Consolidated view of DAST security, WCAG accessibility, network hygiene, web performance, ' +
        'SEO/GEO readiness and privacy controls — calibrated with CVSS and mapped to ISO 27001, ' +
        'SOC 2, PCI-DSS v4.0, EN 301 549 and WCAG/ADA.'
    );
    doc.moveDown(0.5);

    doc.fontSize(9).fillColor('#0f172a').text('Findings by severity');
    doc.moveDown(0.25);

    const startX = doc.page.margins.left;
    let x = startX;
    const y = doc.y;
    const boxW = 85;

    for (const sev of SEVERITY_ORDER) {
      const count = bundle.severityCounts[sev] ?? 0;
      doc.rect(x, y, boxW - 6, 34).fill(severityColor(sev));
      doc.fillColor('#ffffff').fontSize(7).text(sev, x + 6, y + 5, { width: boxW - 18 });
      doc.fontSize(13).text(String(count), x + 6, y + 15, { width: boxW - 18 });
      x += boxW;
    }

    doc.y = y + 44;
    doc
      .fontSize(8)
      .fillColor('#475569')
      .text(
        `Total: ${bundle.findings.length}  ·  Compliance-mapped: ${bundle.compliance.mappedFindingCount}`
      );
    doc.moveDown(0.8);
  }

  private drawTopRisks(doc: PDFDoc, bundle: AuditReportBundle): void {
    this.ensureSpace(doc, 100);
    doc.fontSize(13).fillColor('#0f172a').text('2. C-Level Top Risks');
    doc.moveDown(0.35);

    const top = [...bundle.findings]
      .sort((a, b) => {
        const cvssDelta = (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0);
        if (cvssDelta !== 0) return cvssDelta;
        return this.sevRank(b.severity) - this.sevRank(a.severity);
      })
      .slice(0, 5);

    if (top.length === 0) {
      doc.fontSize(8).fillColor('#15803d').text('No material risks identified in this run.');
      doc.moveDown(0.6);
      return;
    }

    top.forEach((f, i) => {
      this.ensureSpace(doc, 28);
      const cvss = f.cvss ? ` · CVSS ${f.cvss.baseScore}` : '';
      doc
        .fontSize(8)
        .fillColor(severityColor(f.severity))
        .text(`${i + 1}. [${f.severity}] ${f.ruleId}${cvss}`, { continued: false });
      doc.fontSize(8).fillColor('#334155').text(`   ${this.truncate(f.title, 110)}`);
    });
    doc.moveDown(0.8);
  }

  private drawDimensions(doc: PDFDoc, bundle: AuditReportBundle): void {
    this.ensureSpace(doc, 160);
    doc.fontSize(13).fillColor('#0f172a').text('3. Six-Dimension Breakdown');
    doc.moveDown(0.3);
    doc
      .fontSize(8)
      .fillColor('#64748b')
      .text(
        'Security · Accessibility · Network · Performance · SEO/GEO · Privacy. Score 100 = clean dimension.'
      );
    doc.moveDown(0.5);

    const barMax = 220;
    for (const dim of bundle.dimensions) {
      this.ensureSpace(doc, 24);
      this.drawDimensionRow(doc, dim, barMax);
    }
    doc.moveDown(0.8);
  }

  private drawDimensionRow(doc: PDFDoc, dim: DimensionBreakdown, barMax: number): void {
    const label = DIM_LABELS[dim.dimension] ?? dim.dimension;
    const y = doc.y;
    const left = doc.page.margins.left;

    doc.fontSize(8).fillColor('#0f172a').text(label, left, y, { width: 150 });
    doc
      .fontSize(7)
      .fillColor('#64748b')
      .text(`${dim.count} findings`, left + 150, y, { width: 70 });

    const barX = left + 230;
    doc.rect(barX, y + 2, barMax, 9).fill('#e2e8f0');
    const filled = Math.max(2, (dim.score / 100) * barMax);
    doc.rect(barX, y + 2, filled, 9).fill(scoreColor(dim.score));
    doc
      .fontSize(8)
      .fillColor(scoreColor(dim.score))
      .text(String(dim.score), barX + barMax + 8, y, { width: 36 });

    doc.y = y + 16;
  }

  private drawCompliance(doc: PDFDoc, bundle: AuditReportBundle): void {
    this.ensureSpace(doc, 140);
    doc.fontSize(13).fillColor('#0f172a').text('4. Regulatory & Compliance Mapping');
    doc.moveDown(0.3);
    doc
      .fontSize(8)
      .fillColor('#64748b')
      .text(
        'ISO/IEC 27001 · SOC 2 Type II · PCI-DSS v4.0 · EN 301 549 · WCAG 2.1/2.2 AA · ADA'
      );
    doc.moveDown(0.5);

    for (const fw of bundle.compliance.frameworks) {
      this.ensureSpace(doc, 36);
      doc
        .fontSize(9)
        .fillColor('#0f172a')
        .text(
          `${fw.framework}  ·  gaps: ${fw.gapCount}  ·  related findings: ${fw.relatedFindings}`
        );

      const gapControls = fw.controls.filter((c) => c.status === 'GAP').slice(0, 4);
      if (gapControls.length === 0) {
        doc
          .fontSize(7)
          .fillColor('#15803d')
          .text('  No HIGH/CRITICAL gaps for mapped controls.');
      } else {
        for (const c of gapControls) {
          doc
            .fontSize(7)
            .fillColor('#b91c1c')
            .text(
              `  [GAP] ${c.controlId} — ${c.controlTitle} (${c.relatedFindingIds.length})`
            );
        }
      }
      doc.moveDown(0.25);
    }
    doc.moveDown(0.5);
  }

  private drawCriticalFindings(doc: PDFDoc, bundle: AuditReportBundle): void {
    this.ensureSpace(doc, 80);
    doc.fontSize(13).fillColor('#0f172a').text('5. Critical & High Findings (Evidence)');
    doc.moveDown(0.35);

    const critical = bundle.findings
      .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      .slice(0, 20);

    if (critical.length === 0) {
      doc.fontSize(8).fillColor('#15803d').text('No CRITICAL or HIGH findings in this run.');
      doc.moveDown(0.6);
      return;
    }

    for (const finding of critical) {
      this.drawFindingCard(doc, finding);
    }
  }

  private drawRemediationRoadmap(doc: PDFDoc, bundle: AuditReportBundle): void {
    this.ensureSpace(doc, 100);
    doc.fontSize(13).fillColor('#0f172a').text('6. Remediation Roadmap');
    doc.moveDown(0.35);
    doc
      .fontSize(8)
      .fillColor('#64748b')
      .text('Prioritized backlog for engineering — Immediate / Near-term / Backlog.');
    doc.moveDown(0.4);

    const immediate = bundle.findings.filter(
      (f) => f.severity === 'CRITICAL' || (f.cvss?.baseScore ?? 0) >= 9
    );
    const nearTerm = bundle.findings.filter(
      (f) =>
        f.severity === 'HIGH' &&
        !immediate.includes(f) &&
        (f.cvss?.baseScore ?? 7) >= 7
    );
    const backlog = bundle.findings.filter(
      (f) => f.severity === 'MEDIUM' || f.severity === 'LOW'
    );

    this.drawRoadmapBucket(doc, 'Immediate (P0)', immediate.slice(0, 8), '#b91c1c');
    this.drawRoadmapBucket(doc, 'Near-term (P1)', nearTerm.slice(0, 8), '#c2410c');
    this.drawRoadmapBucket(doc, 'Backlog (P2)', backlog.slice(0, 8), '#1d4ed8');
  }

  private drawRoadmapBucket(
    doc: PDFDoc,
    title: string,
    items: AuditFinding[],
    color: string
  ): void {
    this.ensureSpace(doc, 40);
    doc.fontSize(9).fillColor(color).text(title);
    if (items.length === 0) {
      doc.fontSize(7).fillColor('#94a3b8').text('  — none —');
      doc.moveDown(0.3);
      return;
    }
    for (const f of items) {
      this.ensureSpace(doc, 16);
      doc
        .fontSize(7)
        .fillColor('#334155')
        .text(
          `  • ${f.ruleId}: ${this.truncate(f.remediation.explanation, 140)}`
        );
    }
    doc.moveDown(0.35);
  }

  private drawFindingCard(doc: PDFDoc, finding: AuditFinding): void {
    this.ensureSpace(doc, 88);

    const cvssLabel = finding.cvss
      ? ` · CVSS ${finding.cvss.version} ${finding.cvss.baseScore}`
      : '';
    doc
      .fontSize(9)
      .fillColor(severityColor(finding.severity))
      .text(`[${finding.severity}] ${finding.ruleId}${cvssLabel}`);
    doc.fontSize(8).fillColor('#0f172a').text(finding.title);
    doc.fontSize(7).fillColor('#475569').text(this.truncate(finding.description, 280));

    const evidenceBits: string[] = [];
    if (finding.evidence.url) evidenceBits.push(`URL: ${finding.evidence.url}`);
    if (finding.evidence.selector) {
      evidenceBits.push(`Selector: ${finding.evidence.selector}`);
    }
    if (finding.evidence.responseHeaders) {
      const hdr = Object.keys(finding.evidence.responseHeaders).slice(0, 3).join(', ');
      if (hdr) evidenceBits.push(`Headers: ${hdr}`);
    }
    if (finding.evidence.snippet) {
      evidenceBits.push(`Evidence: ${this.truncate(finding.evidence.snippet, 140)}`);
    }
    if (finding.cvss) {
      evidenceBits.push(`Vector: ${finding.cvss.vector}`);
    }

    if (evidenceBits.length > 0) {
      doc.fontSize(6.5).fillColor('#64748b').text(evidenceBits.join('  |  '));
    }

    const standards = [
      ...(finding.standards.iso27001?.map((c) => `ISO:${c}`) ?? []),
      ...(finding.standards.soc2?.map((c) => `SOC2:${c}`) ?? []),
      ...(finding.standards.pciDss?.map((c) => `PCI:${c}`) ?? []),
      ...(finding.standards.en301549?.map((c) => `EN301549:${c}`) ?? []),
      ...(finding.standards.wcag?.slice(0, 2).map((c) => `WCAG:${c}`) ?? []),
      ...(finding.standards.ada?.map((c) => `ADA:${c}`) ?? [])
    ].slice(0, 8);

    if (standards.length > 0) {
      doc.fontSize(6.5).fillColor('#1d4ed8').text(`Compliance: ${standards.join(', ')}`);
    }

    doc
      .fontSize(7)
      .fillColor('#0f172a')
      .text(`Remediation: ${this.truncate(finding.remediation.explanation, 240)}`);

    doc.moveDown(0.5);
  }

  private drawFooter(doc: PDFDoc): void {
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      const bottom = doc.page.height - 28;
      doc
        .fontSize(7)
        .fillColor('#94a3b8')
        .text(
          `CoreCheck Enterprise  ·  Confidential  ·  Page ${i - range.start + 1} of ${range.count}`,
          doc.page.margins.left,
          bottom,
          {
            width: doc.page.width - doc.page.margins.left - doc.page.margins.right,
            align: 'center'
          }
        );
    }
  }

  private ensureSpace(doc: PDFDoc, needed: number): void {
    const bottom = doc.page.height - doc.page.margins.bottom;
    if (doc.y + needed > bottom) {
      doc.addPage();
      this.drawBrandedHeader(doc, {
        target: '',
        timestamp: '',
        scannedPages: [],
        findings: [],
        digitalQualityScore: 0,
        maxCvssScore: 0,
        severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        dimensions: [],
        compliance: { frameworks: [], mappedFindingCount: 0 },
        gateFailed: false,
        failOn: 'HIGH'
      });
    }
  }

  private sevRank(severity: SeverityLevel): number {
    return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }[severity] ?? 0;
  }

  private truncate(text: string, max: number): string {
    const clean = text.replace(/\s+/g, ' ').trim();
    if (clean.length <= max) return clean;
    return `${clean.slice(0, max - 1)}…`;
  }
}

export async function generatePdfReport(
  bundle: AuditReportBundle,
  outputPath: string
): Promise<void> {
  const reporter = new PdfReporter();
  await reporter.generate(bundle, outputPath);
}
