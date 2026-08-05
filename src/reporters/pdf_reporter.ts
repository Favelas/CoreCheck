import * as fs from 'node:fs';
import * as path from 'node:path';
import PDFDocument from 'pdfkit';
import QRCode from 'qrcode';

import {
  AuditAttestation,
  AuditFinding,
  AuditReportBundle,
  DimensionBreakdown,
  SeverityLevel
} from '../types/audit.js';
import {
  buildAttestation,
  computeAuditHash,
  pathToDashboardUrl,
  resolveDashboardBaseUrl
} from '../utils/attestation.js';

export {
  buildAttestation,
  computeAuditHash,
  pathToDashboardUrl,
  resolveDashboardBaseUrl
} from '../utils/attestation.js';

type PDFDoc = InstanceType<typeof PDFDocument>;

const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const DIM_LABELS: Record<string, string> = {
  SECURITY: 'Security',
  ACCESSIBILITY: 'Accessibility',
  NETWORK: 'Network',
  PERFORMANCE: 'Performance',
  SEO: 'SEO / GEO',
  PRIVACY: 'Privacy'
};

/** Paleta Enterprise (firma / Big Four). */
const C = {
  ink: '#0B1220',
  slate: '#1E293B',
  muted: '#64748B',
  line: '#CBD5E1',
  paper: '#F8FAFC',
  white: '#FFFFFF',
  accent: '#0EA5E9',
  pass: '#16A34A',
  fail: '#DC2626',
  codeBg: '#E2E8F0',
  codeFg: '#0F172A'
} as const;

export interface PdfReportOptions {
  /**
   * Base URL cloud del dashboard (solo si CORECHECK_DASHBOARD_URL / SaaS real).
   * Preferir `localDashboardPath` vía `buildAttestation` para reportes offline.
   */
  dashboardBaseUrl?: string;
}

function severityColor(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return '#991B1B';
    case 'HIGH':
      return '#C2410C';
    case 'MEDIUM':
      return '#1D4ED8';
    case 'LOW':
      return '#0E7490';
    default:
      return '#475569';
  }
}

function scoreColor(score: number): string {
  if (score >= 85) return C.pass;
  if (score >= 70) return '#CA8A04';
  return C.fail;
}

/**
 * Generador de PDF oficial de auditoría Enterprise (pdfkit).
 * Cover + Attestation QR · Executive Dashboard · Compliance · Detailed Findings.
 */
export class PdfReporter {
  private attestation!: AuditAttestation;
  private bundle!: AuditReportBundle;

  public async generate(
    bundle: AuditReportBundle,
    outputPath: string,
    options: PdfReportOptions = {}
  ): Promise<void> {
    await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });

    this.bundle = bundle;
    // Respeta attestation ya cableada por la CLI (file:// local); no regenerar a cloud fantasma.
    this.attestation =
      bundle.attestation?.dashboardUrl &&
      bundle.attestation.dashboardUrl !== 'about:blank' &&
      bundle.attestation.attestationHash
        ? bundle.attestation
        : buildAttestation(bundle, {
            licenseTier: bundle.attestation?.licenseTier,
            organization: bundle.attestation?.organization,
            accountId: bundle.attestation?.accountId,
            dashboardBaseUrl: options.dashboardBaseUrl
          });

    const qrContent =
      this.attestation.qrPayload ||
      this.attestation.dashboardUrl ||
      this.attestation.attestationHash;

    const qrPng = await QRCode.toBuffer(qrContent, {
      type: 'png',
      width: 220,
      margin: 1,
      errorCorrectionLevel: 'M',
      color: { dark: C.ink, light: C.white }
    });

    const doc = new PDFDocument({
      size: 'A4',
      autoFirstPage: true,
      bufferPages: true,
      margins: { top: 56, bottom: 56, left: 48, right: 48 },
      info: {
        Title: 'Digital Quality & Security Audit Report',
        Author: 'CoreCheck Enterprise',
        Subject: `${bundle.target} · ${this.attestation.attestationHash.slice(0, 16)}`,
        Keywords: 'CoreCheck, DAST, WCAG, Compliance, CVSS, Attestation',
        CreationDate: new Date(bundle.timestamp)
      }
    });

    const stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);

    this.drawCoverPage(doc, qrPng);
    doc.addPage();
    this.drawPageChrome(doc);
    this.drawExecutiveDashboard(doc);
    this.drawDimensionsSection(doc);
    doc.addPage();
    this.drawPageChrome(doc);
    this.drawComplianceMatrix(doc);
    doc.addPage();
    this.drawPageChrome(doc);
    this.drawDetailedFindings(doc);
    doc.addPage();
    this.drawPageChrome(doc);
    this.drawRemediationRoadmap(doc);
    this.drawAttestationClosing(doc);

    this.applyPageNumbers(doc);

    doc.end();
    await new Promise<void>((resolve, reject) => {
      stream.on('finish', () => resolve());
      stream.on('error', reject);
    });
  }

  // ——— Cover ———

  private drawCoverPage(doc: PDFDoc, qrPng: Buffer): void {
    const w = doc.page.width;
    const h = doc.page.height;

    // Full-bleed dark cover
    doc.rect(0, 0, w, h).fill(C.ink);
    doc.rect(0, 0, 8, h).fill(C.accent);

    doc
      .fillColor(C.accent)
      .fontSize(9)
      .font('Helvetica-Bold')
      .text('CORECHECK  ·  ENTERPRISE AUDIT', 48, 48, { characterSpacing: 1.2 });

    doc
      .fillColor(C.white)
      .fontSize(26)
      .font('Helvetica-Bold')
      .text('Digital Quality & Security\nAudit Report', 48, 88, {
        width: w - 96,
        lineGap: 4
      });

    doc
      .moveTo(48, 168)
      .lineTo(200, 168)
      .strokeColor(C.accent)
      .lineWidth(2)
      .stroke();

    const metaY = 190;
    doc.font('Helvetica').fontSize(9).fillColor('#94A3B8');
    doc.text('TARGET URL', 48, metaY);
    doc
      .font('Helvetica-Bold')
      .fontSize(11)
      .fillColor(C.white)
      .text(this.bundle.target, 48, metaY + 14, {
        width: w - 280,
        link: this.bundle.target,
        underline: true
      });

    doc.font('Helvetica').fontSize(9).fillColor('#94A3B8').text('GENERATED (UTC)', 48, metaY + 52);
    doc
      .font('Helvetica-Bold')
      .fontSize(11)
      .fillColor(C.white)
      .text(this.formatUtc(this.bundle.timestamp), 48, metaY + 66);

    doc.font('Helvetica').fontSize(9).fillColor('#94A3B8').text('ATTESTATION HASH (SHA-256)', 48, metaY + 100);
    doc
      .font('Courier')
      .fontSize(8)
      .fillColor('#E2E8F0')
      .text(this.attestation.attestationHash, 48, metaY + 114, { width: w - 280 });

    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor('#94A3B8')
      .text(
        `Algorithm: ${this.attestation.algorithm}` +
          (this.attestation.hmacSignature
            ? `  ·  HMAC: ${this.attestation.hmacSignature.slice(0, 16)}…`
            : '') +
          `  ·  CLI v${this.attestation.cliVersion}`,
        48,
        metaY + 132,
        { width: w - 280 }
      );

    doc.font('Helvetica').fontSize(9).fillColor('#94A3B8').text('LICENSE TIER', 48, metaY + 158);
    doc
      .font('Helvetica-Bold')
      .fontSize(11)
      .fillColor(C.white)
      .text(this.attestation.licenseTier ?? 'UNLICENSED / DEV', 48, metaY + 172);

    if (this.attestation.organization) {
      doc.font('Helvetica').fontSize(9).fillColor('#94A3B8').text('ORGANIZATION', 48, metaY + 206);
      doc
        .font('Helvetica-Bold')
        .fontSize(11)
        .fillColor(C.white)
        .text(this.attestation.organization, 48, metaY + 220);
    }

    // Gate badge
    const gatePass = !this.bundle.gateFailed;
    const gateColor = gatePass ? C.pass : C.fail;
    const gateLabel = gatePass ? '[GATE PASSED]' : '[GATE FAILED]';
    doc.roundedRect(48, h - 280, 220, 36, 4).fill(gateColor);
    doc
      .fillColor(C.white)
      .font('Helvetica-Bold')
      .fontSize(14)
      .text(gateLabel, 48, h - 270, { width: 220, align: 'center' });

    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor('#94A3B8')
      .text(
        `Fail-on threshold: ${this.bundle.failOn}  ·  Environment: ${this.bundle.environment ?? 'prod'}  ·  Pages scanned: ${this.bundle.scannedPages.length}`,
        48,
        h - 232,
        { width: w - 280 }
      );

    // Attestation & Web UI block with QR
    const boxX = w - 220;
    const boxY = h - 300;
    doc.roundedRect(boxX - 16, boxY - 16, 188, 250, 6).fill(C.slate);
    doc
      .fillColor(C.accent)
      .font('Helvetica-Bold')
      .fontSize(8)
      .text('ATTESTATION & LOCAL DASHBOARD', boxX - 4, boxY - 4, { width: 160 });

    doc.image(qrPng, boxX + 8, boxY + 16, { width: 120, height: 120 });

    const isLocalFile = this.attestation.dashboardUrl.startsWith('file:');
    doc
      .font('Helvetica')
      .fontSize(7)
      .fillColor('#CBD5E1')
      .text(
        isLocalFile
          ? 'QR firmado (hash + dashboard local). Escanee o abra interactive-dashboard.html'
          : 'QR de attestation firmado / estructurado',
        boxX - 4,
        boxY + 144,
        { width: 160 }
      );

    doc
      .font('Helvetica-Bold')
      .fontSize(6.5)
      .fillColor(C.accent)
      .text(
        isLocalFile ? 'interactive-dashboard.html' : this.attestation.verificationUrl,
        boxX - 4,
        boxY + 172,
        {
          width: 160,
          link: this.attestation.dashboardUrl,
          underline: true
        }
      );

    doc
      .font('Courier')
      .fontSize(6)
      .fillColor('#94A3B8')
      .text(`HASH ${this.attestation.attestationHash.slice(0, 16)}`, boxX - 4, boxY + 198, {
        width: 160
      });

    doc
      .font('Helvetica')
      .fontSize(7)
      .fillColor('#64748B')
      .text(
        'Confidential — For authorized recipients only. Automated continuous assessment; not a certified penetration test.',
        48,
        h - 48,
        { width: w - 96 }
      );
  }

  // ——— Chrome / header on content pages ———

  private drawPageChrome(doc: PDFDoc): void {
    const left = doc.page.margins.left;
    const right = doc.page.width - doc.page.margins.right;
    doc.rect(0, 0, doc.page.width, 40).fill(C.ink);
    doc.rect(0, 0, 6, 40).fill(C.accent);
    doc
      .fillColor(C.white)
      .font('Helvetica-Bold')
      .fontSize(9)
      .text('CoreCheck Enterprise', left, 14, { width: 200 });
    doc
      .fillColor('#94A3B8')
      .font('Helvetica')
      .fontSize(7)
      .text('Digital Quality & Security Audit', right - 180, 15, {
        width: 180,
        align: 'right'
      });
    doc.y = 56;
  }

  // ——— Executive Dashboard ———

  private drawExecutiveDashboard(doc: PDFDoc): void {
    this.sectionTitle(doc, '1. Executive Summary & Dashboard');
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(C.muted)
      .text(
        'Consolidated DAST security, WCAG accessibility, network hygiene, web performance, SEO/GEO and privacy — calibrated with CVSS and mapped to ISO 27001, SOC 2, PCI-DSS v4.0, EN 301 549 and WCAG/ADA.',
        { width: this.contentWidth(doc) }
      );
    doc.moveDown(0.6);

    const left = doc.page.margins.left;
    const cardY = doc.y;
    const cardH = 118;
    const scoreCardW = 150;
    const cvssCardW = 120;
    const sevCardW = this.contentWidth(doc) - scoreCardW - cvssCardW - 16;

    // Score gauge card
    doc.roundedRect(left, cardY, scoreCardW, cardH, 4).fillAndStroke(C.paper, C.line);
    this.drawScoreGauge(doc, left + scoreCardW / 2, cardY + 48, 34, this.bundle.digitalQualityScore);
    doc
      .font('Helvetica')
      .fontSize(7)
      .fillColor(C.muted)
      .text('Digital Quality Score', left + 8, cardY + 92, {
        width: scoreCardW - 16,
        align: 'center'
      });

    // Max CVSS card
    const cvssX = left + scoreCardW + 8;
    doc.roundedRect(cvssX, cardY, cvssCardW, cardH, 4).fillAndStroke(C.paper, C.line);
    doc
      .font('Helvetica')
      .fontSize(7)
      .fillColor(C.muted)
      .text('MAX CVSS', cvssX + 8, cardY + 14, { width: cvssCardW - 16, align: 'center' });
    const maxCvss = this.bundle.maxCvssScore;
    doc
      .font('Helvetica-Bold')
      .fontSize(28)
      .fillColor(maxCvss >= 7 ? C.fail : maxCvss >= 4 ? '#C2410C' : C.pass)
      .text(maxCvss > 0 ? maxCvss.toFixed(1) : '—', cvssX + 8, cardY + 40, {
        width: cvssCardW - 16,
        align: 'center'
      });
    doc
      .font('Helvetica')
      .fontSize(7)
      .fillColor(C.muted)
      .text('Base score (0–10)', cvssX + 8, cardY + 82, {
        width: cvssCardW - 16,
        align: 'center'
      });

    // Severity breakdown card
    const sevX = cvssX + cvssCardW + 8;
    doc.roundedRect(sevX, cardY, sevCardW, cardH, 4).fillAndStroke(C.paper, C.line);
    doc
      .font('Helvetica-Bold')
      .fontSize(8)
      .fillColor(C.ink)
      .text('Vulnerability Severity', sevX + 10, cardY + 10);

    let rowY = cardY + 28;
    for (const sev of SEVERITY_ORDER) {
      const count = this.bundle.severityCounts[sev] ?? 0;
      doc.roundedRect(sevX + 10, rowY, 8, 8, 1).fill(severityColor(sev));
      doc
        .font('Helvetica')
        .fontSize(8)
        .fillColor(C.slate)
        .text(sev, sevX + 24, rowY - 1, { width: 70 });
      doc
        .font('Helvetica-Bold')
        .fontSize(8)
        .fillColor(C.ink)
        .text(String(count), sevX + sevCardW - 36, rowY - 1, { width: 24, align: 'right' });
      rowY += 15;
    }

    doc.y = cardY + cardH + 14;
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(C.muted)
      .text(
        `Total findings: ${this.bundle.findings.length}  ·  Compliance-mapped: ${this.bundle.compliance.mappedFindingCount}` +
          (this.bundle.suppressedCount
            ? `  ·  Baseline suppressions: ${this.bundle.suppressedCount}`
            : '')
      );
    doc.moveDown(0.8);
  }

  private drawScoreGauge(doc: PDFDoc, cx: number, cy: number, r: number, score: number): void {
    const clamped = Math.max(0, Math.min(100, score));
    const start = -Math.PI * 0.75;
    const full = Math.PI * 1.5;
    const end = start + full * (clamped / 100);
    const color = scoreColor(clamped);

    this.drawArc(doc, cx, cy, r, start, start + full, C.line, 7);
    this.drawArc(doc, cx, cy, r, start, end, color, 7);

    doc
      .font('Helvetica-Bold')
      .fontSize(18)
      .fillColor(color)
      .text(clamped.toFixed(1), cx - 28, cy - 10, { width: 56, align: 'center' });
  }

  private drawArc(
    doc: PDFDoc,
    cx: number,
    cy: number,
    r: number,
    a0: number,
    a1: number,
    color: string,
    lineWidth: number
  ): void {
    if (a1 <= a0) return;
    const steps = Math.max(8, Math.ceil(((a1 - a0) / (Math.PI * 2)) * 64));
    doc.save();
    doc.strokeColor(color).lineWidth(lineWidth).lineCap('round');
    for (let i = 0; i < steps; i++) {
      const t0 = a0 + ((a1 - a0) * i) / steps;
      const t1 = a0 + ((a1 - a0) * (i + 1)) / steps;
      const x0 = cx + r * Math.cos(t0);
      const y0 = cy + r * Math.sin(t0);
      const x1 = cx + r * Math.cos(t1);
      const y1 = cy + r * Math.sin(t1);
      doc.moveTo(x0, y0).lineTo(x1, y1).stroke();
    }
    doc.restore();
  }

  private drawDimensionsSection(doc: PDFDoc): void {
    this.ensureSpace(doc, 160);
    this.sectionTitle(doc, '2. Six-Dimension Breakdown');
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(C.muted)
      .text(
        'Security · Accessibility · Performance · SEO/GEO · Privacy · Network. Score 100 = clean dimension.'
      );
    doc.moveDown(0.5);

    const barMax = 200;
    for (const dim of this.bundle.dimensions) {
      this.ensureSpace(doc, 22);
      this.drawDimensionRow(doc, dim, barMax);
    }
    doc.moveDown(0.4);
  }

  private drawDimensionRow(doc: PDFDoc, dim: DimensionBreakdown, barMax: number): void {
    const label = DIM_LABELS[dim.dimension] ?? dim.dimension;
    const y = doc.y;
    const left = doc.page.margins.left;

    doc.font('Helvetica-Bold').fontSize(8).fillColor(C.ink).text(label, left, y, { width: 110 });
    doc
      .font('Helvetica')
      .fontSize(7)
      .fillColor(C.muted)
      .text(`${dim.count} finding(s)`, left + 112, y + 1, { width: 70 });

    const barX = left + 190;
    doc.roundedRect(barX, y + 2, barMax, 8, 2).fill(C.codeBg);
    const filled = Math.max(dim.score > 0 ? 3 : 0, (dim.score / 100) * barMax);
    if (filled > 0) {
      doc.roundedRect(barX, y + 2, filled, 8, 2).fill(scoreColor(dim.score));
    }
    doc
      .font('Helvetica-Bold')
      .fontSize(8)
      .fillColor(scoreColor(dim.score))
      .text(String(dim.score), barX + barMax + 8, y, { width: 36 });

    doc.y = y + 18;
  }

  // ——— Compliance ———

  private drawComplianceMatrix(doc: PDFDoc): void {
    this.sectionTitle(doc, '3. Compliance & Regulatory Gaps');
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(C.muted)
      .text(
        'Coverage vs gaps for ISO/IEC 27001, SOC 2, PCI-DSS v4.0, WCAG 2.2 AA / ADA and EN 301 549.'
      );
    doc.moveDown(0.5);

    // Table header
    const left = doc.page.margins.left;
    const col = [130, 70, 60, 70, this.contentWidth(doc) - 330];
    const headers = ['Framework', 'Related', 'Gaps', 'Covered', 'Affected Controls (sample)'];
    let x = left;
    const headerY = doc.y;
    doc.rect(left, headerY, this.contentWidth(doc), 18).fill(C.slate);
    doc.font('Helvetica-Bold').fontSize(7).fillColor(C.white);
    headers.forEach((h, i) => {
      doc.text(h, x + 4, headerY + 5, { width: col[i] - 8 });
      x += col[i];
    });
    doc.y = headerY + 20;

    for (const fw of this.bundle.compliance.frameworks) {
      this.ensureSpace(doc, 36);
      const y = doc.y;
      const gaps = fw.controls.filter((c) => c.status === 'GAP' || c.status === 'PARTIAL');
      const covered = fw.controls.filter((c) => c.status === 'COVERED').length;
      const gapSample = gaps
        .slice(0, 4)
        .map((c) => c.controlId)
        .join(', ');

      doc.rect(left, y, this.contentWidth(doc), 22).fill(C.paper);
      x = left;
      const cells = [
        fw.framework,
        String(fw.relatedFindings),
        String(fw.gapCount),
        String(covered),
        gapSample || '—'
      ];
      cells.forEach((cell, i) => {
        doc
          .font(i === 0 ? 'Helvetica-Bold' : 'Helvetica')
          .fontSize(7)
          .fillColor(i === 2 && fw.gapCount > 0 ? C.fail : C.ink)
          .text(cell, x + 4, y + 6, { width: col[i] - 8, ellipsis: true });
        x += col[i];
      });
      doc.y = y + 24;
    }

    doc.moveDown(0.6);
    this.ensureSpace(doc, 80);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.ink).text('Controls Affected vs Covered');
    doc.moveDown(0.3);

    for (const fw of this.bundle.compliance.frameworks) {
      const gaps = fw.controls.filter((c) => c.status === 'GAP').slice(0, 5);
      const covered = fw.controls.filter((c) => c.status === 'COVERED').slice(0, 3);
      this.ensureSpace(doc, 40);
      doc.font('Helvetica-Bold').fontSize(8).fillColor(C.slate).text(fw.framework);
      if (gaps.length === 0) {
        doc.font('Helvetica').fontSize(7).fillColor(C.pass).text('  No HIGH/CRITICAL gaps for mapped controls.');
      } else {
        for (const c of gaps) {
          doc
            .font('Helvetica')
            .fontSize(7)
            .fillColor(C.fail)
            .text(`  [GAP] ${c.controlId} — ${this.truncate(c.controlTitle, 90)}`);
        }
      }
      for (const c of covered) {
        doc
          .font('Helvetica')
          .fontSize(7)
          .fillColor(C.pass)
          .text(`  [COVERED] ${c.controlId} — ${this.truncate(c.controlTitle, 90)}`);
      }
      doc.moveDown(0.25);
    }
  }

  // ——— Detailed Findings ———

  private drawDetailedFindings(doc: PDFDoc): void {
    this.sectionTitle(doc, '4. Detailed Findings Catalogue');
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(C.muted)
      .text(
        'Structured technical catalogue for engineering and auditors. CRITICAL/HIGH first, then MEDIUM (capped).'
      );
    doc.moveDown(0.5);

    const priority = [...this.bundle.findings].sort((a, b) => {
      const sev = this.sevRank(b.severity) - this.sevRank(a.severity);
      if (sev !== 0) return sev;
      return (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0);
    });

    const criticalHigh = priority.filter(
      (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
    );
    const medium = priority.filter((f) => f.severity === 'MEDIUM').slice(0, 15);
    const catalogue = [...criticalHigh, ...medium];

    if (catalogue.length === 0) {
      doc.font('Helvetica').fontSize(9).fillColor(C.pass).text('No material findings in this run.');
      return;
    }

    let index = 1;
    for (const finding of catalogue) {
      this.drawFindingBlock(doc, finding, index++);
    }
  }

  private drawFindingBlock(doc: PDFDoc, finding: AuditFinding, index: number): void {
    // Reserve space for a coherent block (avoid orphan headers mid-page)
    this.ensureSpace(doc, 130);

    const left = doc.page.margins.left;
    const width = this.contentWidth(doc);
    const startY = doc.y;

    doc.roundedRect(left, startY, width, 18, 2).fill(severityColor(finding.severity));
    doc
      .font('Helvetica-Bold')
      .fontSize(8)
      .fillColor(C.white)
      .text(
        `${index}. [${finding.severity}]  ${finding.ruleId}` +
          (finding.cvss ? `  ·  CVSS ${finding.cvss.baseScore.toFixed(1)}` : ''),
        left + 8,
        startY + 5,
        { width: width - 16 }
      );
    doc.y = startY + 24;

    doc.font('Helvetica-Bold').fontSize(10).fillColor(C.ink).text(finding.title, { width });
    doc.moveDown(0.2);
    doc.font('Helvetica').fontSize(8).fillColor(C.slate).text(finding.description, { width });
    doc.moveDown(0.3);

    if (finding.cvss) {
      doc
        .font('Courier')
        .fontSize(7)
        .fillColor(C.ink)
        .text(`CVSS ${finding.cvss.version} Vector: ${finding.cvss.vector}`, { width });
      doc.moveDown(0.2);
    }

    const stdParts = [
      ...(finding.standards.owasp?.map((s) => `OWASP:${s}`) ?? []),
      ...(finding.standards.cwe?.map((s) => `CWE:${s}`) ?? []),
      ...(finding.standards.iso27001?.map((s) => `ISO:${s}`) ?? []),
      ...(finding.standards.soc2?.map((s) => `SOC2:${s}`) ?? []),
      ...(finding.standards.pciDss?.map((s) => `PCI:${s}`) ?? []),
      ...(finding.standards.wcag?.slice(0, 2).map((s) => `WCAG:${s}`) ?? []),
      ...(finding.standards.en301549?.map((s) => `EN:${s}`) ?? []),
      ...(finding.standards.ada?.map((s) => `ADA:${s}`) ?? [])
    ].slice(0, 10);

    if (stdParts.length > 0) {
      doc
        .font('Helvetica')
        .fontSize(7)
        .fillColor('#1D4ED8')
        .text(`Standards: ${stdParts.join('  ·  ')}`, { width });
      doc.moveDown(0.25);
    }

    if (finding.evidence.url) {
      doc
        .font('Helvetica')
        .fontSize(7)
        .fillColor(C.accent)
        .text(`Evidence URL: ${finding.evidence.url}`, {
          width,
          link: finding.evidence.url,
          underline: true
        });
      doc.moveDown(0.15);
    }

    const affectedUrls = [
      ...new Set(
        [
          ...(finding.evidence.locations?.map((l) => l.url).filter(Boolean) as string[]),
          ...(finding.evidence.url ? [finding.evidence.url] : [])
        ].filter(Boolean)
      )
    ];
    if (affectedUrls.length > 1) {
      this.ensureSpace(doc, 28 + Math.min(affectedUrls.length, 10) * 9);
      doc
        .font('Helvetica-Bold')
        .fontSize(7)
        .fillColor(C.ink)
        .text(`Affected pages (${affectedUrls.length}) — site-level consolidated:`, {
          width
        });
      for (const u of affectedUrls.slice(0, 12)) {
        let label = u;
        try {
          const parsed = new URL(u);
          label = parsed.pathname + parsed.search || '/';
        } catch {
          /* keep */
        }
        doc
          .font('Helvetica')
          .fontSize(6.5)
          .fillColor(C.accent)
          .text(`  • ${label}`, { width, link: u, underline: true });
      }
      if (affectedUrls.length > 12) {
        doc
          .font('Helvetica')
          .fontSize(6.5)
          .fillColor(C.muted)
          .text(`  … +${affectedUrls.length - 12} more`);
      }
      doc.moveDown(0.2);
    }

    if (finding.evidence.selector) {
      doc
        .font('Helvetica')
        .fontSize(7)
        .fillColor(C.muted)
        .text(`Selector: ${finding.evidence.selector}`, { width });
      doc.moveDown(0.15);
    }

    if (finding.evidence.snippet) {
      const snippet =
        affectedUrls.length > 1 && finding.evidence.snippet.startsWith('Affected pages')
          ? finding.evidence.snippet.split('\n\nEvidence sample:\n').slice(1).join('\n') ||
            finding.evidence.snippet
          : finding.evidence.snippet;
      if (snippet.trim()) {
        this.ensureSpace(doc, 48);
        this.drawCodeBox(doc, 'Evidence Snippet', snippet, 6);
      }
    }

    doc.moveDown(0.25);
    doc.font('Helvetica-Bold').fontSize(8).fillColor(C.ink).text('Remediation Guidance');
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(C.slate)
      .text(finding.remediation.explanation, { width });
    doc.moveDown(0.2);

    if (finding.remediation.codeBefore) {
      this.ensureSpace(doc, 40);
      this.drawCodeBox(doc, 'Código Antes', finding.remediation.codeBefore, 4);
    }
    if (finding.remediation.codeAfter) {
      this.ensureSpace(doc, 40);
      this.drawCodeBox(doc, 'Código Después', finding.remediation.codeAfter, 4);
    }

    doc.moveDown(0.55);
    doc
      .moveTo(left, doc.y)
      .lineTo(left + width, doc.y)
      .strokeColor(C.line)
      .lineWidth(0.5)
      .stroke();
    doc.moveDown(0.45);
  }

  private drawCodeBox(doc: PDFDoc, label: string, code: string, maxLines: number): void {
    const left = doc.page.margins.left;
    const width = this.contentWidth(doc);
    const lines = this.truncate(code.replace(/\r\n/g, '\n'), 520)
      .split('\n')
      .slice(0, maxLines);
    const body = lines.join('\n');
    const boxH = 14 + lines.length * 9 + 8;

    this.ensureSpace(doc, boxH + 4);
    const y = doc.y;
    doc.roundedRect(left, y, width, boxH, 3).fill(C.codeBg);
    doc.font('Helvetica-Bold').fontSize(6.5).fillColor(C.muted).text(label, left + 6, y + 4);
    doc
      .font('Courier')
      .fontSize(7)
      .fillColor(C.codeFg)
      .text(body, left + 6, y + 14, { width: width - 12, lineGap: 1 });
    doc.y = y + boxH + 4;
  }

  // ——— Roadmap + closing ———

  private drawRemediationRoadmap(doc: PDFDoc): void {
    this.sectionTitle(doc, '5. Remediation Roadmap');
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(C.muted)
      .text('Prioritized backlog for engineering — Immediate / Near-term / Backlog.');
    doc.moveDown(0.4);

    const immediate = this.bundle.findings.filter(
      (f) => f.severity === 'CRITICAL' || (f.cvss?.baseScore ?? 0) >= 9
    );
    const nearTerm = this.bundle.findings.filter(
      (f) => f.severity === 'HIGH' && !immediate.includes(f)
    );
    const backlog = this.bundle.findings.filter(
      (f) => f.severity === 'MEDIUM' || f.severity === 'LOW'
    );

    this.drawRoadmapBucket(doc, 'Immediate (P0)', immediate.slice(0, 10), C.fail);
    this.drawRoadmapBucket(doc, 'Near-term (P1)', nearTerm.slice(0, 10), '#C2410C');
    this.drawRoadmapBucket(doc, 'Backlog (P2)', backlog.slice(0, 10), '#1D4ED8');
  }

  private drawRoadmapBucket(
    doc: PDFDoc,
    title: string,
    items: AuditFinding[],
    color: string
  ): void {
    this.ensureSpace(doc, 36);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(color).text(title);
    if (items.length === 0) {
      doc.font('Helvetica').fontSize(7).fillColor(C.muted).text('  — none —');
      doc.moveDown(0.3);
      return;
    }
    for (const f of items) {
      this.ensureSpace(doc, 14);
      doc
        .font('Helvetica')
        .fontSize(7)
        .fillColor(C.slate)
        .text(`  • ${f.ruleId}: ${this.truncate(f.remediation.explanation, 130)}`);
    }
    doc.moveDown(0.35);
  }

  private drawAttestationClosing(doc: PDFDoc): void {
    this.ensureSpace(doc, 90);
    doc.moveDown(0.5);
    const left = doc.page.margins.left;
    const width = this.contentWidth(doc);
    const y = doc.y;
    doc.roundedRect(left, y, width, 72, 4).fill(C.ink);
    doc
      .font('Helvetica-Bold')
      .fontSize(9)
      .fillColor(C.accent)
      .text('Official Attestation', left + 12, y + 10);
    doc
      .font('Helvetica')
      .fontSize(7)
      .fillColor('#CBD5E1')
      .text(
        `This document is bound to Attestation Hash ${this.attestation.attestationHash.slice(0, 32)}… ` +
          `Verify integrity and open the interactive dashboard at:`,
        left + 12,
        y + 26,
        { width: width - 24 }
      );
    doc
      .font('Helvetica-Bold')
      .fontSize(8)
      .fillColor(C.accent)
      .text(this.attestation.dashboardUrl, left + 12, y + 48, {
        width: width - 24,
        link: this.attestation.dashboardUrl,
        underline: true
      });
    doc.y = y + 80;
  }

  // ——— Page numbers ———

  private applyPageNumbers(doc: PDFDoc): void {
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      const pageNo = i - range.start + 1;
      const total = range.count;
      const bottom = doc.page.height - 32;

      // Skip heavy chrome on cover (page 1) but still number it
      doc
        .font('Helvetica')
        .fontSize(7)
        .fillColor(pageNo === 1 ? '#64748B' : C.muted)
        .text(
          `Página ${pageNo} de ${total}  ·  CoreCheck Enterprise  ·  Confidential  ·  ${this.attestation.attestationHash.slice(0, 12)}`,
          doc.page.margins.left,
          bottom,
          {
            width: doc.page.width - doc.page.margins.left - doc.page.margins.right,
            align: 'center'
          }
        );
    }
  }

  // ——— Helpers ———

  private sectionTitle(doc: PDFDoc, title: string): void {
    doc.font('Helvetica-Bold').fontSize(13).fillColor(C.ink).text(title);
    doc
      .moveTo(doc.page.margins.left, doc.y + 2)
      .lineTo(doc.page.margins.left + 120, doc.y + 2)
      .strokeColor(C.accent)
      .lineWidth(1.5)
      .stroke();
    doc.moveDown(0.45);
  }

  private contentWidth(doc: PDFDoc): number {
    return doc.page.width - doc.page.margins.left - doc.page.margins.right;
  }

  private ensureSpace(doc: PDFDoc, needed: number): void {
    const bottom = doc.page.height - doc.page.margins.bottom - 8;
    if (doc.y + needed > bottom) {
      doc.addPage();
      this.drawPageChrome(doc);
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

  private formatUtc(iso: string): string {
    try {
      const d = new Date(iso);
      return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
    } catch {
      return iso;
    }
  }
}

export async function generatePdfReport(
  bundle: AuditReportBundle,
  outputPath: string,
  options: PdfReportOptions = {}
): Promise<void> {
  const reporter = new PdfReporter();
  await reporter.generate(bundle, outputPath, options);
}
