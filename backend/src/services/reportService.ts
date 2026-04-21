import PDFDocument from 'pdfkit';
import { AppDataSource } from '../db/connection';
import { Report } from '../db/models/Report';
import type {
  AssessmentModuleResult,
  DeepScanResult,
  ScanFinding,
} from '../engine/scanTypes';
import type { ScanFindingSeverity } from '../../../shared/scanContract';
import { sanitizeForPdf, sanitizePairs } from './util/pdfSanitize';

/** Convenience wrapper so we always pass through `sanitizeForPdf`
 *  before handing a string to PDFKit. Helvetica AFM only knows
 *  WinAnsi; raw UTF-8 from server banners / scan output throws. */
const sx = (v: unknown, fallback = ''): string => sanitizeForPdf(v, fallback);

/**
 * Persist a completed assessment as a {@link Report} row so it can be re-rendered
 * to HTML / PDF without re-executing the scan modules.
 *
 * Returns the persisted report (including its assigned id), so callers can
 * surface a download link in the same response.
 */
export async function persistAssessmentReport(input: {
  reportType?: 'assessment' | 'discovery';
  result: DeepScanResult;
  notes?: string | null;
}): Promise<Report> {
  const repo = AppDataSource.getRepository(Report);
  const reportType = input.reportType ?? 'assessment';
  const target = input.result.executionMeta?.target ?? 'unknown';

  const counts = countFindingsBySeverity(input.result.findings ?? []);
  const summary = input.result.scanSummary;

  const report = repo.create({
    reportType,
    targetHostname: target,
    title: buildReportTitle(reportType, target),
    durationMs: input.result.executionMeta?.scanDurationMs ?? 0,
    totalFindings: input.result.findings?.length ?? 0,
    criticalCount: counts.Critical,
    highCount: counts.High,
    mediumCount: counts.Medium,
    lowCount: counts.Low,
    infoCount: counts.Info,
    modulesRun: summary?.totalModules ?? 0,
    modulesSucceeded: summary?.completedModules ?? 0,
    modulesFailed: summary?.failedModules ?? 0,
    resultJson: input.result,
    notes: input.notes ?? null,
  });

  return repo.save(report);
}

function buildReportTitle(reportType: string, target: string): string {
  if (reportType === 'discovery') {
    return `UASF Discovery Report — ${target}`;
  }
  return `UASF Application Assessment — ${target}`;
}

function countFindingsBySeverity(findings: ScanFinding[]): Record<ScanFindingSeverity, number> {
  const counts: Record<ScanFindingSeverity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) {
      counts[finding.severity] += 1;
    }
  }
  return counts;
}

/**
 * Render the persisted report to a self-contained HTML document (single file,
 * no external assets). Suitable for download or inline preview.
 */
export function renderReportHtml(report: Report): string {
  const result = report.resultJson;
  const recon = result.reconData;
  const findings = result.findings ?? [];
  const moduleResults = result.moduleResults ?? [];
  const meta = result.executionMeta;
  const summary = result.scanSummary;

  const generatedAt = new Date(report.createdAt).toUTCString();
  const finishedAt = new Date(meta.scanEndedAt).toUTCString();

  const findingsRows = findings
    .map((finding, index) => renderFindingRow(finding, index))
    .join('');

  const modulesRows = moduleResults
    .map((moduleResult) => renderModuleRow(moduleResult))
    .join('');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(report.title)}</title>
    <style>${REPORT_CSS}</style>
  </head>
  <body>
    <header class="report-header">
      <div class="brand">
        <div class="brand-mark">UASF</div>
        <div class="brand-text">
          <div class="brand-title">Universal Attack Simulation Framework</div>
          <div class="brand-sub">Vendor-agnostic security validation report</div>
        </div>
      </div>
      <div class="header-meta">
        <div><strong>Report ID:</strong> ${escapeHtml(report.id)}</div>
        <div><strong>Generated:</strong> ${escapeHtml(generatedAt)}</div>
      </div>
    </header>

    <section class="summary-card">
      <h1>${escapeHtml(report.title)}</h1>
      <div class="kv-grid">
        <div><span>Target</span><b>${escapeHtml(report.targetHostname)}</b></div>
        <div><span>Report type</span><b>${escapeHtml(report.reportType)}</b></div>
        <div><span>Scan finished</span><b>${escapeHtml(finishedAt)}</b></div>
        <div><span>Duration</span><b>${report.durationMs} ms</b></div>
        <div><span>Modules run</span><b>${report.modulesRun} (${report.modulesSucceeded} ok / ${report.modulesFailed} failed)</b></div>
        <div><span>Average confidence</span><b>${summary?.averageConfidence ?? 0}%</b></div>
      </div>

      <div class="severity-grid">
        ${renderSeverityChip('Critical', report.criticalCount)}
        ${renderSeverityChip('High', report.highCount)}
        ${renderSeverityChip('Medium', report.mediumCount)}
        ${renderSeverityChip('Low', report.lowCount)}
        ${renderSeverityChip('Info', report.infoCount)}
      </div>
    </section>

    <section class="recon">
      <h2>Reconnaissance</h2>
      <div class="recon-grid">
        <div class="recon-cell"><span>Origin IPv4</span><b>${escapeHtml(recon.ip)}</b></div>
        <div class="recon-cell"><span>TLS Issuer</span><b>${escapeHtml(recon.tlsIssuer)}</b></div>
        <div class="recon-cell"><span>TLS Valid To</span><b>${escapeHtml(recon.tlsValidTo)}</b></div>
      </div>
      ${
        recon.dnsDetails.length
          ? `<h3>Routing &amp; DNS evidence</h3><ul class="dns-list">${recon.dnsDetails
              .map((line) => `<li>${escapeHtml(line)}</li>`)
              .join('')}</ul>`
          : '<p class="muted">No routing details captured.</p>'
      }
    </section>

    <section class="findings">
      <h2>Findings (${findings.length})</h2>
      ${findings.length === 0 ? '<p class="muted">No findings were produced for this assessment.</p>' : `<div class="findings-list">${findingsRows}</div>`}
    </section>

    <section class="modules">
      <h2>Module trace (${moduleResults.length})</h2>
      ${moduleResults.length === 0 ? '<p class="muted">No module traces recorded.</p>' : `<div class="modules-list">${modulesRows}</div>`}
    </section>

    <footer class="report-footer">
      <p>
        Generated by UASF — Universal Attack Simulation Framework. Evidence-derived findings only;
        no fabricated results. For approved assets only.
      </p>
    </footer>
  </body>
</html>`;
}

function renderSeverityChip(label: ScanFindingSeverity, count: number): string {
  const cls = `sev-${label.toLowerCase()}`;
  return `<div class="sev-chip ${cls}"><div class="sev-count">${count}</div><div class="sev-label">${label}</div></div>`;
}

function renderFindingRow(finding: ScanFinding, index: number): string {
  const sevClass = `sev-${(finding.severity ?? 'Info').toLowerCase()}`;
  return `
    <article class="finding ${sevClass}">
      <header>
        <span class="finding-index">#${index + 1}</span>
        <span class="finding-sev ${sevClass}">${escapeHtml(finding.severity ?? 'Info')}</span>
        <span class="finding-cat">${escapeHtml(finding.category ?? 'Info')}</span>
        ${typeof finding.confidence === 'number' ? `<span class="finding-conf">CF ${finding.confidence}%</span>` : ''}
        <h3>${escapeHtml(finding.title ?? 'Untitled finding')}</h3>
      </header>
      <p class="finding-desc">${escapeHtml(finding.description ?? '')}</p>
      ${finding.cwe ? `<p class="finding-cwe"><strong>Threat ref:</strong> ${escapeHtml(finding.cwe)}</p>` : ''}
      ${finding.evidence ? `<pre class="finding-evidence">${escapeHtml(finding.evidence)}</pre>` : ''}
      ${finding.remediation ? `<p class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>` : ''}
    </article>
  `;
}

function renderModuleRow(moduleResult: AssessmentModuleResult): string {
  const duration = Math.max(0, (moduleResult.endedAt ?? 0) - (moduleResult.startedAt ?? 0));
  const errors = (moduleResult.errors ?? []).map((error) => `<li>${escapeHtml(error)}</li>`).join('');
  return `
    <article class="module status-${escapeHtml(moduleResult.status)}">
      <header>
        <span class="module-name">${escapeHtml(moduleResult.moduleName)}</span>
        <span class="module-tool">${escapeHtml(moduleResult.sourceTool)}</span>
        <span class="module-status">${escapeHtml(moduleResult.status)}</span>
        <span class="module-conf">CF ${moduleResult.confidence}%</span>
        <span class="module-dur">${duration} ms</span>
      </header>
      <p class="module-evidence">${escapeHtml(moduleResult.normalizedEvidence ?? '')}</p>
      ${errors ? `<ul class="module-errors">${errors}</ul>` : ''}
    </article>
  `;
}

const REPORT_CSS = `
  :root { color-scheme: light; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f4f6; color: #111827; }
  .report-header { background: linear-gradient(135deg, #4d1c8c, #8e51df); color: white; padding: 24px 40px; display: flex; justify-content: space-between; align-items: center; }
  .brand { display: flex; gap: 16px; align-items: center; }
  .brand-mark { width: 48px; height: 48px; border-radius: 8px; background: rgba(255,255,255,0.18); display: flex; align-items: center; justify-content: center; font-weight: 800; letter-spacing: 0.1em; }
  .brand-title { font-weight: 700; font-size: 16px; }
  .brand-sub { font-size: 12px; opacity: 0.85; letter-spacing: 0.05em; }
  .header-meta { font-size: 11px; text-align: right; opacity: 0.9; }
  .header-meta div { margin: 2px 0; }
  section { margin: 24px 40px; padding: 24px; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 12px; }
  section h1 { margin-top: 0; font-size: 24px; }
  section h2 { margin-top: 0; font-size: 18px; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }
  .kv-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px 24px; margin-top: 16px; }
  .kv-grid > div { display: flex; flex-direction: column; font-size: 13px; }
  .kv-grid span { color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  .kv-grid b { font-weight: 600; color: #111827; word-break: break-word; }
  .severity-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-top: 24px; }
  .sev-chip { padding: 14px; border-radius: 10px; text-align: center; border: 1px solid; }
  .sev-chip .sev-count { font-size: 28px; font-weight: 800; }
  .sev-chip .sev-label { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; margin-top: 4px; }
  .sev-critical { background: #fef2f2; color: #b91c1c; border-color: #fecaca; }
  .sev-high { background: #fff7ed; color: #c2410c; border-color: #fed7aa; }
  .sev-medium { background: #fefce8; color: #a16207; border-color: #fde68a; }
  .sev-low { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; }
  .sev-info { background: #f3f4f6; color: #374151; border-color: #e5e7eb; }
  .recon-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }
  .recon-cell { padding: 12px; border-radius: 8px; background: #f9fafb; border: 1px solid #e5e7eb; }
  .recon-cell span { display: block; font-size: 11px; color: #6b7280; letter-spacing: 0.06em; text-transform: uppercase; }
  .recon-cell b { font-size: 14px; font-weight: 600; }
  .dns-list { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.6; }
  .findings-list, .modules-list { display: grid; gap: 12px; }
  .finding { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; }
  .finding header { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; margin-bottom: 8px; }
  .finding header h3 { width: 100%; margin: 8px 0 0 0; font-size: 16px; }
  .finding-index { font-family: ui-monospace, monospace; color: #6b7280; }
  .finding-sev { padding: 2px 10px; border-radius: 999px; font-weight: 700; font-size: 11px; letter-spacing: 0.05em; }
  .finding-cat { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #6b7280; }
  .finding-conf { font-size: 11px; color: #047857; background: #ecfdf5; padding: 2px 8px; border-radius: 999px; border: 1px solid #a7f3d0; }
  .finding-desc { color: #374151; font-size: 14px; line-height: 1.5; }
  .finding-cwe { font-size: 12px; color: #b91c1c; }
  .finding-evidence { background: #0f172a; color: #93c5fd; padding: 12px; border-radius: 8px; font-family: ui-monospace, monospace; font-size: 12px; line-height: 1.4; white-space: pre-wrap; word-break: break-word; }
  .finding-remediation { background: #ecfdf5; color: #065f46; padding: 8px 12px; border-radius: 8px; font-size: 12px; }
  .module { border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px 16px; }
  .module header { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; font-size: 12px; }
  .module-name { font-weight: 700; font-size: 14px; }
  .module-tool { color: #4b5563; }
  .module-status { padding: 2px 8px; border-radius: 999px; font-weight: 700; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; }
  .status-success .module-status { background: #ecfdf5; color: #047857; }
  .status-partial .module-status { background: #fefce8; color: #a16207; }
  .status-failed .module-status { background: #fef2f2; color: #b91c1c; }
  .module-conf { color: #047857; }
  .module-dur { color: #6b7280; }
  .module-evidence { font-family: ui-monospace, monospace; font-size: 12px; color: #374151; }
  .module-errors { font-family: ui-monospace, monospace; font-size: 11px; color: #b91c1c; }
  .report-footer { margin: 24px 40px 40px; font-size: 11px; color: #6b7280; text-align: center; }
  .muted { color: #6b7280; font-style: italic; }
  @media print { body { background: white; } section { box-shadow: none; border-color: #d1d5db; } .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
`;

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Render the persisted report to a PDF buffer using PDFKit (no headless
 * browser, no external services). The layout is designed to feel
 * presentation-ready: branded cover header, severity ribbon, two-column
 * key/value blocks, banded tables, page breaks that respect content
 * heights, and a footer with page numbers and report metadata.
 */
export function renderReportPdf(report: Report): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        // Tighter margins: the previous 90/70 left ~530pt of usable
        // height per page, which inflated long assessments to 24+
        // pages. 58/48 keeps a clear safe-zone below the header band
        // (50pt tall) and above the footer band (~28pt) while giving
        // ~80pt extra usable height per page.
        margins: { top: 58, bottom: 48, left: 44, right: 44 },
        bufferPages: true,
        info: {
          Title: sx(report.title, 'UASF Report'),
          Subject: 'UASF Universal Attack Simulation Framework Report',
          Author: 'UASF',
          Producer: 'UASF Report Engine',
        },
      });

      const chunks: Buffer[] = [];
      doc.on('data', (chunk: Buffer) => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      writePdfReport(doc, report);

      // Apply repeating header / footer (with page numbers) to every
      // page after content has been laid out, so totals are accurate.
      const range = doc.bufferedPageRange();
      for (let pageIndex = 0; pageIndex < range.count; pageIndex += 1) {
        doc.switchToPage(range.start + pageIndex);
        drawHeaderBand(doc, report);
        drawFooterBand(doc, report, pageIndex + 1, range.count);
      }

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}

const COLORS = {
  primary: '#4d1c8c',
  accent: '#8e51df',
  ink: '#111827',
  muted: '#6b7280',
  rule: '#e5e7eb',
  bandBg: '#f5f3ff',
  zebra: '#f9fafb',
  critical: '#b91c1c',
  high: '#c2410c',
  medium: '#a16207',
  low: '#1d4ed8',
  info: '#374151',
  ok: '#047857',
} as const;

function writePdfReport(doc: PDFKit.PDFDocument, report: Report): void {
  const result = report.resultJson;
  const recon = result.reconData;
  const findings = result.findings ?? [];
  const moduleResults = result.moduleResults ?? [];
  const summary = result.scanSummary;

  doc.font('Helvetica');

  // Title block — tighter type scale & spacing.
  doc
    .fillColor(COLORS.ink)
    .font('Helvetica-Bold')
    .fontSize(16)
    .text(sx(report.title, 'UASF Report'), { align: 'left' });
  doc
    .moveDown(0.1)
    .font('Helvetica')
    .fontSize(8.5)
    .fillColor(COLORS.muted)
    .text(
      sx(
        `Report ID ${report.id}  ·  ${report.reportType.toUpperCase()}  ·  Generated ${new Date(
          report.createdAt,
        ).toUTCString()}`,
      ),
    );
  doc.moveDown(0.4);

  // Severity ribbon — one color band, equal columns.
  drawSeverityRibbon(doc, report);
  doc.moveDown(0.35);

  // Executive summary key/value grid
  sectionTitle(doc, 'Executive summary');
  drawKeyValueGrid(doc, sanitizePairs([
    ['Target', report.targetHostname],
    ['Report type', report.reportType],
    ['Duration', `${report.durationMs} ms`],
    ['Modules run', `${report.modulesRun} (${report.modulesSucceeded} ok / ${report.modulesFailed} failed)`],
    ['Total findings', String(report.totalFindings)],
    ['Average confidence', `${summary?.averageConfidence ?? 0}%`],
  ]));
  doc.moveDown(0.3);

  // Reconnaissance section
  sectionTitle(doc, 'Reconnaissance');
  drawKeyValueGrid(doc, sanitizePairs([
    ['Origin IPv4', recon.ip],
    ['TLS issuer', recon.tlsIssuer],
    ['TLS valid to', recon.tlsValidTo],
  ]));
  if (recon.dnsDetails.length > 0) {
    doc.moveDown(0.2);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.ink).text('Routing / DNS evidence');
    doc.font('Courier').fontSize(8).fillColor(COLORS.info);
    // Cap to a reasonable number of lines — a sprawling DNS dump is
    // not actionable in a security report and was a common cause of
    // the recon section spilling across pages.
    const dnsLines = recon.dnsDetails.slice(0, 10);
    for (const line of dnsLines) {
      doc.text(sx(`* ${line}`), { lineGap: 0.5 });
    }
    if (recon.dnsDetails.length > dnsLines.length) {
      doc.fillColor(COLORS.muted).text(
        sx(`* … (${recon.dnsDetails.length - dnsLines.length} more entries omitted)`),
        { lineGap: 0.5 },
      );
    }
    doc.font('Helvetica');
  }
  doc.moveDown(0.35);

  // Findings section
  sectionTitle(doc, `Findings (${findings.length})`);
  if (findings.length === 0) {
    doc.font('Helvetica-Oblique').fontSize(9).fillColor(COLORS.muted)
      .text('No findings were produced for this assessment.');
  } else {
    findings.forEach((finding, index) => {
      try {
        drawFindingCard(doc, finding, index);
      } catch (err) {
        // A single malformed finding must never poison the whole PDF.
        // We log-and-skip so the rest of the report still renders.
        // eslint-disable-next-line no-console
        console.warn('[reportService] skipped corrupt finding', index, err);
      }
    });
  }
  doc.moveDown(0.4);

  // Module trace section — banded table.  Lower the threshold for
  // forcing a page break: previously we only broke if <200pt of room
  // remained, which often left an awkward two-row stub at the bottom.
  if (doc.y > doc.page.height - doc.page.margins.bottom - 120) {
    doc.addPage();
  }
  sectionTitle(doc, `Module trace (${moduleResults.length})`);
  if (moduleResults.length === 0) {
    doc.font('Helvetica-Oblique').fontSize(10).fillColor(COLORS.muted)
      .text('No module traces recorded.');
  } else {
    drawModuleTable(doc, moduleResults);
  }
}

function sectionTitle(doc: PDFKit.PDFDocument, label: string): void {
  ensureSpace(doc, 30);
  const x = doc.page.margins.left;
  doc.font('Helvetica-Bold').fontSize(11).fillColor(COLORS.primary).text(sx(label), x, doc.y);
  doc.moveDown(0.1);
  doc
    .moveTo(x, doc.y)
    .lineTo(doc.page.width - doc.page.margins.right, doc.y)
    .strokeColor(COLORS.rule)
    .lineWidth(0.5)
    .stroke();
  doc.moveDown(0.2);
}

function drawSeverityRibbon(doc: PDFKit.PDFDocument, report: Report): void {
  const x = doc.page.margins.left;
  const y = doc.y;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  // Height reduced 56 → 42pt — still legible but reclaims a finding's
  // worth of vertical space on the cover page.
  const height = 42;

  doc.save();
  doc.roundedRect(x, y, width, height, 5).fillColor(COLORS.bandBg).fill();
  doc.restore();

  const cells: Array<{ label: string; value: number; color: string }> = [
    { label: 'Critical', value: report.criticalCount, color: COLORS.critical },
    { label: 'High', value: report.highCount, color: COLORS.high },
    { label: 'Medium', value: report.mediumCount, color: COLORS.medium },
    { label: 'Low', value: report.lowCount, color: COLORS.low },
    { label: 'Info', value: report.infoCount, color: COLORS.info },
  ];
  const cellWidth = width / cells.length;

  cells.forEach((cell, index) => {
    const cellX = x + index * cellWidth;
    doc.font('Helvetica-Bold').fontSize(16).fillColor(cell.color)
      .text(String(cell.value), cellX, y + 6, { width: cellWidth, align: 'center' });
    doc.font('Helvetica').fontSize(7.5).fillColor(COLORS.muted)
      .text(cell.label.toUpperCase(), cellX, y + 27, {
        width: cellWidth,
        align: 'center',
        characterSpacing: 0.8,
      });
    if (index > 0) {
      doc.moveTo(cellX, y + 6).lineTo(cellX, y + height - 6)
        .strokeColor(COLORS.rule).lineWidth(0.4).stroke();
    }
  });

  doc.y = y + height + 2;
}

function drawKeyValueGrid(doc: PDFKit.PDFDocument, rows: Array<[string, string]>): void {
  const x = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const colCount = 3;
  const colWidth = width / colCount;
  // Tighter row stride — 38 → 26pt was the single biggest win on
  // pages dominated by KV grids (cover, recon, executive summary).
  const rowHeight = 26;
  const totalRows = Math.ceil(rows.length / colCount);

  ensureSpace(doc, totalRows * rowHeight + 4);

  rows.forEach((row, index) => {
    const rowIndex = Math.floor(index / colCount);
    const colIndex = index % colCount;
    const cellX = x + colIndex * colWidth;
    const cellY = doc.y + rowIndex * rowHeight;
    doc.font('Helvetica').fontSize(7).fillColor(COLORS.muted)
      .text(sx(row[0]).toUpperCase(), cellX, cellY, { width: colWidth - 8, characterSpacing: 0.5 });
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.ink)
      .text(sx(row[1], '-'), cellX, cellY + 10, { width: colWidth - 8, ellipsis: true });
  });
  doc.y += totalRows * rowHeight;
}

function drawFindingCard(doc: PDFKit.PDFDocument, finding: ScanFinding, index: number): void {
  // We reserve enough vertical space to keep each card contiguous,
  // but the estimate is intentionally tight so we don't waste a page
  // when the next card would only have spilled by one line.
  const blockHeight = estimateFindingHeight(finding);
  ensureSpace(doc, Math.min(blockHeight, 280));
  const x = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const startY = doc.y;

  // left severity rail (drawn after we know the final card height —
  // doing it up-front meant the rail could over- or under-shoot when
  // PDFKit wrapped text differently than the estimator predicted).
  const sev = finding.severity ?? 'Info';
  const innerX = x + 10;
  const innerWidth = width - 14;

  // Title + chips on the same band — saves ~22pt per finding compared
  // to laying them out on two separate rows.
  doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.ink)
    .text(sx(`#${index + 1}  ${finding.title ?? 'Untitled finding'}`), innerX, startY, {
      width: innerWidth,
    });

  const chipsY = doc.y + 1;
  drawChip(doc, sev, severityColor(sev), innerX, chipsY);
  const sevWidth = chipWidth(doc, sev);
  drawChip(doc, finding.category ?? 'Info', COLORS.muted, innerX + sevWidth + 4, chipsY);
  const catWidth = chipWidth(doc, finding.category ?? 'Info');
  if (typeof finding.confidence === 'number') {
    drawChip(
      doc,
      `CF ${finding.confidence}%`,
      COLORS.ok,
      innerX + sevWidth + catWidth + 8,
      chipsY,
    );
  }
  doc.y = chipsY + 14;

  if (finding.description) {
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.info)
      .text(sx(finding.description), innerX, doc.y, { width: innerWidth, lineGap: 1 });
  }
  if (finding.cwe) {
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLORS.critical)
      .text(sx(`Threat reference: ${finding.cwe}`), innerX, doc.y + 2, { width: innerWidth });
  }
  if (finding.evidence) {
    doc.font('Courier').fontSize(7.5).fillColor('#1f2937')
      .text(sx(finding.evidence), innerX, doc.y + 2, { width: innerWidth, lineGap: 0.5 });
    doc.font('Helvetica');
  }
  if (finding.remediation) {
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLORS.ok)
      .text('Remediation', innerX, doc.y + 3);
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.info)
      .text(sx(finding.remediation), innerX, doc.y + 1, { width: innerWidth, lineGap: 1 });
  }

  // Now we know the *real* card height — draw the severity rail.
  const endY = doc.y;
  doc.save();
  doc.rect(x, startY, 3, Math.max(12, endY - startY)).fillColor(severityColor(sev)).fill();
  doc.restore();

  // Subtle separator + minimal breathing room.
  doc.moveDown(0.25);
  doc.moveTo(x, doc.y).lineTo(x + width, doc.y)
    .strokeColor(COLORS.rule).lineWidth(0.4).stroke();
  doc.moveDown(0.2);
}

function estimateFindingHeight(finding: ScanFinding): number {
  // Numbers are intentionally smaller than the previous estimator so
  // ensureSpace doesn't add gratuitous page breaks.  The rendering
  // pass tolerates an underestimate gracefully — the worst case is a
  // single line spilling onto the next page.
  let h = 36; // title + chip row
  if (finding.description) {
    h += Math.max(14, Math.ceil(finding.description.length / 110) * 10);
  }
  if (finding.cwe) h += 10;
  if (finding.evidence) {
    h += Math.max(12, Math.ceil(finding.evidence.length / 110) * 8);
  }
  if (finding.remediation) {
    h += Math.max(14, Math.ceil(finding.remediation.length / 110) * 10);
  }
  return h + 8;
}

function drawChip(doc: PDFKit.PDFDocument, label: string, color: string, x: number, y: number): void {
  const text = sx(label).toUpperCase();
  const width = chipWidth(doc, text);
  doc.save();
  doc.roundedRect(x, y, width, 14, 7).fillColor(color).fillOpacity(0.12).fill();
  doc.fillOpacity(1).strokeColor(color).lineWidth(0.6)
    .roundedRect(x, y, width, 14, 7).stroke();
  doc.font('Helvetica-Bold').fontSize(7).fillColor(color)
    .text(text, x + 6, y + 4, { width: width - 12, align: 'center', characterSpacing: 0.6 });
  doc.restore();
}

function chipWidth(doc: PDFKit.PDFDocument, label: string): number {
  doc.font('Helvetica-Bold').fontSize(7);
  return Math.min(160, Math.max(46, doc.widthOfString(sx(label).toUpperCase()) + 14));
}

function drawModuleTable(doc: PDFKit.PDFDocument, modules: AssessmentModuleResult[]): void {
  const x = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const cols = [
    { label: 'Module', width: width * 0.28 },
    { label: 'Tool', width: width * 0.22 },
    { label: 'Status', width: width * 0.12 },
    { label: 'CF', width: width * 0.08 },
    { label: 'Duration', width: width * 0.12 },
    { label: 'Evidence', width: width * 0.18 },
  ];

  // Header
  doc.save();
  doc.rect(x, doc.y, width, 14).fillColor(COLORS.bandBg).fill();
  doc.restore();
  let cx = x;
  doc.font('Helvetica-Bold').fontSize(7.5).fillColor(COLORS.primary);
  for (const col of cols) {
    doc.text(sx(col.label).toUpperCase(), cx + 4, doc.y + 4, {
      width: col.width - 6,
      characterSpacing: 0.6,
    });
    cx += col.width;
  }
  doc.y += 16;

  modules.forEach((moduleResult, rowIndex) => {
    const duration = Math.max(0, (moduleResult.endedAt ?? 0) - (moduleResult.startedAt ?? 0));
    // Cap evidence to a single visible row's worth to keep the trace
    // table dense and scannable.  Operators who need the full text
    // already have the JSON / HTML report.
    const evidence = (moduleResult.normalizedEvidence ?? '').slice(0, 140);
    const rowHeight = Math.max(16, Math.ceil(evidence.length / 50) * 8 + 10);
    ensureSpace(doc, rowHeight + 2);

    if (rowIndex % 2 === 0) {
      doc.save();
      doc.rect(x, doc.y, width, rowHeight).fillColor(COLORS.zebra).fill();
      doc.restore();
    }

    const cells = [
      moduleResult.moduleName,
      moduleResult.sourceTool,
      moduleResult.status,
      `${moduleResult.confidence}%`,
      `${duration} ms`,
      evidence,
    ];

    cx = x;
    doc.font('Helvetica').fontSize(7.5).fillColor(COLORS.ink);
    cells.forEach((cell, index) => {
      const isStatus = index === 2;
      doc.fillColor(isStatus ? statusColor(moduleResult.status) : COLORS.ink);
      doc.text(sx(cell, ''), cx + 4, doc.y + 3, {
        width: cols[index].width - 8,
        height: rowHeight - 4,
        ellipsis: index !== 5,
      });
      cx += cols[index].width;
    });
    doc.y += rowHeight;
  });
}

function statusColor(status: string): string {
  switch (status) {
    case 'success':
      return COLORS.ok;
    case 'partial':
      return COLORS.medium;
    case 'failed':
      return COLORS.critical;
    default:
      return COLORS.muted;
  }
}

function drawHeaderBand(doc: PDFKit.PDFDocument, report: Report): void {
  const w = doc.page.width;
  // Shorter band (44pt vs 64pt) — paired with the tighter top margin
  // this reclaims real estate that otherwise wastes a line of every page.
  // CRITICAL: every text() call uses { lineBreak: false, height } so PDFKit
  // does not auto-flow into a new page when the cursor sits outside the
  // safe content area (e.g. the footer at page.height - 24). Without this
  // every header/footer pass appends an extra empty page, which is exactly
  // the bug behind the "6-page report with 4 blank pages" we just hit.
  doc.save();
  doc.rect(0, 0, w, 44).fillColor(COLORS.primary).fill();
  doc
    .fillColor('#ffffff')
    .font('Helvetica-Bold')
    .fontSize(11)
    .text('UASF', 44, 14, { lineBreak: false, width: 80, height: 16 });
  doc
    .font('Helvetica')
    .fontSize(8)
    .fillColor('#e0d6f4')
    .text('Universal Attack Simulation Framework', 80, 17, {
      lineBreak: false,
      width: 280,
      height: 14,
    });
  doc
    .font('Helvetica')
    .fontSize(8)
    .fillColor('#e0d6f4')
    .text(sx(report.targetHostname), 0, 14, {
      width: w - 44,
      align: 'right',
      lineBreak: false,
      height: 14,
    });
  doc.fontSize(7).text(sx(report.reportType).toUpperCase(), 0, 25, {
    width: w - 44,
    align: 'right',
    characterSpacing: 0.8,
    lineBreak: false,
    height: 12,
  });
  doc.restore();
}

function drawFooterBand(
  doc: PDFKit.PDFDocument,
  report: Report,
  pageNumber: number,
  totalPages: number,
): void {
  // Single-line footer — the previous two-row footer ate ~30pt per page.
  const y = doc.page.height - 24;
  const x = 44;
  const w = doc.page.width - 88;
  doc.save();
  doc.moveTo(x, y - 5).lineTo(x + w, y - 5).strokeColor(COLORS.rule).lineWidth(0.5).stroke();
  doc.font('Helvetica').fontSize(7).fillColor(COLORS.muted);
  doc.text(
    sx(`UASF · Report ${report.id.slice(0, 8)} · ${report.targetHostname}`),
    x,
    y,
    { width: w * 0.6, align: 'left', lineBreak: false, height: 12 },
  );
  doc.text(`Page ${pageNumber} of ${totalPages}`, x + w * 0.6, y, {
    width: w * 0.4,
    align: 'right',
    lineBreak: false,
    height: 12,
  });
  doc.restore();
}

function ensureSpace(doc: PDFKit.PDFDocument, needed: number): void {
  if (doc.y + needed > doc.page.height - doc.page.margins.bottom) {
    doc.addPage();
  }
}

function severityColor(severity: ScanFindingSeverity | string): string {
  switch (severity) {
    case 'Critical':
      return COLORS.critical;
    case 'High':
      return COLORS.high;
    case 'Medium':
      return COLORS.medium;
    case 'Low':
      return COLORS.low;
    default:
      return COLORS.info;
  }
}
