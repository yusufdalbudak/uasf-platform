/**
 * UASF — EASM Executive Summary Report Renderer
 *
 * 7-page, presentation-ready report that mirrors the structure operators
 * expect from a mature External Attack Surface Management product:
 *
 *   1. Cover page (title + date + brand band)
 *   2. Overview (4 metric tiles + Score + Timeline)
 *   3. Assets   (totals, asset types, top 5 assets table)
 *   4. Issues   (severity bar + Most Critical issues table)
 *   5. Technologies (categories + Most identified technologies)
 *   6. Vulnerabilities (severity bar + summary)
 *   7. Closing page
 *
 * Both HTML and PDF render from the SAME view-model
 * (`EasmOverview` from easmOverviewService) so the dashboard tile, the
 * HTML preview, and the PDF download can never disagree.  All PDFKit
 * text passes through `sanitizeForPdf` because the AFM Helvetica we
 * use only encodes Latin-1.
 */

import PDFDocument from 'pdfkit';
import { sanitizeForPdf } from '../util/pdfSanitize';
import type { EasmOverview, SeverityCount, SeverityLabel, TopAssetRow, TopIssueRow, TopTechnologyRow } from './easmOverviewService';

const sx = (v: unknown, fallback = ''): string => sanitizeForPdf(v, fallback);

const COLORS = {
  primary: '#4d1c8c',
  primarySoft: '#f5f3ff',
  ink: '#0f172a',
  body: '#374151',
  muted: '#6b7280',
  rule: '#e5e7eb',
  zebra: '#f9fafb',
  critical: '#b91c1c',
  high: '#c2410c',
  medium: '#ca8a04',
  low: '#1d4ed8',
  info: '#6b7280',
  ok: '#047857',
  gradeA: '#10b981',
  gradeB: '#22c55e',
  gradeC: '#eab308',
  gradeD: '#f97316',
  gradeF: '#dc2626',
};

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

export function renderEasmExecutiveSummaryHtml(model: EasmOverview): string {
  const generated = new Date(model.generatedAt).toUTCString();
  const grade = model.score.grade;
  const score = model.score.score;
  const sevColor = (s: SeverityLabel): string => severityColor(s);

  const tileBlock = (label: string, value: number, subline: string): string => `
    <div class="tile">
      <div class="tile-label">${escapeHtml(label.toUpperCase())}</div>
      <div class="tile-value">${value.toLocaleString('en-US')}</div>
      <div class="tile-subline">${escapeHtml(subline)}</div>
    </div>`;

  const sevBar = (rows: SeverityCount[], total: number): string => {
    if (total === 0) return '<div class="empty">No findings recorded.</div>';
    const segs = rows
      .filter((r) => r.count > 0)
      .map(
        (r) => `<div class="seg" style="flex: ${r.count}; background: ${sevColor(r.label)};" title="${r.label}: ${r.count}"></div>`,
      )
      .join('');
    const legend = rows
      .map(
        (r) => `<div class="legend-item">
          <span class="legend-dot" style="background:${sevColor(r.label)}"></span>
          <span class="legend-label">${escapeHtml(r.label)}</span>
          <span class="legend-count">${r.count}</span>
        </div>`,
      )
      .join('');
    return `<div class="sev-bar">${segs}</div><div class="legend">${legend}</div>`;
  };

  const topAssetsTable = (rows: TopAssetRow[]): string =>
    rows.length === 0
      ? '<div class="empty">No approved assets registered yet.</div>'
      : `<table class="data-table">
          <thead><tr>
            <th>Hostname</th>
            <th>Type</th>
            <th class="num">Issues</th>
            <th class="num">Technologies</th>
            <th class="num">Score</th>
            <th>Rating</th>
          </tr></thead>
          <tbody>
            ${rows
              .map(
                (a) => `
              <tr>
                <td class="mono">${escapeHtml(a.hostname)}</td>
                <td>${escapeHtml(a.assetType)}</td>
                <td class="num">${a.issues}</td>
                <td class="num">${a.technologies}</td>
                <td class="num">${a.ratingScore}</td>
                <td><span class="grade g-${a.rating}">${a.rating}</span></td>
              </tr>`,
              )
              .join('')}
          </tbody>
        </table>`;

  const topIssuesTable = (rows: TopIssueRow[]): string =>
    rows.length === 0
      ? '<div class="empty">No issues observed yet.</div>'
      : `<table class="data-table">
          <thead><tr>
            <th>Issue</th>
            <th>Category</th>
            <th class="num">Assets</th>
            <th>Severity</th>
          </tr></thead>
          <tbody>
            ${rows
              .map(
                (i) => `
              <tr>
                <td>${escapeHtml(i.title)}</td>
                <td>${escapeHtml(i.category)}</td>
                <td class="num">${i.assetCount}</td>
                <td><span class="sev sev-${i.severity.toLowerCase()}">${escapeHtml(i.severity.toUpperCase())}</span></td>
              </tr>`,
              )
              .join('')}
          </tbody>
        </table>`;

  const topTechTable = (rows: TopTechnologyRow[]): string =>
    rows.length === 0
      ? '<div class="empty">No technologies fingerprinted yet.</div>'
      : `<table class="data-table">
          <thead><tr>
            <th>Technology</th>
            <th>Category</th>
            <th>Version</th>
            <th class="num">Assets</th>
            <th class="num">Vulnerabilities</th>
          </tr></thead>
          <tbody>
            ${rows
              .map(
                (t) => `
              <tr>
                <td><strong>${escapeHtml(t.productName)}</strong> ${t.vendor ? `<span class="muted">— ${escapeHtml(t.vendor)}</span>` : ''}</td>
                <td>${escapeHtml(prettyCategory(t.category))}</td>
                <td class="mono">${escapeHtml(t.version ?? t.versionFamily ?? '—')}</td>
                <td class="num">${t.assetCount}</td>
                <td class="num">${t.vulnerabilityCount}</td>
              </tr>`,
              )
              .join('')}
          </tbody>
        </table>`;

  const timelineSparkline = renderTimelineSvg(model);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>UASF EASM Executive Summary</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>${EASM_REPORT_CSS}</style>
</head>
<body>
  <header class="brand-band">
    <div class="brand-left">
      <div class="brand-mark">UASF</div>
      <div class="brand-tag">External Attack Surface Management — Executive Summary</div>
    </div>
    <div class="brand-right">
      <div class="brand-meta">Generated</div>
      <div class="brand-meta-value">${escapeHtml(generated)}</div>
    </div>
  </header>

  <main>
    <!-- ===== Section 1 — Overview ===== -->
    <section class="section">
      <h2 class="section-title">Executive Overview</h2>
      <div class="overview-grid">
        <div class="overview-tiles">
          ${tileBlock(model.tiles.assets.label, model.tiles.assets.value, model.tiles.assets.subline)}
          ${tileBlock(model.tiles.technologies.label, model.tiles.technologies.value, model.tiles.technologies.subline)}
          ${tileBlock(model.tiles.issues.label, model.tiles.issues.value, model.tiles.issues.subline)}
          ${tileBlock(model.tiles.vulnerabilities.label, model.tiles.vulnerabilities.value, model.tiles.vulnerabilities.subline)}
        </div>
        <div class="score-card">
          <div class="score-card-label">SECURITY SCORE</div>
          <div class="score-grade g-${grade}">${grade}</div>
          <div class="score-value">${score}</div>
          <div class="score-summary">${escapeHtml(model.score.summary)}</div>
        </div>
      </div>
      <div class="timeline-card">
        <div class="timeline-head">
          <div class="timeline-title">Issue volume — last 14 days</div>
          <div class="timeline-meta">Critical / High / Medium / Low</div>
        </div>
        ${timelineSparkline}
      </div>
    </section>

    <!-- ===== Section 2 — Assets ===== -->
    <section class="section">
      <h2 class="section-title">Assets</h2>
      <div class="kv-grid">
        <div class="kv">
          <div class="kv-label">TOTAL APPROVED ASSETS</div>
          <div class="kv-value xl">${model.assets.total}</div>
        </div>
        <div class="kv">
          <div class="kv-label">DOMAINS</div>
          <div class="kv-value">${model.assets.domains}</div>
        </div>
        <div class="kv">
          <div class="kv-label">SUBDOMAINS</div>
          <div class="kv-value">${model.assets.subdomains}</div>
        </div>
        <div class="kv">
          <div class="kv-label">IP ADDRESSES</div>
          <div class="kv-value">${model.assets.ipAddresses}</div>
        </div>
      </div>
      <div class="subsection-title">Asset types</div>
      <div class="chip-row">
        ${model.assets.byType
          .map(
            (b) => `<div class="chip"><span class="chip-label">${escapeHtml(b.type)}</span><span class="chip-count">${b.count}</span></div>`,
          )
          .join('')}
      </div>
      <div class="subsection-title">Top assets</div>
      ${topAssetsTable(model.assets.top)}
    </section>

    <!-- ===== Section 3 — Issues ===== -->
    <section class="section">
      <h2 class="section-title">Issues</h2>
      <div class="kv-grid">
        <div class="kv wide">
          <div class="kv-label">TOTAL ISSUES</div>
          <div class="kv-value xl">${model.issues.total}</div>
          ${sevBar(model.issues.bySeverity, model.issues.total)}
        </div>
      </div>
      <div class="subsection-title">By category</div>
      <div class="chip-row">
        ${model.issues.byCategory
          .map(
            (b) => `<div class="chip"><span class="chip-label">${escapeHtml(b.category)}</span><span class="chip-count">${b.count}</span></div>`,
          )
          .join('')}
      </div>
      <div class="subsection-title">Most critical issues</div>
      ${topIssuesTable(model.issues.mostCritical)}
      <div class="subsection-title">Most seen issues</div>
      ${topIssuesTable(model.issues.mostSeen)}
    </section>

    <!-- ===== Section 4 — Technologies ===== -->
    <section class="section">
      <h2 class="section-title">Technologies</h2>
      <div class="kv-grid">
        <div class="kv">
          <div class="kv-label">DISTINCT TECHNOLOGIES</div>
          <div class="kv-value xl">${model.technologies.total}</div>
        </div>
        <div class="kv wide">
          <div class="kv-label">BY CATEGORY</div>
          <div class="chip-row in-kv">
            ${model.technologies.byCategory
              .map(
                (b) => `<div class="chip"><span class="chip-label">${escapeHtml(prettyCategory(b.category))}</span><span class="chip-count">${b.count}</span></div>`,
              )
              .join('')}
          </div>
        </div>
      </div>
      <div class="subsection-title">Most identified technologies</div>
      ${topTechTable(model.technologies.mostUsed)}
      <div class="subsection-title">Most vulnerable technologies</div>
      ${topTechTable(model.technologies.mostVulnerable)}
    </section>

    <!-- ===== Section 5 — Vulnerabilities ===== -->
    <section class="section">
      <h2 class="section-title">Vulnerabilities</h2>
      <div class="kv-grid">
        <div class="kv wide">
          <div class="kv-label">TOTAL VULNERABILITIES</div>
          <div class="kv-value xl">${model.vulnerabilities.total}</div>
          ${sevBar(model.vulnerabilities.bySeverity, model.vulnerabilities.total)}
        </div>
      </div>
      <p class="closing-line">
        Vulnerability counts combine CVE/advisory correlations from detected technologies
        (mycve + OSV.dev) with cached dependency advisories (NVD).  Where the local feed
        could not assert version applicability, the correlation is reported with hedged
        certainty rather than dropped.
      </p>
    </section>
  </main>

  <footer class="closing">
    <div class="closing-headline">
      Continuously detect, analyse, and validate risks across your approved attack surface.
    </div>
    <div class="closing-sub">
      Stay ahead with evidence-based fingerprinting, version-aware advisory correlation, and
      hardening validation against your edge defences.
    </div>
    <div class="closing-brand">UASF — Universal Attack Simulation Framework</div>
  </footer>
</body>
</html>`;
}

function renderTimelineSvg(model: EasmOverview): string {
  const days = model.timeline;
  if (days.length === 0) return '<div class="empty">No timeline data.</div>';
  const w = 780;
  const h = 80;
  const pad = 4;
  const max = Math.max(
    1,
    ...days.map((d) => d.critical + d.high + d.medium + d.low),
  );
  const colW = (w - pad * 2) / days.length;
  const bars = days
    .map((d, i) => {
      const total = d.critical + d.high + d.medium + d.low;
      const x = pad + i * colW;
      let yCursor = h - pad;
      const stack = (count: number, color: string): string => {
        if (count === 0) return '';
        const barH = (count / max) * (h - pad * 2);
        yCursor -= barH;
        return `<rect x="${x + 2}" y="${yCursor}" width="${colW - 4}" height="${barH}" fill="${color}" rx="1.5" />`;
      };
      const segs = stack(d.low, COLORS.low) + stack(d.medium, COLORS.medium) + stack(d.high, COLORS.high) + stack(d.critical, COLORS.critical);
      return total === 0
        ? `<rect x="${x + 2}" y="${h - pad - 2}" width="${colW - 4}" height="2" fill="${COLORS.rule}" rx="1" />`
        : segs;
    })
    .join('');
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="timeline-svg">${bars}</svg>`;
}

const EASM_REPORT_CSS = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    color: ${COLORS.ink}; background: #ffffff; -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .brand-band {
    background: ${COLORS.primary}; color: #fff; padding: 24px 40px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .brand-mark { font-size: 22px; font-weight: 800; letter-spacing: 0.16em; }
  .brand-tag { font-size: 12px; opacity: 0.85; margin-top: 4px; }
  .brand-meta { font-size: 10px; opacity: 0.7; text-transform: uppercase; letter-spacing: 0.1em; text-align: right; }
  .brand-meta-value { font-size: 12px; opacity: 0.95; }
  main { max-width: 920px; margin: 0 auto; padding: 28px 40px 0; }
  .section { padding: 24px 0; border-bottom: 1px solid ${COLORS.rule}; page-break-inside: avoid; }
  .section:last-of-type { border-bottom: none; }
  .section-title {
    font-size: 18px; color: ${COLORS.primary}; margin: 0 0 16px; letter-spacing: 0.02em;
  }
  .subsection-title {
    font-size: 11px; color: ${COLORS.primary}; text-transform: uppercase; letter-spacing: 0.1em;
    margin: 18px 0 8px; font-weight: 700;
  }
  .overview-grid {
    display: grid; grid-template-columns: 2fr 1fr; gap: 20px; align-items: stretch;
  }
  .overview-tiles { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .tile {
    border: 1px solid ${COLORS.rule}; border-radius: 12px; padding: 14px 16px;
    background: ${COLORS.zebra};
  }
  .tile-label {
    font-size: 9.5px; color: ${COLORS.muted}; letter-spacing: 0.1em; font-weight: 700;
  }
  .tile-value {
    font-size: 28px; font-weight: 800; color: ${COLORS.ink}; margin: 4px 0 2px;
  }
  .tile-subline { font-size: 11px; color: ${COLORS.muted}; }
  .score-card {
    border: 1px solid ${COLORS.rule}; border-radius: 12px; padding: 16px;
    background: linear-gradient(180deg, ${COLORS.primarySoft}, #ffffff);
    display: flex; flex-direction: column; align-items: center; text-align: center;
  }
  .score-card-label {
    font-size: 9.5px; color: ${COLORS.primary}; letter-spacing: 0.12em; font-weight: 700;
  }
  .score-grade {
    width: 80px; height: 80px; border-radius: 50%; color: #fff; display: flex; align-items: center;
    justify-content: center; font-size: 38px; font-weight: 800; margin: 12px 0 4px;
    box-shadow: 0 4px 18px rgba(77,28,140,0.18);
  }
  .g-A { background: ${COLORS.gradeA}; }
  .g-B { background: ${COLORS.gradeB}; }
  .g-C { background: ${COLORS.gradeC}; }
  .g-D { background: ${COLORS.gradeD}; }
  .g-F { background: ${COLORS.gradeF}; }
  .score-value { font-size: 22px; font-weight: 800; color: ${COLORS.ink}; }
  .score-summary { font-size: 11px; color: ${COLORS.muted}; margin-top: 4px; line-height: 1.5; }
  .timeline-card {
    margin-top: 18px; border: 1px solid ${COLORS.rule}; border-radius: 12px; padding: 14px 16px;
  }
  .timeline-head {
    display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;
  }
  .timeline-title { font-size: 12px; font-weight: 700; color: ${COLORS.ink}; }
  .timeline-meta { font-size: 10px; color: ${COLORS.muted}; }
  .timeline-svg { width: 100%; height: 80px; }
  .kv-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
  }
  .kv {
    border: 1px solid ${COLORS.rule}; border-radius: 10px; padding: 12px 14px; background: #fff;
  }
  .kv.wide { grid-column: span 4; }
  .kv-label {
    font-size: 9.5px; color: ${COLORS.muted}; letter-spacing: 0.1em; font-weight: 700;
  }
  .kv-value { font-size: 18px; font-weight: 800; color: ${COLORS.ink}; margin-top: 4px; }
  .kv-value.xl { font-size: 28px; }
  .chip-row { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip-row.in-kv { margin-top: 8px; }
  .chip {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 999px; background: ${COLORS.primarySoft}; color: ${COLORS.primary};
    font-size: 11px; font-weight: 600;
  }
  .chip-count {
    background: ${COLORS.primary}; color: #fff; font-size: 10px; padding: 1px 6px; border-radius: 999px;
  }
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th, .data-table td {
    text-align: left; padding: 8px 10px; border-bottom: 1px solid ${COLORS.rule}; vertical-align: top;
  }
  .data-table th {
    background: ${COLORS.primarySoft}; color: ${COLORS.primary}; font-size: 10.5px;
    text-transform: uppercase; letter-spacing: 0.06em;
  }
  .data-table .num { text-align: right; font-variant-numeric: tabular-nums; }
  .data-table .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; }
  .grade { display: inline-block; min-width: 22px; padding: 2px 8px; border-radius: 6px; color: #fff; font-weight: 800; text-align: center; }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 10px; font-weight: 700; }
  .sev-critical { background: #fee2e2; color: ${COLORS.critical}; }
  .sev-high { background: #ffedd5; color: ${COLORS.high}; }
  .sev-medium { background: #fef9c3; color: ${COLORS.medium}; }
  .sev-low { background: #dbeafe; color: ${COLORS.low}; }
  .sev-info { background: #f3f4f6; color: ${COLORS.muted}; }
  .sev-bar {
    display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: ${COLORS.rule}; margin-top: 10px;
  }
  .seg { height: 100%; }
  .legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; font-size: 11px; }
  .legend-item { display: inline-flex; align-items: center; gap: 6px; color: ${COLORS.body}; }
  .legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .legend-count { color: ${COLORS.muted}; }
  .empty { font-size: 11px; color: ${COLORS.muted}; font-style: italic; padding: 6px 0; }
  .muted { color: ${COLORS.muted}; }
  .closing { padding: 32px 40px; text-align: center; background: ${COLORS.zebra}; border-top: 1px solid ${COLORS.rule}; }
  .closing-headline { font-size: 14px; font-weight: 700; color: ${COLORS.ink}; }
  .closing-sub { font-size: 12px; color: ${COLORS.muted}; margin: 6px 0 14px; line-height: 1.5; }
  .closing-brand { font-size: 11px; color: ${COLORS.primary}; letter-spacing: 0.16em; font-weight: 700; }
  .closing-line { font-size: 11.5px; color: ${COLORS.body}; line-height: 1.6; margin: 12px 2px 0; }
  @media print { .section { page-break-inside: avoid; } }
`;

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function prettyCategory(c: string): string {
  return c.replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
}

function severityColor(label: SeverityLabel): string {
  switch (label) {
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

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

export function renderEasmExecutiveSummaryPdf(model: EasmOverview): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 56, bottom: 50, left: 44, right: 44 },
        bufferPages: true,
        info: {
          Title: sx('UASF EASM Executive Summary'),
          Subject: 'UASF EASM Executive Summary Report',
          Author: 'UASF',
          Producer: 'UASF Report Engine',
        },
      });

      const chunks: Buffer[] = [];
      doc.on('data', (c: Buffer) => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      writeCoverPage(doc, model);
      writeOverviewPage(doc, model);
      writeAssetsPage(doc, model);
      writeIssuesPage(doc, model);
      writeTechnologiesPage(doc, model);
      writeVulnerabilitiesPage(doc, model);
      writeClosingPage(doc);

      // Brand chrome on every page (skip cover).
      const range = doc.bufferedPageRange();
      for (let i = 0; i < range.count; i += 1) {
        doc.switchToPage(range.start + i);
        if (i === 0) {
          // cover already painted
          drawFooterBand(doc, i + 1, range.count);
        } else {
          drawHeaderBand(doc);
          drawFooterBand(doc, i + 1, range.count);
        }
      }
      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

function writeCoverPage(doc: PDFKit.PDFDocument, model: EasmOverview): void {
  const w = doc.page.width;
  const h = doc.page.height;
  // Full-bleed brand band
  doc.save().rect(0, 0, w, 240).fillColor(COLORS.primary).fill();
  doc
    .fillColor('#ffffff')
    .font('Helvetica-Bold')
    .fontSize(48)
    .text(sx('EASM'), 0, 60, { width: w, align: 'center' });
  doc
    .font('Helvetica-Bold')
    .fontSize(24)
    .text(sx('Executive Summary'), 0, 120, { width: w, align: 'center' });
  doc
    .font('Helvetica')
    .fontSize(12)
    .fillColor('#e0d6f4')
    .text(sx('Universal Attack Simulation Framework'), 0, 160, { width: w, align: 'center' });
  doc
    .fontSize(11)
    .fillColor('#ffffffcc')
    .text(sx(new Date(model.generatedAt).toUTCString()), 0, 190, { width: w, align: 'center' });
  doc.restore();

  // Score badge
  const cx = w / 2;
  const cy = 380;
  const r = 70;
  doc.save();
  doc.circle(cx, cy, r).fillColor(gradeColor(model.score.grade)).fill();
  doc
    .fillColor('#ffffff')
    .font('Helvetica-Bold')
    .fontSize(56)
    .text(model.score.grade, cx - 24, cy - 36, { width: 50, align: 'center' });
  doc.restore();
  doc
    .fillColor(COLORS.ink)
    .font('Helvetica-Bold')
    .fontSize(28)
    .text(String(model.score.score), 0, cy + 80, { width: w, align: 'center' });
  doc
    .font('Helvetica')
    .fontSize(11)
    .fillColor(COLORS.muted)
    .text(sx('Overall Security Score (0–1000)'), 0, cy + 114, { width: w, align: 'center' });
  doc
    .font('Helvetica-Oblique')
    .fontSize(11)
    .fillColor(COLORS.body)
    .text(sx(model.score.summary), 60, cy + 140, { width: w - 120, align: 'center', lineGap: 2 });

  // Cover footnote
  doc
    .font('Helvetica')
    .fontSize(9.5)
    .fillColor(COLORS.muted)
    .text(
      sx(
        'Approved attack surface only — every metric in this report is bound to assets that have been explicitly registered and approved in UASF.',
      ),
      60,
      h - 120,
      { width: w - 120, align: 'center', lineGap: 2 },
    );
}

function writeOverviewPage(doc: PDFKit.PDFDocument, model: EasmOverview): void {
  doc.addPage();
  sectionTitle(doc, 'Executive Overview');
  drawTilesGrid(doc, [
    [model.tiles.assets.label, model.tiles.assets.value, model.tiles.assets.subline],
    [model.tiles.technologies.label, model.tiles.technologies.value, model.tiles.technologies.subline],
    [model.tiles.issues.label, model.tiles.issues.value, model.tiles.issues.subline],
    [model.tiles.vulnerabilities.label, model.tiles.vulnerabilities.value, model.tiles.vulnerabilities.subline],
  ]);
  doc.moveDown(0.6);
  sectionTitle(doc, 'Issue volume — last 14 days');
  drawTimelineBars(doc, model);
  doc.moveDown(0.4);
  doc
    .font('Helvetica-Oblique')
    .fontSize(9)
    .fillColor(COLORS.muted)
    .text(sx(model.score.summary), { width: pageInnerWidth(doc), lineGap: 2 });
}

function writeAssetsPage(doc: PDFKit.PDFDocument, model: EasmOverview): void {
  doc.addPage();
  sectionTitle(doc, 'Assets');
  drawTilesGrid(doc, [
    ['TOTAL APPROVED ASSETS', model.assets.total, ''],
    ['DOMAINS', model.assets.domains, ''],
    ['SUBDOMAINS', model.assets.subdomains, ''],
    ['IP ADDRESSES', model.assets.ipAddresses, ''],
  ]);
  doc.moveDown(0.4);
  if (model.assets.byType.length > 0) {
    subTitle(doc, 'Asset types');
    drawChipRow(
      doc,
      model.assets.byType.map((b) => `${b.type}: ${b.count}`),
    );
    doc.moveDown(0.4);
  }
  subTitle(doc, 'Top assets');
  drawTable(
    doc,
    ['Hostname', 'Type', 'Issues', 'Tech', 'Score', 'Rating'],
    model.assets.top.map((a) => [
      a.hostname,
      a.assetType,
      String(a.issues),
      String(a.technologies),
      String(a.ratingScore),
      a.rating,
    ]),
    [0.35, 0.12, 0.1, 0.08, 0.1, 0.1],
    [false, false, true, true, true, true],
  );
}

function writeIssuesPage(doc: PDFKit.PDFDocument, model: EasmOverview): void {
  doc.addPage();
  sectionTitle(doc, 'Issues');
  drawHeadlineMetric(doc, 'TOTAL ISSUES', model.issues.total);
  drawSeverityBar(doc, model.issues.bySeverity, model.issues.total);
  doc.moveDown(0.6);
  if (model.issues.byCategory.length > 0) {
    subTitle(doc, 'By category');
    drawChipRow(
      doc,
      model.issues.byCategory.map((b) => `${b.category}: ${b.count}`),
    );
    doc.moveDown(0.4);
  }
  subTitle(doc, 'Most critical issues');
  drawTable(
    doc,
    ['Issue', 'Category', 'Assets', 'Severity'],
    model.issues.mostCritical.map((i) => [i.title, i.category, String(i.assetCount), i.severity]),
    [0.5, 0.22, 0.1, 0.18],
    [false, false, true, false],
  );
  doc.moveDown(0.4);
  subTitle(doc, 'Most seen issues');
  drawTable(
    doc,
    ['Issue', 'Category', 'Assets', 'Severity'],
    model.issues.mostSeen.map((i) => [i.title, i.category, String(i.assetCount), i.severity]),
    [0.5, 0.22, 0.1, 0.18],
    [false, false, true, false],
  );
}

function writeTechnologiesPage(doc: PDFKit.PDFDocument, model: EasmOverview): void {
  doc.addPage();
  sectionTitle(doc, 'Technologies');
  drawHeadlineMetric(doc, 'DISTINCT TECHNOLOGIES', model.technologies.total);
  if (model.technologies.byCategory.length > 0) {
    subTitle(doc, 'By category');
    drawChipRow(
      doc,
      model.technologies.byCategory.map(
        (b) => `${b.category.replace(/_/g, ' ')}: ${b.count}`,
      ),
    );
    doc.moveDown(0.4);
  }
  subTitle(doc, 'Most identified technologies');
  drawTable(
    doc,
    ['Technology', 'Category', 'Version', 'Assets', 'Vulns'],
    model.technologies.mostUsed.map((t) => [
      t.vendor ? `${t.productName} — ${t.vendor}` : t.productName,
      prettyCategory(t.category),
      t.version ?? t.versionFamily ?? '-',
      String(t.assetCount),
      String(t.vulnerabilityCount),
    ]),
    [0.36, 0.22, 0.18, 0.12, 0.12],
    [false, false, false, true, true],
  );
  doc.moveDown(0.4);
  subTitle(doc, 'Most vulnerable technologies');
  drawTable(
    doc,
    ['Technology', 'Category', 'Version', 'Assets', 'Vulns'],
    model.technologies.mostVulnerable.map((t) => [
      t.vendor ? `${t.productName} — ${t.vendor}` : t.productName,
      prettyCategory(t.category),
      t.version ?? t.versionFamily ?? '-',
      String(t.assetCount),
      String(t.vulnerabilityCount),
    ]),
    [0.36, 0.22, 0.18, 0.12, 0.12],
    [false, false, false, true, true],
  );
}

function writeVulnerabilitiesPage(doc: PDFKit.PDFDocument, model: EasmOverview): void {
  doc.addPage();
  sectionTitle(doc, 'Vulnerabilities');
  drawHeadlineMetric(doc, 'TOTAL VULNERABILITIES', model.vulnerabilities.total);
  drawSeverityBar(doc, model.vulnerabilities.bySeverity, model.vulnerabilities.total);
  doc.moveDown(0.6);
  doc
    .font('Helvetica')
    .fontSize(9.5)
    .fillColor(COLORS.body)
    .text(
      sx(
        'Vulnerability counts combine CVE/advisory correlations from detected technologies (mycve + OSV.dev) with cached dependency advisories (NVD).  Where the local feed could not assert version applicability the correlation is reported with hedged certainty rather than dropped.',
      ),
      { width: pageInnerWidth(doc), lineGap: 2.5 },
    );
}

function writeClosingPage(doc: PDFKit.PDFDocument): void {
  doc.addPage();
  const w = doc.page.width;
  const h = doc.page.height;
  doc
    .fillColor(COLORS.primary)
    .font('Helvetica-Bold')
    .fontSize(20)
    .text(sx('UASF'), 0, h / 2 - 80, { width: w, align: 'center' });
  doc
    .fillColor(COLORS.ink)
    .font('Helvetica-Bold')
    .fontSize(13)
    .text(
      sx('Continuously detect, analyse, and validate risks across your approved attack surface.'),
      60,
      h / 2 - 40,
      { width: w - 120, align: 'center' },
    );
  doc
    .font('Helvetica')
    .fontSize(11)
    .fillColor(COLORS.muted)
    .text(
      sx(
        'Stay ahead with evidence-based fingerprinting, version-aware advisory correlation, and hardening validation against your edge defences.',
      ),
      60,
      h / 2,
      { width: w - 120, align: 'center', lineGap: 3 },
    );
  doc
    .font('Helvetica-Bold')
    .fontSize(10)
    .fillColor(COLORS.primary)
    .text(sx('UNIVERSAL ATTACK SIMULATION FRAMEWORK'), 0, h / 2 + 80, {
      width: w,
      align: 'center',
      characterSpacing: 1,
    });
}

// ---------------- PDF primitives ----------------

function pageInnerWidth(doc: PDFKit.PDFDocument): number {
  return doc.page.width - doc.page.margins.left - doc.page.margins.right;
}

function sectionTitle(doc: PDFKit.PDFDocument, label: string): void {
  doc
    .font('Helvetica-Bold')
    .fontSize(14)
    .fillColor(COLORS.primary)
    .text(sx(label), doc.page.margins.left, doc.y);
  doc.moveDown(0.1);
  doc
    .moveTo(doc.page.margins.left, doc.y)
    .lineTo(doc.page.width - doc.page.margins.right, doc.y)
    .strokeColor(COLORS.rule)
    .lineWidth(0.5)
    .stroke();
  doc.moveDown(0.4);
}

function subTitle(doc: PDFKit.PDFDocument, label: string): void {
  doc
    .font('Helvetica-Bold')
    .fontSize(9.5)
    .fillColor(COLORS.primary)
    .text(sx(label.toUpperCase()), doc.page.margins.left, doc.y, { characterSpacing: 0.6 });
  doc.moveDown(0.2);
}

function drawHeadlineMetric(doc: PDFKit.PDFDocument, label: string, value: number): void {
  const x = doc.page.margins.left;
  const startY = doc.y;
  doc
    .font('Helvetica')
    .fontSize(8.5)
    .fillColor(COLORS.muted)
    .text(sx(label.toUpperCase()), x, startY, { characterSpacing: 0.6 });
  doc.font('Helvetica-Bold').fontSize(28).fillColor(COLORS.ink).text(value.toLocaleString('en-US'), x, startY + 11);
  doc.y = startY + 46;
}

function drawTilesGrid(doc: PDFKit.PDFDocument, tiles: Array<[string, number | string, string]>): void {
  const x = doc.page.margins.left;
  const w = pageInnerWidth(doc);
  const cols = 2;
  const colW = (w - 12) / cols;
  const rowH = 64;
  const startY = doc.y;
  for (let i = 0; i < tiles.length; i += 1) {
    const row = Math.floor(i / cols);
    const col = i % cols;
    const tx = x + col * (colW + 12);
    const ty = startY + row * (rowH + 10);
    doc.rect(tx, ty, colW, rowH).fillColor(COLORS.zebra).fill();
    doc.rect(tx, ty, colW, rowH).strokeColor(COLORS.rule).lineWidth(0.5).stroke();
    doc.fillColor(COLORS.muted).font('Helvetica').fontSize(7.5).text(sx(String(tiles[i][0]).toUpperCase()), tx + 12, ty + 10, {
      characterSpacing: 0.6,
      width: colW - 24,
    });
    doc.fillColor(COLORS.ink).font('Helvetica-Bold').fontSize(20).text(String(tiles[i][1]), tx + 12, ty + 22, {
      width: colW - 24,
    });
    if (tiles[i][2]) {
      doc.fillColor(COLORS.muted).font('Helvetica').fontSize(8).text(sx(tiles[i][2]), tx + 12, ty + 46, {
        width: colW - 24,
      });
    }
  }
  doc.y = startY + Math.ceil(tiles.length / cols) * (rowH + 10) + 4;
}

function drawSeverityBar(doc: PDFKit.PDFDocument, rows: SeverityCount[], total: number): void {
  const x = doc.page.margins.left;
  const w = pageInnerWidth(doc);
  const y = doc.y;
  if (total === 0) {
    doc.font('Helvetica-Oblique').fontSize(9).fillColor(COLORS.muted).text(sx('No findings recorded.'), x, y);
    doc.y = y + 14;
    return;
  }
  const h = 10;
  let cursor = x;
  for (const r of rows) {
    if (r.count === 0) continue;
    const segW = (r.count / total) * w;
    doc.rect(cursor, y, segW, h).fillColor(severityColor(r.label)).fill();
    cursor += segW;
  }
  // Legend row beneath
  let lx = x;
  const ly = y + h + 8;
  doc.font('Helvetica').fontSize(9).fillColor(COLORS.body);
  for (const r of rows) {
    const txt = `${r.label}: ${r.count}`;
    const dotW = 8;
    doc.rect(lx, ly + 1, dotW, dotW).fillColor(severityColor(r.label)).fill();
    doc.fillColor(COLORS.body).text(sx(txt), lx + dotW + 4, ly, { continued: false });
    lx += dotW + 4 + doc.widthOfString(txt) + 14;
  }
  doc.y = ly + 14;
}

function drawChipRow(doc: PDFKit.PDFDocument, labels: string[]): void {
  const x = doc.page.margins.left;
  const w = pageInnerWidth(doc);
  let cursorX = x;
  let cursorY = doc.y;
  const rowH = 18;
  doc.font('Helvetica-Bold').fontSize(9);
  for (const label of labels) {
    const tw = doc.widthOfString(sx(label));
    const chipW = tw + 18;
    if (cursorX + chipW > x + w) {
      cursorX = x;
      cursorY += rowH + 4;
    }
    doc.rect(cursorX, cursorY, chipW, rowH).fillColor(COLORS.primarySoft).fill();
    doc.fillColor(COLORS.primary).text(sx(label), cursorX + 9, cursorY + 4, { lineBreak: false });
    cursorX += chipW + 6;
  }
  doc.y = cursorY + rowH + 4;
}

function drawTable(
  doc: PDFKit.PDFDocument,
  headers: string[],
  rows: string[][],
  widths: number[],
  numericRight: boolean[],
): void {
  const x = doc.page.margins.left;
  const w = pageInnerWidth(doc);
  const colWidths = widths.map((p) => p * w);
  const headerH = 16;
  const rowH = 18;
  if (rows.length === 0) {
    doc.font('Helvetica-Oblique').fontSize(9).fillColor(COLORS.muted).text(sx('No data.'), x, doc.y);
    doc.moveDown(0.4);
    return;
  }
  // Header
  doc.rect(x, doc.y, w, headerH).fillColor(COLORS.primarySoft).fill();
  let cx = x;
  for (let i = 0; i < headers.length; i += 1) {
    doc
      .fillColor(COLORS.primary)
      .font('Helvetica-Bold')
      .fontSize(8.5)
      .text(sx(headers[i].toUpperCase()), cx + 6, doc.y + 4, {
        width: colWidths[i] - 12,
        align: numericRight[i] ? 'right' : 'left',
        lineBreak: false,
        characterSpacing: 0.5,
      });
    cx += colWidths[i];
  }
  doc.y += headerH;

  // Body
  for (let r = 0; r < rows.length; r += 1) {
    if (doc.y + rowH > doc.page.height - doc.page.margins.bottom - 30) {
      doc.addPage();
      drawHeaderBand(doc);
    }
    if (r % 2 === 0) {
      doc.rect(x, doc.y, w, rowH).fillColor(COLORS.zebra).fill();
    }
    cx = x;
    for (let i = 0; i < rows[r].length; i += 1) {
      doc
        .fillColor(COLORS.ink)
        .font('Helvetica')
        .fontSize(9)
        .text(sx(rows[r][i] ?? '-'), cx + 6, doc.y + 5, {
          width: colWidths[i] - 12,
          align: numericRight[i] ? 'right' : 'left',
          lineBreak: false,
          ellipsis: true,
        });
      cx += colWidths[i];
    }
    doc.y += rowH;
  }
}

function drawTimelineBars(doc: PDFKit.PDFDocument, model: EasmOverview): void {
  const x = doc.page.margins.left;
  const w = pageInnerWidth(doc);
  const h = 70;
  const days = model.timeline;
  if (days.length === 0) return;
  const max = Math.max(1, ...days.map((d) => d.critical + d.high + d.medium + d.low));
  const colW = w / days.length;
  const baseY = doc.y + h;
  doc.save();
  for (let i = 0; i < days.length; i += 1) {
    const d = days[i];
    const total = d.critical + d.high + d.medium + d.low;
    const cx = x + i * colW + 2;
    if (total === 0) {
      doc.rect(cx, baseY - 2, colW - 4, 2).fillColor(COLORS.rule).fill();
      continue;
    }
    let yCursor = baseY;
    const stack = (count: number, color: string): void => {
      if (count === 0) return;
      const bh = (count / max) * (h - 4);
      yCursor -= bh;
      doc.rect(cx, yCursor, colW - 4, bh).fillColor(color).fill();
    };
    stack(d.low, COLORS.low);
    stack(d.medium, COLORS.medium);
    stack(d.high, COLORS.high);
    stack(d.critical, COLORS.critical);
  }
  doc.restore();
  doc.y = baseY + 4;
  doc
    .font('Helvetica')
    .fontSize(7.5)
    .fillColor(COLORS.muted)
    .text(
      sx(`${days[0].date}  →  ${days[days.length - 1].date}`),
      x,
      doc.y,
      { width: w, align: 'center' },
    );
  doc.moveDown(0.6);
}

function drawHeaderBand(doc: PDFKit.PDFDocument): void {
  doc.save();
  const w = doc.page.width;
  doc.rect(0, 0, w, 28).fillColor(COLORS.primary).fill();
  doc
    .fillColor('#ffffff')
    .font('Helvetica-Bold')
    .fontSize(10)
    .text('UASF', 44, 9, { lineBreak: false, width: 60, height: 14 });
  doc
    .font('Helvetica')
    .fontSize(8)
    .fillColor('#e0d6f4')
    .text('EASM Executive Summary', 80, 11, { lineBreak: false, width: 300, height: 14 });
  doc.restore();
}

function drawFooterBand(doc: PDFKit.PDFDocument, current: number, total: number): void {
  const w = doc.page.width;
  const h = doc.page.height;
  const y = h - 22;
  const x = 44;
  const fw = w - 88;
  doc.save();
  doc.moveTo(x, y - 5).lineTo(x + fw, y - 5).strokeColor(COLORS.rule).lineWidth(0.5).stroke();
  // CRITICAL: lineBreak:false + height to prevent PDFKit's auto pagination
  // when y is below the bottom margin.  Without this every footer call
  // creates a new page and the report blows up to 30+ pages.
  doc
    .fillColor(COLORS.muted)
    .font('Helvetica')
    .fontSize(7.5)
    .text(
      sx('UASF · EASM Executive Summary · approved attack surface only'),
      x,
      y,
      { width: fw * 0.7, align: 'left', lineBreak: false, height: 14 },
    );
  doc.text(`Page ${current} of ${total}`, x + fw * 0.7, y, {
    width: fw * 0.3,
    align: 'right',
    lineBreak: false,
    height: 14,
  });
  doc.restore();
}

function gradeColor(g: 'A' | 'B' | 'C' | 'D' | 'F'): string {
  switch (g) {
    case 'A':
      return COLORS.gradeA;
    case 'B':
      return COLORS.gradeB;
    case 'C':
      return COLORS.gradeC;
    case 'D':
      return COLORS.gradeD;
    case 'F':
      return COLORS.gradeF;
  }
}
