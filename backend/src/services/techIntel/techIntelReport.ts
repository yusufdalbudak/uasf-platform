/**
 * UASF Tech Intelligence — Report Renderer
 *
 * HTML and PDF rendering for a single Tech Intelligence run.  Both
 * formats use the same composed view-model so the dashboards, the HTML
 * report, and the PDF report all show the exact same numbers (no
 * recomputation drift).
 */

import PDFDocument from 'pdfkit';
import { sanitizeForPdf, sanitizePairs } from '../util/pdfSanitize';

/** Local short-name wrapper so every PDFKit text call routes through
 *  the WinAnsi-safe sanitizer.  Helvetica AFM throws on raw UTF-8
 *  glyphs that come back from server banners / advisory summaries. */
const sx = (v: unknown, fallback = ''): string => sanitizeForPdf(v, fallback);
import { TechIntelRun } from '../../db/models/TechIntelRun';
import { DetectedTechnology } from '../../db/models/DetectedTechnology';
import { VulnerabilityCorrelation } from '../../db/models/VulnerabilityCorrelation';

export interface TechIntelReportInput {
  run: TechIntelRun;
  technologies: DetectedTechnology[];
  correlations: VulnerabilityCorrelation[];
}

// ---------------------------------------------------------------
// HTML
// ---------------------------------------------------------------

export function renderTechIntelHtml(input: TechIntelReportInput): string {
  const { run, technologies, correlations } = input;
  const generatedAt = new Date().toUTCString();
  const techByCategory = groupBy(technologies, (t) => t.category);

  const correlationRowsHtml = correlations
    .map((c) => {
      const sevClass = `sev-${(c.severityLabel || 'Unknown').toLowerCase()}`;
      const cvss =
        c.severityScore !== null && c.severityScore !== undefined
          ? `<div class="cvss">CVSS ${c.severityScore.toFixed(1)}</div>`
          : '';
      const advisoryLink = c.sourceUrl
        ? `<a class="adv-link" href="${escapeAttr(c.sourceUrl)}" target="_blank" rel="noopener">${escapeHtml(c.advisoryId)}</a>`
        : escapeHtml(c.advisoryId);
      const cve = c.cveId ? ` <span class="muted">(${escapeHtml(c.cveId)})</span>` : '';
      return `
        <tr>
          <td><span class="sev ${sevClass}">${escapeHtml(c.severityLabel)}</span>${cvss}</td>
          <td>${advisoryLink}${cve}</td>
          <td>
            <div class="prod">${escapeHtml(c.productKey)}</div>
            <div class="muted small">detected: ${escapeHtml(c.detectedVersion ?? 'version unknown')}</div>
          </td>
          <td class="summary-cell">
            <div>${escapeHtml(c.summary)}</div>
            <div class="why"><strong>Why we matched:</strong> ${escapeHtml(c.certaintyLabel)}</div>
            ${
              c.affectedRanges
                ? `<div class="range"><strong>Affected:</strong> <code>${escapeHtml(c.affectedRanges)}</code></div>`
                : '<div class="range muted small">No structured affected range available — match relies on product-name evidence.</div>'
            }
          </td>
          <td>
            <span class="strength s-${c.strength}">${escapeHtml(c.strength.replace(/_/g, ' '))}</span>
          </td>
          <td><code>${escapeHtml(c.fixedVersions ?? '—')}</code></td>
          <td>${c.sourceUrl ? `<a href="${escapeAttr(c.sourceUrl)}" target="_blank" rel="noopener">${escapeHtml(c.source)}</a>` : escapeHtml(c.source)}</td>
        </tr>`;
    })
    .join('');

  // Group correlations by detected product so the audit-trail section
  // can render a per-technology proof block (evidence → advisories →
  // verdict).  Technologies with zero correlations are still listed so
  // the operator can see *why* nothing matched.
  const correlationsByProduct = groupBy(correlations, (c) => c.productKey);
  const auditBlocksHtml = technologies
    .map((tech) => {
      const matches = correlationsByProduct.get(tech.productKey) ?? [];
      const sortedMatches = matches
        .slice()
        .sort((a, b) => severityRank(b.severityLabel) - severityRank(a.severityLabel))
        .slice(0, 8);
      const evidence = (tech.evidence ?? [])
        .map((e) => {
          const { label, value } = splitEvidenceLabel(e.source, e.detail);
          return `<li><span class="ev-src">${escapeHtml(label)}</span> ${escapeHtml(value)}</li>`;
        })
        .join('');
      const matchList =
        sortedMatches.length === 0
          ? `<p class="muted small">No advisories matched this product. The cached feed (mycve + OSV) does not currently mention <code>${escapeHtml(tech.productName)}</code> with sufficient certainty.</p>`
          : `<ul class="audit-list">${sortedMatches
              .map(
                (c) => `
                <li class="audit-item">
                  <div class="audit-head">
                    <span class="sev sev-${(c.severityLabel || 'Unknown').toLowerCase()}">${escapeHtml(c.severityLabel)}</span>
                    <span class="strength s-${c.strength}">${escapeHtml(c.strength.replace(/_/g, ' '))}</span>
                    ${
                      c.sourceUrl
                        ? `<a href="${escapeAttr(c.sourceUrl)}" target="_blank" rel="noopener" class="audit-id">${escapeHtml(c.advisoryId)}</a>`
                        : `<span class="audit-id">${escapeHtml(c.advisoryId)}</span>`
                    }
                  </div>
                  <div class="audit-why">${escapeHtml(c.certaintyLabel)}</div>
                  ${
                    c.affectedRanges
                      ? `<div class="audit-range">Detected <code>${escapeHtml(tech.version ?? 'unknown')}</code> evaluated against affected range <code>${escapeHtml(c.affectedRanges)}</code></div>`
                      : ''
                  }
                </li>`,
              )
              .join('')}</ul>`;
      return `
        <article class="audit-block">
          <header class="audit-block-head">
            <div>
              <h3>${escapeHtml(tech.productName)} <span class="cf cf-${tech.confidence}">CF ${tech.confidence}</span></h3>
              <div class="audit-meta">
                version <b>${escapeHtml(tech.version ?? '—')}</b>
                · certainty <b class="vc-${tech.versionCertainty}">${escapeHtml(tech.versionCertainty)}</b>
                · ${matches.length} advisory match${matches.length === 1 ? '' : 'es'}
              </div>
            </div>
          </header>
          <div class="audit-evidence">
            <h4>Detection evidence</h4>
            ${evidence ? `<ul class="evidence">${evidence}</ul>` : '<p class="muted small">No evidence retained.</p>'}
          </div>
          <div class="audit-matches">
            <h4>Advisory matches</h4>
            ${matchList}
          </div>
        </article>`;
    })
    .join('');

  const techCardsHtml = Array.from(techByCategory.entries())
    .map(
      ([category, items]) => `
        <section class="tech-section">
          <h3>${escapeHtml(formatCategory(category))} <span class="count">${items.length}</span></h3>
          <div class="tech-grid">
            ${items.map(renderTechCardHtml).join('')}
          </div>
        </section>`,
    )
    .join('');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>UASF Tech Intelligence — ${escapeHtml(run.targetKey)}</title>
    <style>${CSS}</style>
  </head>
  <body>
    <header class="report-header">
      <div class="brand">
        <div class="brand-mark">UASF</div>
        <div>
          <div class="brand-title">Universal Attack Simulation Framework</div>
          <div class="brand-sub">Tech Intelligence — Fingerprint &amp; Vulnerability Correlation</div>
        </div>
      </div>
      <div class="header-meta">
        <div><strong>Run ID:</strong> ${escapeHtml(run.id)}</div>
        <div><strong>Generated:</strong> ${escapeHtml(generatedAt)}</div>
      </div>
    </header>

    <section class="summary">
      <h1>${escapeHtml(run.targetKey)}</h1>
      <div class="kv-grid">
        <div><span>Resolved hostname</span><b>${escapeHtml(run.resolvedHostname)}</b></div>
        <div><span>Profile</span><b>${escapeHtml(run.profileId)}</b></div>
        <div><span>Status</span><b class="status-${escapeHtml(run.status)}">${escapeHtml(run.status)}</b></div>
        <div><span>Duration</span><b>${run.durationMs} ms</b></div>
        <div><span>Detected technologies</span><b>${run.technologyCount}</b></div>
        <div><span>Advisory correlations</span><b>${run.correlationCount}</b></div>
        <div><span>High / Critical findings</span><b>${run.highOrCriticalCount}</b></div>
        <div><span>Run started</span><b>${escapeHtml(new Date(run.createdAt).toUTCString())}</b></div>
      </div>
      ${run.errorMessage ? `<p class="warn">Notes: ${escapeHtml(run.errorMessage)}</p>` : ''}
      ${renderExecutionTraceHtml(run.executionTrace)}
    </section>

    <section>
      <h2>Detected technologies</h2>
      ${technologies.length === 0 ? '<p class="muted">No technologies were detected for this run.</p>' : techCardsHtml}
    </section>

    <section>
      <h2>Vulnerability / advisory correlation</h2>
      <p class="legend">
        Each row is a single (technology, advisory) pair. The <em>Why we matched</em> line
        explains the reasoning the correlator used; <em>Affected</em> shows the structured
        version range from the source feed when available; <em>Match strength</em> ranks the
        proof from <code>confirmed_version_match</code> (highest) down to
        <code>text_match</code> (operator confirmation required).
      </p>
      ${
        correlations.length === 0
          ? '<p class="muted">No correlations were produced.  This means the cached advisory feed does not currently mention the detected products with sufficient certainty for matching.</p>'
          : `
          <table class="corr-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Advisory</th>
                <th>Product / version</th>
                <th>Summary &amp; reasoning</th>
                <th>Match strength</th>
                <th>Fixed in</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              ${correlationRowsHtml}
            </tbody>
          </table>`
      }
    </section>

    <section>
      <h2>Match audit trail</h2>
      <p class="legend">
        For each detected technology, this section shows the underlying detection
        evidence and the advisories that matched it. Use this view to verify the
        proof chain end-to-end: <em>fingerprint evidence → product/version → advisory
        match reasoning</em>.
      </p>
      ${technologies.length === 0 ? '<p class="muted">No technologies were detected for this run.</p>' : auditBlocksHtml}
    </section>

    <footer class="report-footer">
      <p>
        Generated by UASF — Universal Attack Simulation Framework.  Tech Intelligence runs are
        evidence-derived; correlations marked "ambiguous" or "text match" require operator
        confirmation before being treated as exploitable.
      </p>
    </footer>
  </body>
</html>`;
}

function renderTechCardHtml(tech: DetectedTechnology): string {
  const evidence = (tech.evidence ?? [])
    .map((e) => {
      const { label, value } = splitEvidenceLabel(e.source, e.detail);
      return `<li><span class="ev-src">${escapeHtml(label)}</span> ${escapeHtml(value)}</li>`;
    })
    .join('');
  return `
    <article class="tech-card cf-${tech.confidence}">
      <header>
        <h4>${escapeHtml(tech.productName)}</h4>
        <span class="cat">${escapeHtml(formatCategory(tech.category))}</span>
        <span class="cf cf-${tech.confidence}">CF ${tech.confidence}</span>
      </header>
      <div class="kv">
        <div><span>Vendor</span><b>${escapeHtml(tech.vendor ?? '—')}</b></div>
        <div><span>Version</span><b>${escapeHtml(tech.version ?? '—')}</b></div>
        <div><span>Family</span><b>${escapeHtml(tech.versionFamily ?? '—')}</b></div>
        <div><span>Version certainty</span><b class="vc-${tech.versionCertainty}">${escapeHtml(tech.versionCertainty)}</b></div>
      </div>
      ${evidence ? `<ul class="evidence">${evidence}</ul>` : '<p class="muted">No evidence retained.</p>'}
      <p class="evidence-note">Evidence above is the verbatim signal the fingerprint engine used to assert this technology — it is also what the audit trail below cross-references when matching advisories.</p>
    </article>`;
}

const CSS = `
  :root { color-scheme: light; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f4f6; color: #111827; }
  .report-header { background: linear-gradient(135deg, #4d1c8c, #8e51df); color: white; padding: 24px 40px; display: flex; justify-content: space-between; align-items: center; }
  .brand { display: flex; gap: 16px; align-items: center; }
  .brand-mark { width: 48px; height: 48px; border-radius: 8px; background: rgba(255,255,255,0.18); display: flex; align-items: center; justify-content: center; font-weight: 800; letter-spacing: 0.1em; }
  .brand-title { font-weight: 700; font-size: 16px; }
  .brand-sub { font-size: 12px; opacity: 0.85; letter-spacing: 0.05em; }
  .header-meta { font-size: 11px; text-align: right; opacity: 0.9; }
  section { margin: 24px 40px; padding: 24px; background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; }
  section h1 { margin: 0 0 16px; font-size: 22px; }
  section h2 { margin: 0 0 16px; font-size: 16px; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }
  section h3 { margin: 16px 0 8px; font-size: 14px; color: #4d1c8c; }
  .kv-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px 24px; }
  .kv-grid > div { display: flex; flex-direction: column; font-size: 13px; }
  .kv-grid span { color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  .kv-grid b { font-weight: 600; word-break: break-word; }
  .status-completed { color: #047857; }
  .status-partial { color: #a16207; }
  .status-failed { color: #b91c1c; }
  .tech-section { border-top: 1px dashed #e5e7eb; padding-top: 8px; }
  .tech-section h3 .count { background: #ede9fe; color: #4d1c8c; font-size: 11px; padding: 2px 8px; border-radius: 999px; margin-left: 6px; }
  .tech-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
  .tech-card { border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; background: #fafafa; }
  .tech-card header { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
  .tech-card h4 { margin: 0; font-size: 14px; }
  .tech-card .cat { font-size: 10px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.06em; }
  .tech-card .cf { font-size: 10px; padding: 2px 8px; border-radius: 999px; font-weight: 700; }
  .cf-very_high { background: #ecfdf5; color: #047857; }
  .cf-high { background: #ecfdf5; color: #047857; }
  .cf-medium { background: #fefce8; color: #a16207; }
  .cf-low { background: #f3f4f6; color: #6b7280; }
  .vc-exact { color: #047857; font-weight: 700; }
  .vc-probable { color: #a16207; font-weight: 700; }
  .vc-family { color: #1d4ed8; font-weight: 700; }
  .vc-unknown { color: #6b7280; font-weight: 700; }
  .tech-card .kv { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px 12px; font-size: 12px; }
  .tech-card .kv span { color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
  .evidence { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; line-height: 1.5; margin-top: 10px; padding-left: 16px; color: #374151; }
  .evidence .ev-src { display: inline-block; min-width: 70px; color: #4d1c8c; font-weight: 700; }
  .evidence-note { font-size: 10px; color: #6b7280; margin: 8px 0 0; line-height: 1.5; font-style: italic; }
  .legend { font-size: 12px; color: #4b5563; margin: -4px 0 14px; line-height: 1.5; }
  .legend code { background: #f5f3ff; color: #4d1c8c; padding: 1px 6px; border-radius: 4px; font-size: 11px; }
  .corr-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .corr-table th, .corr-table td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  .corr-table th { background: #faf5ff; color: #4d1c8c; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  .corr-table .summary-cell { max-width: 360px; }
  .corr-table .why { margin-top: 6px; font-size: 11px; color: #374151; background: #fafaff; border-left: 3px solid #c4b5fd; padding: 4px 8px; border-radius: 0 6px 6px 0; }
  .corr-table .why strong { color: #4d1c8c; }
  .corr-table .range { margin-top: 4px; font-size: 11px; color: #374151; }
  .corr-table .range code { background: #f3f4f6; padding: 1px 6px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .corr-table .small { font-size: 11px; }
  .corr-table .prod { font-weight: 600; color: #111827; }
  .corr-table .cvss { font-size: 10px; color: #6b7280; margin-top: 4px; }
  .corr-table .adv-link { color: #4d1c8c; text-decoration: none; font-weight: 600; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .corr-table .adv-link:hover { text-decoration: underline; }
  .audit-block { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; margin-bottom: 16px; background: linear-gradient(180deg, #ffffff, #fafaff); }
  .audit-block-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
  .audit-block-head h3 { margin: 0; font-size: 14px; color: #111827; display: flex; align-items: center; gap: 8px; }
  .audit-meta { font-size: 11px; color: #6b7280; margin-top: 4px; }
  .audit-meta b { color: #111827; }
  .audit-evidence h4, .audit-matches h4 { margin: 8px 0 4px; font-size: 11px; color: #4d1c8c; text-transform: uppercase; letter-spacing: 0.06em; }
  .audit-list { list-style: none; padding: 0; margin: 0; }
  .audit-item { padding: 8px 10px; border-left: 3px solid #ede9fe; margin: 4px 0; background: #fcfcfd; border-radius: 0 8px 8px 0; }
  .audit-head { display: flex; gap: 8px; align-items: center; margin-bottom: 4px; flex-wrap: wrap; }
  .audit-id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; color: #4d1c8c; font-weight: 700; text-decoration: none; }
  .audit-id:hover { text-decoration: underline; }
  .audit-why { font-size: 11px; color: #374151; line-height: 1.5; }
  .audit-range { font-size: 11px; color: #4b5563; margin-top: 4px; }
  .audit-range code { background: #f3f4f6; padding: 1px 6px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 10px; }
  .sev { padding: 2px 10px; border-radius: 999px; font-weight: 700; font-size: 10px; }
  .sev-critical { background: #fef2f2; color: #b91c1c; }
  .sev-high { background: #fff7ed; color: #c2410c; }
  .sev-medium { background: #fefce8; color: #a16207; }
  .sev-low { background: #eff6ff; color: #1d4ed8; }
  .sev-unknown { background: #f3f4f6; color: #6b7280; }
  .strength { font-size: 10px; padding: 2px 8px; border-radius: 999px; }
  .s-confirmed_version_match { background: #fef2f2; color: #b91c1c; }
  .s-probable_version_match { background: #fff7ed; color: #c2410c; }
  .s-product_match_version_ambiguous { background: #fefce8; color: #a16207; }
  .s-text_match { background: #f3f4f6; color: #374151; }
  .muted { color: #6b7280; font-style: italic; }
  .warn { color: #a16207; background: #fefce8; border: 1px solid #fde68a; padding: 8px 12px; border-radius: 8px; font-size: 12px; margin-top: 12px; }
  .report-footer { margin: 24px 40px 40px; font-size: 11px; color: #6b7280; text-align: center; }
  .trace { margin-top: 14px; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 12px; background: #fafbff; }
  .trace-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #4b5563; margin-bottom: 6px; }
  .trace-row { font-size: 12px; color: #374151; margin: 4px 0; display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  .trace-row.warn-row { color: #b91c1c; }
  .trace-row span { color: #6b7280; }
  .trace-row b { font-weight: 600; }
  .trace-row b.ok { color: #047857; }
  .trace-row b.mute { color: #6b7280; }
  .probe { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-family: SFMono-Regular, Menlo, Consolas, monospace; }
  .probe.ok { background: #ecfdf5; border: 1px solid #6ee7b7; color: #065f46; }
  .probe.warn { background: #fefce8; border: 1px solid #fde68a; color: #854d0e; }
  .probe.bad { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
  .trace details { margin-top: 4px; font-size: 12px; color: #4b5563; }
  .trace details ul { margin: 4px 0 0; padding-left: 18px; }
`;

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(value: unknown): string {
  return escapeHtml(value);
}

/**
 * Renders the orchestrator's profile→backend execution trace into the HTML
 * report so an operator reading the export (not just the live UI) can
 * verify which probes the run actually fired.
 */
function renderExecutionTraceHtml(trace: TechIntelRun['executionTrace']): string {
  if (!trace) return '';
  const declared = new Set(trace.declaredProbes);
  const executed = new Set(trace.executedProbes);
  const skipped = trace.declaredProbes.filter((p) => !executed.has(p));
  const stray = trace.executedProbes.filter((p) => !declared.has(p));
  const tag = (probes: string[], cls: string) =>
    probes.length === 0
      ? '<span class="muted">none</span>'
      : probes.map((p) => `<code class="probe ${cls}">${escapeHtml(p)}</code>`).join(' ');
  const errorList =
    trace.probeErrors.length === 0
      ? ''
      : `<details><summary>Probe-level diagnostics (${trace.probeErrors.length})</summary><ul>${trace.probeErrors
          .map((e) => `<li><code>${escapeHtml(e)}</code></li>`)
          .join('')}</ul></details>`;
  return `
    <div class="trace">
      <div class="trace-title">Execution trace (profile → backend integrity)</div>
      <div class="trace-row">
        <span>HTTP:</span><b class="${trace.httpProbed ? 'ok' : 'mute'}">${trace.httpProbed ? 'fired' : 'not used'}</b>
        <span>TLS:</span><b class="${trace.tlsProbed ? 'ok' : 'mute'}">${trace.tlsProbed ? 'fired' : 'not used'}</b>
        <span>Nmap:</span><b class="${trace.nmapProbed ? 'ok' : 'mute'}">${trace.nmapProbed ? 'fired' : 'not used'}</b>
      </div>
      <div class="trace-row"><span>Executed (${trace.executedProbes.length}):</span>${tag(trace.executedProbes, 'ok')}</div>
      ${
        skipped.length > 0
          ? `<div class="trace-row"><span>Declared but not executed:</span>${tag(skipped, 'warn')}</div>`
          : ''
      }
      ${
        stray.length > 0
          ? `<div class="trace-row warn-row"><span>Engine integrity warning — executed but not declared:</span>${tag(stray, 'bad')}</div>`
          : ''
      }
      ${errorList}
    </div>`;
}

function formatCategory(c: string): string {
  return c.replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
}

/**
 * Header / cookie evidence rows are emitted by the engine as
 * `field: value` strings (e.g. `via: 1.1 …cloudfront.net`).  When we
 * only show the generic source ("header") two distinct rows render with
 * an identical-looking prefix, leaving operators uncertain whether they
 * are reading two converging signals or the same signal duplicated.
 * Pulling the field name into the visible label removes that ambiguity
 * for both the HTML report and the PDF.
 */
function splitEvidenceLabel(
  source: string,
  detail: string,
): { label: string; value: string } {
  const colon = detail.indexOf(':');
  if (colon > 0 && colon < 80 && (source === 'header' || source === 'cookie' || source === 'banner')) {
    const field = detail.slice(0, colon).trim();
    const value = detail.slice(colon + 1).trim();
    if (field && value) return { label: `${source} · ${field}`, value };
  }
  return { label: source, value: detail };
}

function severityRank(label: string): number {
  switch ((label ?? '').toLowerCase()) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    case 'low':
      return 1;
    default:
      return 0;
  }
}

function groupBy<T, K>(items: T[], keyFn: (item: T) => K): Map<K, T[]> {
  const out = new Map<K, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    const list = out.get(key) ?? [];
    list.push(item);
    out.set(key, list);
  }
  return out;
}

// ---------------------------------------------------------------
// PDF
// ---------------------------------------------------------------

const COLORS = {
  primary: '#4d1c8c',
  ink: '#111827',
  muted: '#6b7280',
  rule: '#e5e7eb',
  bandBg: '#f5f3ff',
  zebra: '#f9fafb',
  critical: '#b91c1c',
  high: '#c2410c',
  medium: '#a16207',
  low: '#1d4ed8',
  ok: '#047857',
};

export function renderTechIntelPdf(input: TechIntelReportInput): Promise<Buffer> {
  const { run, technologies, correlations } = input;
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        // Tighter margins keep the header/footer comfortable while
        // gaining ~80pt usable height per page.
        margins: { top: 58, bottom: 48, left: 44, right: 44 },
        bufferPages: true,
        info: {
          Title: sx(`UASF Tech Intelligence - ${run.targetKey}`, 'UASF Tech Intelligence'),
          Subject: 'UASF Tech Intelligence Report',
          Author: 'UASF',
          Producer: 'UASF Report Engine',
        },
      });

      const chunks: Buffer[] = [];
      doc.on('data', (chunk: Buffer) => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      writePdf(doc, run, technologies, correlations);

      const range = doc.bufferedPageRange();
      for (let i = 0; i < range.count; i += 1) {
        doc.switchToPage(range.start + i);
        drawHeaderBand(doc, run);
        drawFooterBand(doc, run, i + 1, range.count);
      }
      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

function writePdf(
  doc: PDFKit.PDFDocument,
  run: TechIntelRun,
  technologies: DetectedTechnology[],
  correlations: VulnerabilityCorrelation[],
): void {
  doc.font('Helvetica').fillColor(COLORS.ink).fontSize(16).font('Helvetica-Bold')
    .text(sx(`UASF Tech Intelligence - ${run.targetKey}`));
  doc.moveDown(0.1)
    .font('Helvetica').fontSize(8.5).fillColor(COLORS.muted)
    .text(sx(`Run ${run.id}  ·  ${run.profileId.toUpperCase()}  ·  Status ${run.status.toUpperCase()}  ·  Generated ${new Date().toUTCString()}`));
  doc.moveDown(0.5);

  sectionTitle(doc, 'Executive summary');
  drawKv(doc, sanitizePairs([
    ['Target key', run.targetKey],
    ['Resolved hostname', run.resolvedHostname],
    ['Profile', run.profileId],
    ['Duration', `${run.durationMs} ms`],
    ['Detected technologies', String(run.technologyCount)],
    ['Advisory correlations', String(run.correlationCount)],
    ['High / Critical correlations', String(run.highOrCriticalCount)],
    ['Run started', new Date(run.createdAt).toUTCString()],
  ]));
  doc.moveDown(0.3);

  if (run.executionTrace) {
    sectionTitle(doc, 'Execution trace (profile -> backend integrity)');
    const t = run.executionTrace;
    drawKv(doc, sanitizePairs([
      ['HTTP probes', t.httpProbed ? 'fired' : 'not used'],
      ['TLS probes', t.tlsProbed ? 'fired' : 'not used'],
      ['Nmap probes', t.nmapProbed ? 'fired' : 'not used'],
      ['Declared probes', t.declaredProbes.join(', ') || '-'],
      ['Executed probes', t.executedProbes.join(', ') || 'none'],
      ['Probe-level errors', String(t.probeErrors.length)],
    ]));
    if (t.probeErrors.length > 0) {
      doc.font('Helvetica-Oblique').fontSize(8).fillColor(COLORS.muted)
        .text(sx(t.probeErrors.slice(0, 6).join('  ·  ')), {
          width: doc.page.width - doc.page.margins.left - doc.page.margins.right,
          lineGap: 0.5,
        });
    }
    doc.moveDown(0.3);
  }

  sectionTitle(doc, `Detected technologies (${technologies.length})`);
  if (technologies.length === 0) {
    doc.font('Helvetica-Oblique').fontSize(9).fillColor(COLORS.muted)
      .text('No technologies were detected.');
  } else {
    for (const tech of technologies) {
      try {
        drawTechRow(doc, tech);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('[techIntelReport] skipped corrupt tech row', err);
      }
    }
  }
  doc.moveDown(0.4);

  sectionTitle(doc, `Vulnerability / advisory correlations (${correlations.length})`);
  if (correlations.length === 0) {
    doc.font('Helvetica-Oblique').fontSize(9).fillColor(COLORS.muted)
      .text('No correlations were produced for the detected technologies.');
  } else {
    drawCorrelationTable(doc, correlations);
  }
}

function sectionTitle(doc: PDFKit.PDFDocument, label: string): void {
  ensureSpace(doc, 30);
  const x = doc.page.margins.left;
  doc.font('Helvetica-Bold').fontSize(11).fillColor(COLORS.primary).text(sx(label), x, doc.y);
  doc.moveDown(0.1);
  doc.moveTo(x, doc.y).lineTo(doc.page.width - doc.page.margins.right, doc.y)
    .strokeColor(COLORS.rule).lineWidth(0.5).stroke();
  doc.moveDown(0.2);
}

function drawKv(doc: PDFKit.PDFDocument, pairs: Array<[string, string]>): void {
  const x = doc.page.margins.left;
  const colWidth = (doc.page.width - x - doc.page.margins.right) / 2;
  let y = doc.y;
  // 22pt row stride (was 28pt) — three KV rows per page-third instead
  // of two, without sacrificing legibility.
  const rowStride = 22;
  for (let i = 0; i < pairs.length; i += 1) {
    const [k, v] = pairs[i];
    const col = i % 2;
    if (col === 0 && i !== 0) y += rowStride;
    if (y + rowStride > doc.page.height - doc.page.margins.bottom - 20) {
      doc.addPage();
      y = doc.y;
    }
    const cellX = x + col * colWidth;
    doc.font('Helvetica').fontSize(7).fillColor(COLORS.muted)
      .text(sx(k).toUpperCase(), cellX, y, { characterSpacing: 0.5 });
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.ink)
      .text(sx(v, '-'), cellX, y + 9, { width: colWidth - 8, ellipsis: true });
  }
  doc.y = y + rowStride;
}

function drawTechRow(doc: PDFKit.PDFDocument, tech: DetectedTechnology): void {
  // Compact 3-line tech card: title row, meta row, version row.
  // Was 64pt tall — now 38pt.
  const cardHeight = 38;
  ensureSpace(doc, cardHeight + 4);
  const x = doc.page.margins.left;
  const w = doc.page.width - x - doc.page.margins.right;
  const top = doc.y;
  doc.rect(x, top, w, cardHeight).fillColor(COLORS.zebra).fill();
  doc.fillColor(COLORS.ink).font('Helvetica-Bold').fontSize(10)
    .text(sx(tech.productName, 'unknown product'), x + 8, top + 4, { width: w - 16, ellipsis: true });
  doc.font('Helvetica').fontSize(8).fillColor(COLORS.muted)
    .text(sx(`${tech.category.replace(/_/g, ' ')}  ·  ${tech.vendor ?? '-'}`), x + 8, top + 16, {
      width: w - 16,
      ellipsis: true,
    });
  const detail = `Version: ${tech.version ?? '-'}  ·  Family: ${tech.versionFamily ?? '-'}  ·  Certainty: ${tech.versionCertainty}  ·  Confidence: ${tech.confidence}`;
  doc.font('Helvetica').fontSize(8).fillColor(COLORS.ink)
    .text(sx(detail), x + 8, top + 26, { width: w - 16, ellipsis: true });
  doc.y = top + cardHeight + 2;
}

function drawCorrelationTable(doc: PDFKit.PDFDocument, correlations: VulnerabilityCorrelation[]): void {
  const x = doc.page.margins.left;
  const w = doc.page.width - x - doc.page.margins.right;

  // Compact 4-line correlation block — each one is ~52pt instead of
  // the previous ~80pt, which roughly halves the page count when a
  // run produces many advisories.
  for (let i = 0; i < correlations.length; i += 1) {
    const c = correlations[i];
    try {
      const blockHeight = 52;
      ensureSpace(doc, blockHeight + 2);

      const top = doc.y;
      const sevColor = severityToColor(c.severityLabel ?? 'info');

      // Severity rail
      doc.rect(x, top, 3, blockHeight - 4).fillColor(sevColor).fill();

      // Header line: SEV  ·  Advisory  ·  Strength
      const advisoryId = sx(c.advisoryId ?? 'advisory');
      const cveSuffix = c.cveId && c.cveId !== c.advisoryId ? ` (${sx(c.cveId)})` : '';
      const strength = sx((c.strength ?? '').replace(/_/g, ' '));
      const headerLine = `${sx(c.severityLabel ?? 'info').toUpperCase()}  ·  ${advisoryId}${cveSuffix}  ·  ${strength}`;
      doc.fillColor(sevColor).font('Helvetica-Bold').fontSize(9)
        .text(headerLine, x + 10, top + 2, { width: w - 14, ellipsis: true });

      // CVSS + product + version line
      const cvssPart = c.severityScore !== null && c.severityScore !== undefined
        ? `CVSS ${Number(c.severityScore).toFixed(1)}  ·  `
        : '';
      doc.fillColor(COLORS.muted).font('Helvetica').fontSize(7.5)
        .text(
          sx(`${cvssPart}${c.productKey ?? '-'}  ·  detected: ${c.detectedVersion ?? 'version unknown'}`),
          x + 10,
          top + 14,
          { width: w - 14, ellipsis: true },
        );

      // Summary — single-line ellipsis so the block stays compact.
      doc.fillColor(COLORS.ink).font('Helvetica').fontSize(8)
        .text(sx(c.summary, '(no summary)'), x + 10, top + 25, {
          width: w - 14,
          ellipsis: true,
          height: 11,
        });

      // Why we matched + affected/fixed range — packed onto one line
      // when both fit, otherwise wrapped tightly.
      const proofParts: string[] = [];
      proofParts.push(`Why: ${sx(c.certaintyLabel ?? 'n/a')}`);
      if (c.affectedRanges) proofParts.push(`Affected: ${sx(c.affectedRanges)}`);
      if (c.fixedVersions) proofParts.push(`Fixed: ${sx(c.fixedVersions)}`);
      doc.fillColor('#4d1c8c').font('Helvetica-Oblique').fontSize(7)
        .text(proofParts.join('  ·  '), x + 10, top + 38, {
          width: w - 14,
          ellipsis: true,
          height: 10,
        });

      // Hairline separator
      doc.y = top + blockHeight - 2;
      doc.moveTo(x, doc.y).lineTo(x + w, doc.y).strokeColor(COLORS.rule).lineWidth(0.3).stroke();
      doc.y += 3;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn('[techIntelReport] skipped corrupt correlation row', i, err);
    }
  }
}

function severityToColor(label: string): string {
  switch (label.toLowerCase()) {
    case 'critical':
      return COLORS.critical;
    case 'high':
      return COLORS.high;
    case 'medium':
      return COLORS.medium;
    case 'low':
      return COLORS.low;
    default:
      return COLORS.muted;
  }
}

function drawHeaderBand(doc: PDFKit.PDFDocument, run: TechIntelRun): void {
  const w = doc.page.width;
  doc.save();
  // Tighter band — matches reportService for visual consistency.
  // Every text() uses { lineBreak: false, height } so PDFKit will not
  // auto-flow into a new page when called from the bufferedPageRange loop
  // (otherwise each footer pass appends a blank page — same bug we hit
  // on the EASM report and the Discovery/Assessment report).
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
    .text(sx(run.targetKey), 0, 14, {
      width: w - 44,
      align: 'right',
      lineBreak: false,
      height: 14,
    });
  doc.fontSize(7).text(
    sx(`TECH INTEL · ${run.profileId}`).toUpperCase(),
    0,
    25,
    {
      width: w - 44,
      align: 'right',
      characterSpacing: 0.6,
      lineBreak: false,
      height: 12,
    },
  );
  doc.restore();
}

function drawFooterBand(doc: PDFKit.PDFDocument, run: TechIntelRun, current: number, total: number): void {
  const w = doc.page.width;
  const h = doc.page.height;
  const y = h - 24;
  const x = 44;
  const fw = w - 88;
  doc.save();
  doc.moveTo(x, y - 5).lineTo(x + fw, y - 5).strokeColor(COLORS.rule).lineWidth(0.5).stroke();
  doc.fillColor(COLORS.muted).font('Helvetica').fontSize(7);
  doc.text(
    sx(`UASF · Tech Intel · Run ${run.id.slice(0, 8)}  ·  ${run.targetKey}`),
    x,
    y,
    { width: fw * 0.6, align: 'left', lineBreak: false, height: 12 },
  );
  doc.text(`Page ${current} of ${total}`, x + fw * 0.6, y, {
    width: fw * 0.4,
    align: 'right',
    lineBreak: false,
    height: 12,
  });
  doc.restore();
}

function ensureSpace(doc: PDFKit.PDFDocument, needed: number): void {
  // Footer band reserves ~28pt; respect that to avoid stomping it.
  if (doc.y + needed > doc.page.height - doc.page.margins.bottom - 14) {
    doc.addPage();
  }
}
