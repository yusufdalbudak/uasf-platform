/**
 * PDFKit (Helvetica AFM, the built-in font we use for both report PDFs)
 * supports the WinAnsi encoding only — roughly Latin-1 plus the few
 * pretty-printing slots in 0x80–0x9F (em dash 0x97, bullet 0x95, etc.).
 *
 * If `doc.text(...)` is called with a string containing characters
 * outside that range — common offenders: CJK in scanned banner text,
 * curly quotes copied from documentation, mathematical symbols in JS
 * library names, NUL bytes inside a binary response that survived UTF-8
 * decoding — pdfkit throws synchronously.  The throw escapes the
 * `doc.on('end')` chain in our render functions (`renderReportPdf` /
 * `renderTechIntelPdf`), the route handler turns it into a `500 JSON
 * {"error":"Failed to render PDF"}` response, and any frontend that
 * had already kicked off `window.open(...)` saves that JSON to disk
 * with a `.pdf` extension — which is exactly the "corrupted PDF
 * report" symptom operators have been seeing.
 *
 * `sanitizeForPdf` makes every string PDFKit-safe up front:
 *
 *   - coerces non-strings to strings
 *   - removes ASCII control bytes (except \t / \n) and DEL
 *   - normalises curly quotes, en/em/figure dashes, ellipsis,
 *     non-breaking space, common bullet glyphs to plain ASCII
 *     equivalents — so the PDF renders the same regardless of which
 *     reader the operator opens it in
 *   - replaces every remaining codepoint above 0xFF (CJK, accented
 *     forms outside Latin-1, emoji, mathematical symbols, ...) with
 *     "?" so PDFKit never sees a glyph it can't encode
 *   - clamps absurdly long lines so a single 50KB JSON-encoded blob
 *     in an evidence string can't blow out the page layout
 *
 * The function is intentionally idempotent — calling it twice on the
 * same string returns the same result.
 */

const MAX_PDF_TEXT_LEN = 4000;

/** Replacement table for common Unicode punctuation that exists in
 *  WinAnsi but renders inconsistently across PDF readers; flattening
 *  to ASCII gives us deterministic output everywhere. */
const PUNCT_REPLACE: Array<[RegExp, string]> = [
  // Curly single / double quotes -> straight ASCII quotes
  [/[\u2018\u2019\u201A\u201B]/g, "'"],
  [/[\u201C\u201D\u201E\u201F]/g, '"'],
  // En/em/figure/horizontal-bar dashes -> plain hyphen-minus.  The
  // built-in title strings deliberately use " — " and we want that to
  // come through as " - " in the PDF rather than risk the WinAnsi
  // 0x97 substitution producing a missing-glyph slot in some readers.
  [/[\u2013\u2014\u2015\u2212]/g, '-'],
  // Horizontal ellipsis -> "..."
  [/\u2026/g, '...'],
  // Non-breaking / zero-width / narrow-no-break spaces -> regular space
  [/[\u00A0\u202F\u2007\u2009\u200A]/g, ' '],
  // Zero-width characters -> drop entirely
  [/[\u200B\u200C\u200D\uFEFF]/g, ''],
  // Common bullet glyphs -> "*"
  [/[\u2022\u25CF\u25E6\u2043\u2219]/g, '*'],
  // Heavy / triangular bullets and arrows used in some banner pages
  [/[\u2192\u279C\u27A4\u2794]/g, '->'],
  // Middle dot (U+00B7) is in WinAnsi (0xB7) — keep it as-is.
];

export function sanitizeForPdf(input: unknown, fallback = ''): string {
  if (input === null || input === undefined) return fallback;
  let s: string;
  try {
    s = typeof input === 'string' ? input : String(input);
  } catch {
    return fallback;
  }
  if (!s) return fallback;

  // 1. strip C0 control chars except \t / \n, and DEL
  s = s.replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '');

  // 2. normalise punctuation before the WinAnsi range check so we keep
  //    the visual intent (quotes, dashes, ellipsis) rather than ?-out.
  for (const [re, repl] of PUNCT_REPLACE) {
    s = s.replace(re, repl);
  }

  // 3. any remaining codepoint outside Latin-1 (0x00-0xFF) becomes "?"
  //    The 0x80-0x9F slot is fine — Helvetica WinAnsi has glyphs
  //    there (e.g. 0x95 bullet, 0x97 em dash) and PDFKit handles them.
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp <= 0xff) {
      out += ch;
    } else {
      out += '?';
    }
  }

  // 4. clamp absurdly long single lines that would otherwise overflow
  //    the page-flow estimator and cause runaway pagination
  if (out.length > MAX_PDF_TEXT_LEN) {
    out = `${out.slice(0, MAX_PDF_TEXT_LEN - 8)} [...trim]`;
  }

  return out;
}

/** Sanitise an entire `[label, value]` pair list at once. */
export function sanitizePairs(
  pairs: Array<[string, unknown]>,
): Array<[string, string]> {
  return pairs.map(([k, v]) => [sanitizeForPdf(k), sanitizeForPdf(v, '-')]);
}
