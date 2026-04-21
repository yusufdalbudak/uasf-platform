import { AppDataSource } from '../db/connection';
import { DependencyVulnerability } from '../db/models/DependencyVulnerability';

/**
 * Periodic ingestion of public CVE intelligence from the community
 * "MyCVE" tracker (https://mycve.com/).
 *
 * MyCVE renders a paginated, server-side HTML feed at
 *   https://mycve.com/vulnerability/index?page=N
 * (10 cards per page) and exposes per-CVE detail pages at
 *   https://mycve.com/vulnerability/detail/<CVE-ID>/
 *
 * There is no public REST/JSON API, so we parse a small, well-defined
 * subset of the listing markup. Each card looks like:
 *
 *   <h1 class="severity-score text-severity-{level}">SCORE</h1>
 *   <div class="text-muted small">CVSS{2.0|3.0|3.1|4.0}</div>
 *   <a href="/vulnerability/detail/CVE-XXXX-XXXX/" class="text-secondary">
 *     <h3>CVE-XXXX-XXXX - TITLE</h3>
 *   </a>
 *   <p class="mb-4">DESCRIPTION (truncated by source)</p>
 *   <span>📅 Published: Month DD, YYYY, h:mm a.m./p.m.</span>
 *   <span>🔄 Last Modified: Month DD, YYYY, h:mm a.m./p.m.</span>
 *
 * We deliberately scrape ONLY the listing pages (cheap; ~25 requests
 * per refresh) and link the card's "Learn more" action to the MyCVE
 * detail page so the operator can see full descriptions, references,
 * and CVSS vectors without us hammering the source.
 *
 * Pipeline guarantees:
 *   - Idempotent: re-ingesting the same CVE updates the existing row.
 *   - Never throws: per-record / per-page failures are aggregated into
 *     the returned IngestSummary so one bad card or a transient network
 *     error never stalls the schedule.
 */

interface ParsedCard {
  cveId: string;
  title: string;
  description: string;
  severityLabel: string;
  severityScore: number | null;
  cvssVersion: string | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
  detailUrl: string;
}

const MYCVE_BASE = 'https://mycve.com';
const MYCVE_INDEX = `${MYCVE_BASE}/vulnerability/index`;
const MYCVE_DETAIL = `${MYCVE_BASE}/vulnerability/detail`;
const RESULTS_PER_PAGE = 10; // mycve.com pagination is fixed at 10 / page
const MAX_PAGES_PER_REFRESH = 25; // 25 * 10 = 250 newest CVEs / refresh
const PAGE_DELAY_MS = 1_500; // be polite — mycve is a small community site
const REQUEST_TIMEOUT_MS = 30_000;
const ECOSYSTEM_LABEL = 'CVE'; // listing endpoint does not expose ecosystem

const CARD_SPLIT_RE = /<div class="card mb-4">/g;

function decodeHtmlEntities(input: string): string {
  if (!input) return '';
  return input
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ');
}

function stripTags(input: string): string {
  return decodeHtmlEntities(input.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
}

function normalizeSeverityLabel(level: string | null, score: number | null): string {
  const lower = (level ?? '').toLowerCase();
  if (lower === 'critical') return 'Critical';
  if (lower === 'high') return 'High';
  if (lower === 'medium' || lower === 'moderate') return 'Medium';
  if (lower === 'low') return 'Low';
  if (typeof score === 'number' && score > 0) {
    if (score >= 9) return 'Critical';
    if (score >= 7) return 'High';
    if (score >= 4) return 'Medium';
    return 'Low';
  }
  return 'Unknown';
}

/**
 * mycve.com renders dates using Django's `naturaltime`-adjacent formatter, e.g.:
 *   "April 18, 2026, 4:18 p.m."
 *   "April 18, 2026, 11:16 a.m."
 *   "April 17, 2026, midnight"   ← maps to 12:00 AM that day
 *   "April 17, 2026, noon"       ← maps to 12:00 PM that day
 *
 * `Date` cannot parse "p.m." / "midnight" / "noon" natively, so normalize first.
 */
function parseMyCveDate(raw: string | null): Date | null {
  if (!raw) return null;
  let cleaned = raw.replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim();
  // "midnight" → "12:00 AM"; "noon" → "12:00 PM"
  cleaned = cleaned
    .replace(/,\s*midnight$/i, ', 12:00 AM')
    .replace(/,\s*noon$/i, ', 12:00 PM')
    // "p.m." / "a.m." (with or without trailing dot) → "PM" / "AM"
    .replace(/\b([ap])\.m\.?$/i, (_, ap) => `${ap.toUpperCase()}M`);
  // mycve drops the ":00" for on-the-hour times, so we get "2 PM" / "11 PM".
  // V8's Date parser rejects that — pad the minutes back in.
  cleaned = cleaned.replace(/(,\s*)(\d{1,2})\s+(AM|PM)$/i, (_, sep, h, ap) => `${sep}${h}:00 ${ap.toUpperCase()}`);
  const direct = new Date(cleaned);
  if (!Number.isNaN(direct.getTime())) return direct;
  return null;
}

/**
 * Extract a coarse semver-like version range from a CVE summary or
 * description sentence.  The mycve.com feed (and the underlying NVD
 * descriptions it mirrors) is unstructured prose, so we run a small
 * battery of conservative regex patterns over the text.  Anything we
 * cannot confidently extract is returned as null — the correlator
 * downgrades to `text_match` in that case rather than fabricating a
 * range claim.
 *
 * Output format is intentionally aligned with `vulnerabilityCorrelator`'s
 * `isVersionInAnyRange()` parser:
 *   - single bound      → "<2.4.1" / "<=2.4.1"
 *   - bounded range     → ">=2.0.0 <2.4.1"
 *   - multiple clauses  → joined with ";", each clause is one of the above
 */
export function extractAffectedRangesFromText(text: string): string | null {
  if (!text) return null;
  // Operate on the first ~600 chars so we don't accidentally pick up
  // version strings from a "References" tail block.
  let haystack = text.slice(0, 600);
  const ranges: string[] = [];

  const v = '(\\d+(?:\\.\\d+){1,3})';

  // 1) Bounded ranges first.  We match-and-consume so the single-bound
  //    patterns below don't double-emit.
  const boundedPatterns: RegExp[] = [
    // "from X.Y.Z up to (and including)? A.B.C" / "between X and Y"
    new RegExp(
      `(?:from|between|versions?\\s+from)\\s+${v}\\s+(?:up\\s+to|to|and|through|thru)\\s+(?:and\\s+including\\s+)?${v}`,
      'gi',
    ),
    // "X.Y.Z through A.B.C" / "X.Y.Z to A.B.C"
    new RegExp(`${v}\\s+(?:through|thru|to)\\s+${v}`, 'gi'),
  ];
  for (const re of boundedPatterns) {
    const consumed: string[] = [];
    for (const m of haystack.matchAll(re)) {
      ranges.push(`>=${m[1]} <=${m[2]}`);
      consumed.push(m[0]);
    }
    for (const c of consumed) haystack = haystack.replace(c, ' ');
  }

  // 2) Single-bound patterns over the remaining haystack.
  const before = new RegExp(`(?:before|prior\\s+to|earlier\\s+than)\\s+${v}`, 'gi');
  for (const m of haystack.matchAll(before)) {
    ranges.push(`<${m[1]}`);
  }

  const earlier = new RegExp(
    `(?:up\\s+to|including)\\s+${v}|${v}\\s+(?:and|or)\\s+(?:earlier|prior|below)`,
    'gi',
  );
  for (const m of haystack.matchAll(earlier)) {
    const target = m[1] ?? m[2];
    if (target) ranges.push(`<=${target}`);
  }

  if (ranges.length === 0) return null;
  const seen = new Set<string>();
  const uniq = ranges.filter((r) => (seen.has(r) ? false : (seen.add(r), true)));
  return uniq.slice(0, 4).join('; ');
}

/**
 * Extract the fixed-in version from a CVE summary, when the prose says
 * something like "fixed in X.Y.Z" / "patched in X.Y.Z" / "addressed in
 * X.Y.Z".  Returns a comma-separated list (semver-ish) or null.
 */
export function extractFixedVersionsFromText(text: string): string | null {
  if (!text) return null;
  const haystack = text.slice(0, 600);
  const v = '(\\d+(?:\\.\\d+){1,3})';
  const fixed = new RegExp(
    `(?:fixed|patched|addressed|resolved|remediated|corrected)\\s+(?:in|with|by)\\s+(?:version\\s+)?${v}`,
    'gi',
  );
  const out: string[] = [];
  for (const m of haystack.matchAll(fixed)) {
    if (!out.includes(m[1])) out.push(m[1]);
  }
  if (out.length === 0) return null;
  return out.slice(0, 4).join(', ');
}

/**
 * Best-effort product name extractor for free-form CVE summaries.
 * We look for the leading capitalised noun phrase that typically
 * starts these sentences ("Apache HTTP Server before 2.4.49 ...",
 * "PHP versions 8.2.0 through 8.2.30 ...", "WordPress core ...").
 * Returns lowercase product hint suitable for fuzzy matching.
 */
export function extractProductHintFromText(text: string): string | null {
  if (!text) return null;
  const m = text
    .slice(0, 240)
    .match(
      /^(?:In\s+|A\s+|An\s+)?([A-Z][A-Za-z0-9.+#-]{1,40}(?:\s+[A-Z][A-Za-z0-9.+#-]{1,40}){0,4})/,
    );
  if (!m) return null;
  // Drop trailing function/version-y bits accidentally captured.
  return m[1].replace(/\s+(versions?|before|prior|through|in)$/i, '').trim().toLowerCase();
}

function buildHeadline(text: string, maxLen = 240): string {
  if (!text) return '';
  if (text.length <= maxLen) return text;
  const firstStop = text.search(/[.!?](\s|$)/);
  if (firstStop > 0 && firstStop < maxLen) {
    return text.slice(0, firstStop + 1);
  }
  const slice = text.slice(0, maxLen);
  const lastSpace = slice.lastIndexOf(' ');
  return (lastSpace > maxLen * 0.6 ? slice.slice(0, lastSpace) : slice).trim() + '…';
}

/**
 * Extract a single card from a chunk of HTML that starts at the `<div class="card mb-4">`
 * boundary. Returns null if any of the required fields are missing.
 */
function parseCardChunk(chunk: string): ParsedCard | null {
  const cveMatch = chunk.match(
    /href="\/vulnerability\/detail\/(CVE-\d{4}-\d+)\/"[^>]*>\s*<h3>([^<]*)<\/h3>/i,
  );
  if (!cveMatch) return null;
  const cveId = cveMatch[1].trim();
  const titleRaw = decodeHtmlEntities(cveMatch[2] || '').trim();
  // Strip the leading "CVE-XXXX - " prefix from the title if present.
  const title = titleRaw.replace(/^CVE-\d{4}-\d+\s*-\s*/i, '').trim();

  const severityMatch = chunk.match(
    /class="severity-score text-severity-([a-z]*)"[^>]*>([^<]*)<\/h1>/i,
  );
  const severityRaw = severityMatch?.[1] ?? null;
  const scoreText = (severityMatch?.[2] ?? '').trim();
  const score = scoreText ? Number.parseFloat(scoreText) : null;
  const severityScore = Number.isFinite(score) && score! > 0 ? score : null;

  const cvssMatch = chunk.match(/<div class="text-muted small">([^<]*)<\/div>/i);
  const cvssVersion = cvssMatch ? decodeHtmlEntities(cvssMatch[1]).trim() || null : null;

  const descMatch = chunk.match(/<p class="mb-4">([\s\S]*?)<\/p>/i);
  const description = descMatch ? stripTags(descMatch[1]) : '';

  const publishedMatch = chunk.match(/Published:\s*([^<]+?)<\/span>/i);
  const modifiedMatch = chunk.match(/Last Modified:\s*([^<]+?)<\/span>/i);
  const publishedAt = parseMyCveDate(publishedMatch?.[1] ?? null);
  const modifiedAt = parseMyCveDate(modifiedMatch?.[1] ?? null) ?? publishedAt;

  return {
    cveId,
    title,
    description,
    severityLabel: normalizeSeverityLabel(severityRaw, severityScore),
    severityScore,
    cvssVersion,
    publishedAt,
    modifiedAt,
    detailUrl: `${MYCVE_DETAIL}/${encodeURIComponent(cveId)}/`,
  };
}

function parseListingHtml(html: string): ParsedCard[] {
  const out: ParsedCard[] = [];
  const seen = new Set<string>();
  // Split on the card opening div. The first slice is the page chrome before
  // any card; subsequent slices each contain one card (until the next card or
  // the end of the page section).
  const parts = html.split(CARD_SPLIT_RE);
  for (let i = 1; i < parts.length; i += 1) {
    const card = parseCardChunk(parts[i]);
    if (!card) continue;
    if (seen.has(card.cveId)) continue;
    seen.add(card.cveId);
    out.push(card);
  }
  return out;
}

async function fetchPage(page: number): Promise<string> {
  const url = page === 1 ? MYCVE_INDEX : `${MYCVE_INDEX}?page=${page}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      headers: {
        // Browser-style UA — mycve.com is a small Django site behind Cloudflare
        // and prefers normal-looking traffic.
        'User-Agent':
          'Mozilla/5.0 (compatible; UASF-CVE-Sync/1.0; +https://uasf.local)',
        Accept: 'text/html,application/xhtml+xml',
      },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`mycve.com responded ${response.status}`);
    }
    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

async function persistCard(card: ParsedCard): Promise<'inserted' | 'updated'> {
  const repo = AppDataSource.getRepository(DependencyVulnerability);

  const fullText = `${card.title} ${card.description}`.trim();
  const headline = buildHeadline(card.title || card.description || card.cveId, 240);

  // Extract structured fingerprint hints from the prose so the
  // correlator can produce real version-aware proof rather than
  // falling back to plain text matches.
  const productHint = extractProductHintFromText(fullText);
  const affectedRanges = extractAffectedRangesFromText(fullText);
  const fixedVersions = extractFixedVersionsFromText(fullText);

  const existing = await repo.findOne({ where: { advisoryId: card.cveId } });

  const payload = {
    ecosystem: ECOSYSTEM_LABEL,
    // Store the parsed product hint (or fall back to the CVE id) so that
    // the correlator's `packageName` lookup actually has a meaningful
    // string to search against — previously this was the CVE id itself,
    // which never matches a detected technology name.
    packageName: (productHint ?? card.cveId).slice(0, 250),
    advisoryId: card.cveId,
    cveId: card.cveId,
    severityLabel: card.severityLabel,
    severityScore: card.severityScore,
    summary: headline.slice(0, 510),
    details:
      card.description && card.description !== headline ? card.description : null,
    affectedRanges,
    fixedVersions,
    source: 'mycve',
    sourceUrl: card.detailUrl,
    publishedAt: card.publishedAt,
    modifiedAt: card.modifiedAt,
  } as const;

  if (existing) {
    await repo.update({ id: existing.id }, payload);
    return 'updated';
  }
  await repo.save(repo.create(payload));
  return 'inserted';
}

export interface IngestSummary {
  packagesQueried: number;
  advisoriesProcessed: number;
  inserted: number;
  updated: number;
  failures: Array<{ package: string; error: string }>;
  startedAt: string;
  endedAt: string;
}

/**
 * Refresh the CVE cache from the mycve.com listing feed. Safe to call
 * repeatedly; never throws. Per-record errors are aggregated into the
 * returned summary.
 *
 * @param maxPages  Maximum number of listing pages (10 cards each) to
 *                  consume in this refresh cycle. Defaults to
 *                  MAX_PAGES_PER_REFRESH (25 → 250 newest CVEs).
 */
export async function refreshDependencyFeed(
  maxPages = MAX_PAGES_PER_REFRESH,
): Promise<IngestSummary> {
  const started = new Date();

  let inserted = 0;
  let updated = 0;
  let advisoriesProcessed = 0;
  const failures: IngestSummary['failures'] = [];
  let pagesFetched = 0;

  const pageCap = Math.max(1, Math.min(maxPages, MAX_PAGES_PER_REFRESH));

  for (let page = 1; page <= pageCap; page += 1) {
    let html: string;
    try {
      html = await fetchPage(page);
      pagesFetched += 1;
    } catch (error) {
      failures.push({
        package: `mycve:page:${page}`,
        error: (error as Error).message,
      });
      break;
    }

    const cards = parseListingHtml(html);
    if (cards.length === 0) break;

    for (const card of cards) {
      try {
        const status = await persistCard(card);
        advisoriesProcessed += 1;
        if (status === 'inserted') inserted += 1;
        else updated += 1;
      } catch (error) {
        failures.push({
          package: `mycve:${card.cveId}`,
          error: (error as Error).message,
        });
      }
    }

    if (cards.length < RESULTS_PER_PAGE) break; // last page reached
    if (page < pageCap) {
      await new Promise((resolve) => setTimeout(resolve, PAGE_DELAY_MS));
    }
  }

  return {
    packagesQueried: pagesFetched,
    advisoriesProcessed,
    inserted,
    updated,
    failures,
    startedAt: started.toISOString(),
    endedAt: new Date().toISOString(),
  };
}

let scheduleHandle: NodeJS.Timeout | null = null;

/**
 * Kick off a periodic refresh in the background. The first tick runs after
 * a short delay to keep startup fast; subsequent ticks run every `everyMs`.
 *
 * Default cadence: every 2 hours.
 *
 * Idempotent: calling more than once cancels the previous schedule.
 */
export function startDependencyFeedSchedule(everyMs = 2 * 60 * 60 * 1000): void {
  if (scheduleHandle) clearInterval(scheduleHandle);
  setTimeout(() => {
    void refreshDependencyFeed().catch(() => undefined);
  }, 30_000);
  scheduleHandle = setInterval(() => {
    void refreshDependencyFeed().catch(() => undefined);
  }, everyMs);
}
