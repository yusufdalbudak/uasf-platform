/**
 * Article normalization layer.
 *
 * Takes a raw RSS/Atom item produced by `feedParser.ts`, scrubs and
 * classifies it, and emits the canonical shape we persist in
 * `news_articles`. Pure / synchronous / no DB or network access — easy to
 * unit-test.
 *
 * Responsibilities:
 *   - Canonicalize URLs (lowercase host, drop tracking params, trailing /)
 *   - Drop publisher-suffix decoration from titles
 *   - Build the `searchBlob` (lowercase title + summary)
 *   - Build the `dedupeKey` (normalized-title hash) used to cluster reposts
 *   - Auto-classify articleType from keywords
 *   - Extract CVE references and threat-actor / malware references
 *   - Generate up to 4 short "key takeaways" from the summary
 *   - Estimate reading time
 */

import { createHash } from 'crypto';
import type { ArticleType } from './types';
import type { RawFeedItem } from './types';
import type { NewsSourceDefinition } from './sourceRegistry';

export interface NormalizedArticle {
  sourceSlug: string;
  sourceName: string;
  canonicalUrl: string;
  sourceUrl: string;
  title: string;
  summary: string | null;
  keyTakeaways: string[] | null;
  articleType: ArticleType;
  tags: string[];
  author: string | null;
  language: string;
  publishedAt: Date;
  readingMinutes: number;
  dedupeKey: string;
  cveIds: string[];
  actorRefs: string[];
  imageUrl: string | null;
  reputation: string;
  searchBlob: string;
}

// ---------------------------------------------------------------------------
// URL canonicalization
// ---------------------------------------------------------------------------

const TRACKING_PREFIXES = ['utm_', 'mc_', 'fbclid', 'gclid', 'ref_', 'src=', 'referrer'];

export function canonicalizeUrl(input: string): string | null {
  if (!input) return null;
  try {
    const url = new URL(input);
    url.hash = '';
    // Strip well-known tracking params.
    const drop: string[] = [];
    for (const key of Array.from(url.searchParams.keys())) {
      const lower = key.toLowerCase();
      if (TRACKING_PREFIXES.some((p) => lower.startsWith(p))) drop.push(key);
    }
    drop.forEach((k) => url.searchParams.delete(k));
    // Lowercase host, normalise default ports.
    url.hostname = url.hostname.toLowerCase();
    if ((url.protocol === 'https:' && url.port === '443') || (url.protocol === 'http:' && url.port === '80')) {
      url.port = '';
    }
    // Strip trailing slash on the pathname (but keep "/").
    if (url.pathname.length > 1 && url.pathname.endsWith('/')) {
      url.pathname = url.pathname.replace(/\/+$/, '');
    }
    return url.toString();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Title cleanup + dedupe key
// ---------------------------------------------------------------------------

const TITLE_SUFFIX_PATTERNS: RegExp[] = [
  / *[|\-–—] *The Hacker News\s*$/i,
  / *[|\-–—] *BleepingComputer\s*$/i,
  / *[|\-–—] *Dark Reading\s*$/i,
  / *[|\-–—] *SecurityWeek\s*$/i,
  / *[|\-–—] *Help Net Security\s*$/i,
  / *[|\-–—] *Krebs on Security\s*$/i,
  / *[|\-–—] *The Record\s*$/i,
  / *[|\-–—] *Schneier on Security\s*$/i,
  / *[|\-–—] *Talos.*$/i,
  / *[|\-–—] *Unit 42\s*$/i,
  / *[|\-–—] *Mandiant\s*$/i,
  / *[|\-–—] *CrowdStrike.*$/i,
];

export function cleanTitle(title: string): string {
  let out = title.trim();
  for (const re of TITLE_SUFFIX_PATTERNS) {
    out = out.replace(re, '');
  }
  // Collapse whitespace.
  return out.replace(/\s+/g, ' ').trim();
}

const STOP_WORDS = new Set([
  'a', 'an', 'and', 'or', 'but', 'the', 'of', 'in', 'on', 'at', 'to', 'for',
  'with', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'as', 'by',
  'from', 'into', 'this', 'that', 'these', 'those', 'it', 'its', 'over',
  'after', 'before', 'over', 'over', 'new', 'also', 'has', 'have', 'had',
]);

/**
 * Build a canonical key used to cluster near-identical stories across
 * sources. Algorithm:
 *   1. Lowercase
 *   2. Strip publisher suffixes
 *   3. Drop punctuation
 *   4. Drop stop-words (so "Microsoft fixes 1 zero-day" and
 *      "Microsoft has fixed a zero-day" hash to the same key)
 *   5. Collapse whitespace
 *   6. SHA-256 hex (truncated to 32 chars for compact storage)
 */
export function buildDedupeKey(title: string): string {
  const lowered = cleanTitle(title).toLowerCase();
  const noPunct = lowered.replace(/[^\p{L}\p{N}\s]+/gu, ' ');
  const tokens = noPunct
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0 && !STOP_WORDS.has(t));
  const normalized = tokens.join(' ');
  return createHash('sha256').update(normalized).digest('hex').slice(0, 32);
}

// ---------------------------------------------------------------------------
// Article-type classification
// ---------------------------------------------------------------------------

interface TypeRule {
  type: ArticleType;
  patterns: RegExp[];
}

/**
 * Order matters — earlier rules win. The patterns are intentionally a bit
 * conservative; misclassifying as the source's `defaultArticleType` is
 * preferable to flagging anything mentioning "ransomware" as a `breach`.
 */
const TYPE_RULES: TypeRule[] = [
  {
    type: 'vulnerability',
    patterns: [
      /\bcve-\d{4}-\d{4,7}\b/i,
      /\bzero[- ]day\b/i,
      /\bremote code execution\b/i,
      /\bauthentication bypass\b/i,
      /\bprivilege escalation\b/i,
      /\bbuffer overflow\b/i,
    ],
  },
  {
    type: 'advisory',
    patterns: [
      /\b(advisor[yi]|alert)\b/i,
      /\b(actively exploit|kev|cisa)\b/i,
      /\bpatch tuesday\b/i,
    ],
  },
  {
    type: 'breach',
    patterns: [
      /\bdata breach\b/i,
      /\bbreached\b/i,
      /\bcompromised\b/i,
      /\bhacked\b/i,
      /\bintrusion\b/i,
    ],
  },
  {
    type: 'data-leak',
    patterns: [/\bdata leak\b/i, /\bexposed (database|bucket|s3)\b/i, /\b(million|billion) records\b/i],
  },
  {
    type: 'malware',
    patterns: [
      /\bransomware\b/i,
      /\b(stealer|rat|trojan|loader|backdoor|wiper|rootkit)\b/i,
      /\bbotnet\b/i,
    ],
  },
  {
    type: 'threat-actor',
    patterns: [
      /\bAPT[- ]?\d{1,3}\b/,
      /\bnation[- ]state\b/i,
      /\b(Lazarus|Sandworm|FIN\d+|UNC\d+|TA\d+|Lockbit|Cl0p|BlackCat|Scattered Spider)\b/,
    ],
  },
  {
    type: 'cloud',
    patterns: [/\b(aws|azure|gcp|cloudflare|kubernetes|s3 bucket|iam|cloud security)\b/i],
  },
  {
    type: 'supply-chain',
    patterns: [/\bsupply[- ]chain\b/i, /\bnpm package\b/i, /\bpypi\b/i, /\bdependency confusion\b/i],
  },
  {
    type: 'identity',
    patterns: [/\b(mfa|sso|oauth|saml|sim swap|account takeover|password reset)\b/i],
  },
  {
    type: 'appsec',
    patterns: [/\b(xss|sql injection|ssrf|owasp|appsec|web application)\b/i],
  },
];

export function classifyArticleType(
  title: string,
  summary: string | null,
  fallback: ArticleType,
): ArticleType {
  const haystack = `${title}\n${summary ?? ''}`;
  for (const rule of TYPE_RULES) {
    if (rule.patterns.some((re) => re.test(haystack))) return rule.type;
  }
  return fallback;
}

// ---------------------------------------------------------------------------
// Tag building
// ---------------------------------------------------------------------------

const TAG_KEYWORDS: Array<{ tag: string; pattern: RegExp }> = [
  { tag: 'ransomware', pattern: /\bransomware\b/i },
  { tag: 'phishing', pattern: /\bphishing\b/i },
  { tag: 'zero-day', pattern: /\bzero[- ]day\b/i },
  { tag: 'patch', pattern: /\bpatch\b/i },
  { tag: 'malware', pattern: /\bmalware\b/i },
  { tag: 'breach', pattern: /\bbreach\b/i },
  { tag: 'apt', pattern: /\bAPT[- ]?\d/i },
  { tag: 'nation-state', pattern: /\bnation[- ]state\b/i },
  { tag: 'iot', pattern: /\biot\b/i },
  { tag: 'firmware', pattern: /\bfirmware\b/i },
  { tag: 'cloud', pattern: /\b(aws|azure|gcp|cloudflare|kubernetes)\b/i },
  { tag: 'identity', pattern: /\b(mfa|sso|oauth|saml|account takeover)\b/i },
  { tag: 'critical-infra', pattern: /\b(critical infrastructure|ics|scada|ot security)\b/i },
];

export function buildTags(
  title: string,
  summary: string | null,
  upstreamCategories: string[],
  defaultTags: string[] | null | undefined,
): string[] {
  const haystack = `${title}\n${summary ?? ''}`;
  const set = new Set<string>();
  for (const t of defaultTags ?? []) set.add(t.toLowerCase());
  for (const cat of upstreamCategories) {
    const cleaned = cat
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
    if (cleaned && cleaned.length <= 32) set.add(cleaned);
  }
  for (const rule of TAG_KEYWORDS) {
    if (rule.pattern.test(haystack)) set.add(rule.tag);
  }
  // Cap to 12 — enough to be informative, never noisy.
  return Array.from(set).slice(0, 12);
}

// ---------------------------------------------------------------------------
// CVE / actor extraction
// ---------------------------------------------------------------------------

const CVE_RE = /\bcve-\d{4}-\d{4,7}\b/gi;
const ACTOR_PATTERNS = [
  /\b(APT[- ]?\d{1,3})\b/g,
  /\b(FIN\d+|UNC\d+|TA\d+)\b/g,
  /\b(Lazarus|Sandworm|Cozy Bear|Fancy Bear|Kimsuky|MuddyWater|Charming Kitten)\b/gi,
  /\b(Lockbit|BlackCat|ALPHV|Cl0p|Royal|Akira|Play|Scattered Spider|Black Basta)\b/gi,
];

export function extractCves(title: string, summary: string | null): string[] {
  const haystack = `${title} ${summary ?? ''}`;
  const set = new Set<string>();
  let match: RegExpExecArray | null;
  CVE_RE.lastIndex = 0;
  while ((match = CVE_RE.exec(haystack)) !== null) {
    set.add(match[0].toUpperCase());
  }
  return Array.from(set).slice(0, 25);
}

export function extractActors(title: string, summary: string | null): string[] {
  const haystack = `${title} ${summary ?? ''}`;
  const set = new Set<string>();
  for (const re of ACTOR_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(haystack)) !== null) {
      set.add(m[1].toLowerCase());
    }
  }
  return Array.from(set).slice(0, 10);
}

// ---------------------------------------------------------------------------
// Summary cleanup, takeaways, reading time
// ---------------------------------------------------------------------------

const SUMMARY_MAX = 1200;
const TITLE_MAX = 500;

export function cleanSummary(input: string | null): string | null {
  if (!input) return null;
  const collapsed = input.replace(/\s+/g, ' ').trim();
  if (!collapsed) return null;
  if (collapsed.length <= SUMMARY_MAX) return collapsed;
  return `${collapsed.slice(0, SUMMARY_MAX - 1).trimEnd()}\u2026`;
}

/**
 * Best-effort extraction of up to 4 short bullet takeaways from a summary.
 * We split on sentence boundaries and pick the first sentences that are at
 * least 30 chars long. If the summary is short, we return null and the UI
 * just hides the "Key takeaways" section.
 */
export function buildTakeaways(summary: string | null): string[] | null {
  if (!summary) return null;
  const sentences = summary
    .split(/(?<=[.!?])\s+(?=[A-Z0-9])/)
    .map((s) => s.trim())
    .filter((s) => s.length >= 30 && s.length <= 220);
  if (sentences.length < 2) return null;
  return sentences.slice(0, 4);
}

export function estimateReadingMinutes(summary: string | null): number {
  if (!summary) return 1;
  const words = summary.split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.ceil(words / 220));
}

// ---------------------------------------------------------------------------
// Top-level orchestrator
// ---------------------------------------------------------------------------

/**
 * Returns the normalized article OR `null` if the input is unusable
 * (no title, no canonical URL, no published date, etc.).
 */
export function normalizeItem(
  source: NewsSourceDefinition,
  item: RawFeedItem,
): NormalizedArticle | null {
  const title = cleanTitle(item.title);
  if (!title) return null;
  const canonicalUrl = canonicalizeUrl(item.link ?? '');
  if (!canonicalUrl) return null;
  // Use the upstream timestamp if we have one; if a feed forgets to publish
  // pubDate, fall back to "now" so the entry still shows up at the top.
  const publishedAt = item.publishedAt ?? new Date();
  const summary = cleanSummary(item.rawSummary);
  const articleType = classifyArticleType(title, summary, source.defaultArticleType);
  const tags = buildTags(title, summary, item.categories, source.defaultTags ?? null);
  const cveIds = extractCves(title, summary);
  const actorRefs = extractActors(title, summary);
  const dedupeKey = buildDedupeKey(title);
  const searchBlob = `${title} ${summary ?? ''}`.toLowerCase();
  const takeaways = buildTakeaways(summary);
  const readingMinutes = estimateReadingMinutes(summary);

  return {
    sourceSlug: source.slug,
    sourceName: source.name,
    canonicalUrl,
    sourceUrl: item.link ?? canonicalUrl,
    title: title.slice(0, TITLE_MAX),
    summary,
    keyTakeaways: takeaways,
    articleType,
    tags,
    author: item.author?.slice(0, 256) ?? null,
    language: 'en',
    publishedAt,
    readingMinutes,
    dedupeKey,
    cveIds,
    actorRefs,
    imageUrl: item.imageUrl,
    reputation: source.reputation,
    searchBlob: searchBlob.slice(0, 4000),
  };
}
