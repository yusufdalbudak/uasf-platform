/**
 * Lightweight, dependency-free RSS 2.0 / Atom 1.0 / RDF (RSS 1.0) parser
 * tailored to the News & Intelligence module.
 *
 * Why dependency-free
 * -------------------
 * We only consume a small, controlled list of public cybersecurity feeds
 * (`sourceRegistry.ts`). All of them are well-formed but trivially small
 * (≤ ~50 entries each). Pulling a full parser library (`fast-xml-parser`,
 * `feedparser`, `rss-parser`) would add ~150KB of transitive dependencies,
 * a JSDOM-flavoured global, and CVE exposure for what is fundamentally a
 * regex extraction problem on tag-soup we control.
 *
 * What we DO carefully:
 *   - Accept all three feed shapes (RSS 2.0, Atom 1.0, RDF/RSS 1.0).
 *   - Decode the four XML entities + numeric character references.
 *   - Strip CDATA wrappers and HTML in summaries before storing.
 *   - Extract first image from <enclosure>, <media:content>, or inline <img>.
 *   - Pick the publish timestamp from a wide set of upstream conventions
 *     (`pubDate`, `dc:date`, `published`, `updated`, `lastBuildDate`).
 *   - Normalise upstream categories into a flat string list.
 *
 * What we do NOT do:
 *   - We do not attempt to fix mal-formed XML (our sources are reliable).
 *   - We do not follow `<atom:link rel="next">` for pagination — every
 *     curated source paginates via fresh polls.
 *   - We do not download `<media:content>` images; the URL alone is stored.
 */

import type { ParsedFeed, RawFeedItem } from './types';

// ---------------------------------------------------------------------------
// XML / HTML entity helpers
// ---------------------------------------------------------------------------

/** Tiny entity table — covers everything our curated feeds emit. */
const ENTITY_MAP: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  rsquo: '\u2019',
  lsquo: '\u2018',
  rdquo: '\u201D',
  ldquo: '\u201C',
  ndash: '\u2013',
  mdash: '\u2014',
  hellip: '\u2026',
  trade: '\u2122',
  copy: '\u00A9',
  reg: '\u00AE',
};

export function decodeEntities(text: string): string {
  if (!text) return '';
  return text.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (whole, entity: string) => {
    if (entity.startsWith('#x') || entity.startsWith('#X')) {
      const code = parseInt(entity.slice(2), 16);
      return Number.isFinite(code) ? safeFromCodePoint(code) : whole;
    }
    if (entity.startsWith('#')) {
      const code = parseInt(entity.slice(1), 10);
      return Number.isFinite(code) ? safeFromCodePoint(code) : whole;
    }
    const replacement = ENTITY_MAP[entity.toLowerCase()];
    return replacement ?? whole;
  });
}

function safeFromCodePoint(cp: number): string {
  // Reject control bytes that PDFKit/HTML viewers don't render anyway.
  if (cp === 0 || (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d)) return '';
  try {
    return String.fromCodePoint(cp);
  } catch {
    return '';
  }
}

/** Unwrap a single CDATA block: `<![CDATA[...]]>` → `...`. */
function stripCdata(s: string): string {
  return s.replace(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/g, '$1');
}

/** Strip ALL HTML tags from a fragment + collapse whitespace. */
export function stripHtml(input: string): string {
  if (!input) return '';
  const noCdata = stripCdata(input);
  // Drop <style>/<script> blocks entirely (content is JS/CSS, not text).
  const noScripts = noCdata.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ');
  // Replace any remaining tags with a single space so adjacent words don't fuse.
  const noTags = noScripts.replace(/<\/?[a-z][a-z0-9-]*\b[^>]*>/gi, ' ');
  return decodeEntities(noTags).replace(/\s+/g, ' ').trim();
}

/**
 * Read the first matching `<tag>...</tag>` block (with optional XML
 * namespace prefix) from `xml`. Returns the inner string with any
 * surrounding whitespace trimmed but otherwise untouched (no entity
 * decoding here — caller decides whether to strip HTML or keep markup).
 */
export function firstTag(xml: string, tag: string): string | null {
  // Build a single regex that allows the tag to be optionally namespaced
  // (`<dc:date>`, `<atom:link>`) and to carry attributes.
  const re = new RegExp(
    `<(?:[a-z0-9]+:)?${escapeRegex(tag)}\\b[^>]*>([\\s\\S]*?)<\\/(?:[a-z0-9]+:)?${escapeRegex(tag)}>`,
    'i',
  );
  const m = re.exec(xml);
  return m ? m[1].trim() : null;
}

/**
 * Read all attributes of the first occurrence of a self-closing or open
 * tag (`<atom:link href="..." />`, `<enclosure url="..."/>`).
 */
export function firstTagAttrs(
  xml: string,
  tag: string,
): Record<string, string> | null {
  const re = new RegExp(
    `<(?:[a-z0-9]+:)?${escapeRegex(tag)}\\b([^>]*?)\\/?>`,
    'i',
  );
  const m = re.exec(xml);
  if (!m) return null;
  return parseAttrs(m[1]);
}

function parseAttrs(attrs: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([a-zA-Z_:][\w:.-]*)\s*=\s*"([^"]*)"|([a-zA-Z_:][\w:.-]*)\s*=\s*'([^']*)'/g;
  for (;;) {
    const m = re.exec(attrs);
    if (!m) break;
    const name = m[1] ?? m[3];
    const value = m[2] ?? m[4];
    if (name) out[name.toLowerCase()] = decodeEntities(value);
  }
  return out;
}

function escapeRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Item / channel splitting
// ---------------------------------------------------------------------------

/** Pull every `<item>` (RSS) or `<entry>` (Atom) block, in document order. */
export function splitItems(xml: string): string[] {
  const out: string[] = [];
  // Atom uses `<entry>`, RSS 2.0 + RDF use `<item>`. Try Atom first; if it
  // matches, the feed is Atom and we don't fall through to RSS scanning.
  const atomItems = matchAll(xml, /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi);
  if (atomItems.length > 0) return atomItems.map((m) => m[1]);
  const rssItems = matchAll(xml, /<item\b[^>]*>([\s\S]*?)<\/item>/gi);
  return rssItems.map((m) => m[1]);
}

function matchAll(input: string, re: RegExp): RegExpExecArray[] {
  const out: RegExpExecArray[] = [];
  let m: RegExpExecArray | null;
  re.lastIndex = 0;
  while ((m = re.exec(input)) !== null) {
    out.push(m);
    if (m.index === re.lastIndex) re.lastIndex += 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Per-item field extraction
// ---------------------------------------------------------------------------

function extractTitle(item: string): string {
  const raw = firstTag(item, 'title') ?? '';
  return stripHtml(raw);
}

/**
 * Pick the first non-empty link.
 *
 * Atom: `<link href="..."/>` (preferred when rel="alternate" or absent),
 *       `<id>...</id>` (URL-shaped) is the canonical fallback.
 * RSS:  `<link>...</link>` (text), `<guid isPermaLink="true">...</guid>`.
 */
function extractLink(item: string): string | null {
  // Atom: prefer rel="alternate" or no rel at all.
  const atomLinks = matchAll(item, /<link\b([^>]*?)\/?>/gi);
  for (const match of atomLinks) {
    const attrs = parseAttrs(match[1]);
    const href = attrs.href;
    if (!href) continue;
    const rel = (attrs.rel ?? 'alternate').toLowerCase();
    if (rel === 'alternate') return href;
  }
  // RSS 2.0 — text content of <link>.
  const rssLink = firstTag(item, 'link');
  if (rssLink) {
    const cleaned = stripCdata(rssLink).trim();
    if (/^https?:\/\//i.test(cleaned)) return decodeEntities(cleaned);
  }
  // <guid isPermaLink="true">...</guid> — common RSS fallback.
  const guidMatch = /<guid\b([^>]*)>([\s\S]*?)<\/guid>/i.exec(item);
  if (guidMatch) {
    const attrs = parseAttrs(guidMatch[1]);
    const isPermalink = (attrs['ispermalink'] ?? 'true').toLowerCase() !== 'false';
    const value = stripCdata(guidMatch[2]).trim();
    if (isPermalink && /^https?:\/\//i.test(value)) {
      return decodeEntities(value);
    }
  }
  // Atom <id> as a last resort.
  const idTag = firstTag(item, 'id');
  if (idTag && /^https?:\/\//i.test(idTag)) return decodeEntities(idTag);
  return null;
}

function extractSummary(item: string): string | null {
  // Try the richest field first, then progressively poorer ones.
  const candidates = [
    firstTag(item, 'content:encoded'),
    firstTag(item, 'content'),
    firstTag(item, 'summary'),
    firstTag(item, 'description'),
    firstTag(item, 'subtitle'),
  ];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const cleaned = stripHtml(candidate);
    if (cleaned.length >= 20) return cleaned;
  }
  return null;
}

function extractAuthor(item: string): string | null {
  // Atom: <author><name>...</name></author>. RSS: <author>...</author>.
  const authorBlock = firstTag(item, 'author');
  if (authorBlock) {
    const name = firstTag(authorBlock, 'name');
    if (name) return stripHtml(name);
    const cleaned = stripHtml(authorBlock);
    if (cleaned) return cleaned;
  }
  const dcCreator = firstTag(item, 'dc:creator') ?? firstTag(item, 'creator');
  if (dcCreator) return stripHtml(dcCreator);
  return null;
}

function extractCategories(item: string): string[] {
  const out: string[] = [];
  const matches = matchAll(item, /<category\b([^>]*)>([\s\S]*?)<\/category>|<category\b([^>]*?)\/>/gi);
  for (const m of matches) {
    if (m[2]) {
      const cleaned = stripHtml(m[2]);
      if (cleaned) out.push(cleaned);
    } else {
      const attrs = parseAttrs(m[3] ?? '');
      if (attrs.term) out.push(attrs.term);
      else if (attrs.label) out.push(attrs.label);
    }
  }
  return out;
}

function extractImage(item: string): string | null {
  const enclosure = firstTagAttrs(item, 'enclosure');
  if (enclosure?.url && (enclosure.type ?? '').startsWith('image/')) {
    return enclosure.url;
  }
  const mediaContent = firstTagAttrs(item, 'media:content');
  if (mediaContent?.url) return mediaContent.url;
  const mediaThumb = firstTagAttrs(item, 'media:thumbnail');
  if (mediaThumb?.url) return mediaThumb.url;
  // Inline `<img src="...">` inside the description (very common).
  const descBlock = firstTag(item, 'description') ?? firstTag(item, 'content:encoded') ?? '';
  const imgMatch = /<img\b[^>]*?\bsrc=["']([^"']+)["']/i.exec(descBlock);
  if (imgMatch) return decodeEntities(imgMatch[1]);
  return null;
}

function extractDate(item: string): Date | null {
  const candidates = [
    firstTag(item, 'pubDate'),
    firstTag(item, 'published'),
    firstTag(item, 'updated'),
    firstTag(item, 'dc:date'),
    firstTag(item, 'date'),
    firstTag(item, 'lastBuildDate'),
  ];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const trimmed = stripCdata(candidate).trim();
    const parsed = new Date(trimmed);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseFeed(xml: string): ParsedFeed {
  if (!xml || typeof xml !== 'string') {
    return { channelTitle: '', items: [] };
  }

  // Atom feeds nest the channel in `<feed>...<title>`; RSS in `<channel><title>`.
  const channelTitleSource = firstTag(xml, 'channel') ?? xml;
  const channelTitle = stripHtml(firstTag(channelTitleSource, 'title') ?? '');

  const itemBlocks = splitItems(xml);
  const items: RawFeedItem[] = [];
  for (const block of itemBlocks) {
    const title = extractTitle(block);
    if (!title) continue;
    items.push({
      title,
      link: extractLink(block),
      rawSummary: extractSummary(block),
      publishedAt: extractDate(block),
      author: extractAuthor(block),
      categories: extractCategories(block),
      imageUrl: extractImage(block),
    });
  }
  return { channelTitle, items };
}
