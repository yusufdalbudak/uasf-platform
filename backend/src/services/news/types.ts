/**
 * Shared shapes for the News & Intelligence module.
 *
 * Kept in a dedicated file so the source registry, parser, normalizer,
 * dedup engine, and the route layer can all import from one place without
 * pulling in heavy dependencies (or causing cyclic imports through the
 * service entrypoint).
 */

/**
 * Editorial classification of an article. Drives the colored chip on the
 * feed card and the section grouping inside detail pages.
 *
 * IMPORTANT: this list also matches the `articleType` enum the frontend
 * filter renders. Keep them in sync — if you add a value here, add the
 * label in `frontend/src/pages/News.tsx` too.
 */
export type ArticleType =
  | 'news'
  | 'advisory'
  | 'vendor-research'
  | 'breach'
  | 'malware'
  | 'threat-actor'
  | 'vulnerability'
  | 'cloud'
  | 'supply-chain'
  | 'identity'
  | 'appsec'
  | 'data-leak';

export const ARTICLE_TYPES: readonly ArticleType[] = [
  'news',
  'advisory',
  'vendor-research',
  'breach',
  'malware',
  'threat-actor',
  'vulnerability',
  'cloud',
  'supply-chain',
  'identity',
  'appsec',
  'data-leak',
];

/**
 * One feed entry as the parser sees it BEFORE normalization. Anything that
 * may legitimately be missing on a given source is `null` rather than
 * `undefined` so the normalizer never has to deal with both shapes.
 */
export interface RawFeedItem {
  /** Headline, with HTML stripped. May be empty if the feed misbehaves. */
  title: string;
  /** First non-empty of <link>, <id>, <guid permalink="true">. */
  link: string | null;
  /** First non-empty of <description>, <summary>, <content:encoded>. */
  rawSummary: string | null;
  /** ISO timestamp parsed from <pubDate>, <published>, <updated>, etc. */
  publishedAt: Date | null;
  author: string | null;
  /** Raw <category> values (RSS) or <category term="..."/> attrs (Atom). */
  categories: string[];
  /** First image URL the parser found in <enclosure>, <media:content>, etc. */
  imageUrl: string | null;
}

/**
 * The result of parsing one upstream feed.
 */
export interface ParsedFeed {
  /** Channel-level title (e.g. `BleepingComputer`); may be empty. */
  channelTitle: string;
  items: RawFeedItem[];
}
