import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Normalized cybersecurity news article.
 *
 * One row per (source, canonical URL). When the same story is republished by
 * multiple publishers we *do* keep both rows (each carries clear source
 * attribution per product spec), but we cluster them via `dedupeKey`: every
 * row whose normalized title hashes to the same value shares a `clusterId`
 * so the feed can show the cluster size and the detail page can surface
 * "Other coverage" links.
 *
 * Original article bodies are NOT stored verbatim — the spec is explicit:
 * "avoid raw copied article dumps". We persist a normalized internal summary,
 * a tag set, an article-type classification, and always link back to the
 * original publisher. Operators read the full article on the publisher's
 * site via the always-present source link.
 */
@Entity('news_articles')
@Index(['sourceSlug', 'canonicalUrl'], { unique: true })
@Index(['publishedAt'])
@Index(['ingestedAt'])
@Index(['articleType'])
@Index(['dedupeKey'])
@Index(['clusterId'])
export class NewsArticle {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** FK-style reference to NewsSource.slug for cheap joinless rendering. */
  @Column({ type: 'varchar', length: 64 })
  sourceSlug: string;

  /** Display name snapshotted at ingest time so renames don't lose history. */
  @Column({ type: 'varchar', length: 128 })
  sourceName: string;

  /** Canonical (normalized) URL of the original article on the publisher. */
  @Column({ type: 'varchar', length: 1024 })
  canonicalUrl: string;

  /** Raw URL exactly as the feed published it (for debugging/audit). */
  @Column({ type: 'varchar', length: 1024 })
  sourceUrl: string;

  /** Headline. Always sanitized + length-clamped. */
  @Column({ type: 'varchar', length: 512 })
  title: string;

  /**
   * Internal normalized summary. Populated from the feed's `<description>` /
   * `<summary>` / `<content:encoded>` after HTML-stripping, whitespace
   * normalization, and length clamping. Never the full article body.
   */
  @Column({ type: 'text', nullable: true })
  summary: string | null;

  /** Up to 4 short bullet takeaways extracted heuristically from the summary. */
  @Column({ type: 'simple-json', nullable: true })
  keyTakeaways: string[] | null;

  /**
   * Editorial classification used for visual differentiation in the feed.
   * One of: `news` | `advisory` | `vendor-research` | `breach` | `malware`
   * | `threat-actor` | `vulnerability` | `cloud` | `supply-chain`
   * | `identity` | `appsec` | `data-leak`.
   */
  @Column({ type: 'varchar', length: 24, default: 'news' })
  articleType: string;

  /** Free-form taxonomy tags (lowercased, deduplicated, max ~12). */
  @Column({ type: 'simple-array', nullable: true })
  tags: string[] | null;

  /** Author byline, when the feed exposes one. */
  @Column({ type: 'varchar', length: 256, nullable: true })
  author: string | null;

  /** ISO 639-1 language hint (default `en`). */
  @Column({ type: 'varchar', length: 8, default: 'en' })
  language: string;

  /** Original publish timestamp from the feed. */
  @Column({ type: 'timestamptz' })
  publishedAt: Date;

  /** Wall-clock time the platform first saw this article. */
  @Column({ type: 'timestamptz' })
  ingestedAt: Date;

  /**
   * Estimated reading time in minutes. Computed as
   * `ceil(words / 220)` where `words = summary.split(/\s+/).length`.
   * Never below 1.
   */
  @Column({ type: 'int', default: 1 })
  readingMinutes: number;

  /**
   * Stable hash used to cluster near-identical stories across sources.
   * Built from the normalized title (lowercased, stop-words removed,
   * stripped of source-specific decoration like " | BleepingComputer").
   */
  @Column({ type: 'varchar', length: 64 })
  dedupeKey: string;

  /**
   * Cluster id assigned to every article sharing a `dedupeKey`. The first
   * inserted member of a cluster keeps its own UUID as cluster id; later
   * members adopt that id. Lets the feed show "Also covered by N sources".
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  clusterId: string | null;

  /**
   * CVE identifiers mentioned in the title or summary (regex-extracted).
   * Lets the article detail page deep-link into our CVE Intelligence module.
   */
  @Column({ type: 'simple-array', nullable: true })
  cveIds: string[] | null;

  /** Threat-actor / malware-family names referenced (lowercased). */
  @Column({ type: 'simple-array', nullable: true })
  actorRefs: string[] | null;

  /** Optional thumbnail image URL exposed by the feed. */
  @Column({ type: 'varchar', length: 1024, nullable: true })
  imageUrl: string | null;

  /** Reputation tier inherited from the source at ingest time. */
  @Column({ type: 'varchar', length: 8, default: 'A' })
  reputation: string;

  /**
   * Lowercase concatenation of `title + ' ' + summary` used by ILIKE search.
   * Maintained at write time so search doesn't have to lower() at query time.
   */
  @Column({ type: 'text' })
  searchBlob: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
