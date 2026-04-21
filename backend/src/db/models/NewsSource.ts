import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * A curated public cybersecurity news/advisory source the platform ingests
 * from. Sources are not user-creatable through the API — they come from the
 * static registry in `services/news/sourceRegistry.ts` and are upserted on
 * startup. This row primarily stores *operational health* (how the last
 * pull went) so the UI can show source freshness without re-querying every
 * upstream feed.
 *
 * The combination of `feedUrl` is unique so re-running the bootstrap is
 * idempotent.
 */
@Entity('news_sources')
@Index(['slug'], { unique: true })
@Index(['feedUrl'], { unique: true })
@Index(['enabled'])
export class NewsSource {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** URL-safe identifier (e.g. `bleepingcomputer`, `cisa-alerts`). */
  @Column({ type: 'varchar', length: 64 })
  slug: string;

  /** Human-readable display name (e.g. `BleepingComputer`). */
  @Column({ type: 'varchar', length: 128 })
  name: string;

  /** Editorial publisher description for the UI. */
  @Column({ type: 'varchar', length: 512, nullable: true })
  description: string | null;

  /**
   * Vendor / publisher classification. Drives a colored chip in the UI:
   *   `news`         – mainstream cybersecurity press
   *   `vendor`       – product-security blog (vendor research)
   *   `cert`         – CERT/CSIRT/government advisory publisher
   *   `research`     – academic / independent researcher
   */
  @Column({ type: 'varchar', length: 16, default: 'news' })
  category: string;

  /** Reputation tier — drives a small badge in the feed (S/A/B). */
  @Column({ type: 'varchar', length: 8, default: 'A' })
  reputation: string;

  /** Default tag(s) we assume every article from this source carries. */
  @Column({ type: 'simple-array', nullable: true })
  defaultTags: string[] | null;

  /** RSS / Atom feed URL. */
  @Column({ type: 'varchar', length: 1024 })
  feedUrl: string;

  /** Canonical homepage of the publisher. */
  @Column({ type: 'varchar', length: 1024, nullable: true })
  homepageUrl: string | null;

  /** Polite-fetch User-Agent override; null = platform default. */
  @Column({ type: 'varchar', length: 256, nullable: true })
  userAgent: string | null;

  /**
   * Operational on/off switch. A failing source will be left enabled but its
   * `consecutiveFailures` will rise; an operator can flip this to false to
   * stop re-trying a permanently broken feed.
   */
  @Column({ type: 'boolean', default: true })
  enabled: boolean;

  /** ISO timestamp of the last successful poll. */
  @Column({ type: 'timestamptz', nullable: true })
  lastFetchedAt: Date | null;

  /** Last fetch status: `ok` | `error` | null when never polled. */
  @Column({ type: 'varchar', length: 16, nullable: true })
  lastStatus: string | null;

  /** Short error message from the last failed pull. */
  @Column({ type: 'varchar', length: 1024, nullable: true })
  lastError: string | null;

  /** Articles inserted on the last successful pull (de-duped). */
  @Column({ type: 'int', default: 0 })
  lastInsertedCount: number;

  /** Total articles ever ingested from this source. */
  @Column({ type: 'int', default: 0 })
  totalArticles: number;

  /** Number of consecutive failed polls — for operator visibility. */
  @Column({ type: 'int', default: 0 })
  consecutiveFailures: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
