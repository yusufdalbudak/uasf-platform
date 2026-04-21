import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Public IOC / threat-context observation, normalized for cross-source display.
 *
 * Indicators ingested from public, attribution-friendly feeds (e.g. abuse.ch
 * URLhaus). One row per (source, indicator, indicatorType). The same indicator
 * can re-appear across feeds; the upsert path bumps `lastSeen` and
 * `occurrences` rather than duplicating rows.
 */
@Entity('ioc_indicators')
@Index(['source', 'indicator', 'indicatorType'], { unique: true })
@Index(['indicatorType'])
@Index(['threatLabel'])
export class IocIndicator {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Free-form indicator: URL, domain, IPv4, file SHA256, etc. */
  @Column({ type: 'varchar', length: 1024 })
  indicator: string;

  /** url | domain | ipv4 | ipv6 | sha256 | sha1 | md5 | other */
  @Column({ type: 'varchar', length: 16 })
  indicatorType: string;

  /** Human-readable threat label (malware family, kit, campaign, ...). */
  @Column({ type: 'varchar', length: 128, nullable: true })
  threatLabel: string | null;

  /** Confidence label as reported by the upstream feed: high | medium | low. */
  @Column({ type: 'varchar', length: 16, default: 'medium' })
  confidence: string;

  /** Upstream source identifier (e.g. `urlhaus`, `feodo-tracker`). */
  @Column({ type: 'varchar', length: 64 })
  source: string;

  /** Human-friendly source display name. */
  @Column({ type: 'varchar', length: 128, nullable: true })
  sourceName: string | null;

  /** Direct link back to the upstream record so operators can verify. */
  @Column({ type: 'varchar', length: 1024, nullable: true })
  sourceUrl: string | null;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  /** Number of times the ingest pipeline has re-confirmed this indicator. */
  @Column({ type: 'int', default: 1 })
  occurrences: number;

  @Column({ type: 'timestamptz' })
  firstSeen: Date;

  @Column({ type: 'timestamptz' })
  lastSeen: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
