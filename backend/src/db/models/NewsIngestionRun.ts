import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

/**
 * One row per ingestion pass over the registered news sources.
 *
 * Stored so the operator dashboard can show "last refresh: 14m ago, 3 of 12
 * sources failed, 47 new articles" without re-running the pipeline.
 */
@Entity('news_ingestion_runs')
@Index(['startedAt'])
@Index(['triggeredBy'])
export class NewsIngestionRun {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** `scheduled` | `manual` | `boot`. */
  @Column({ type: 'varchar', length: 16, default: 'scheduled' })
  triggeredBy: string;

  @Column({ type: 'timestamptz' })
  startedAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  endedAt: Date | null;

  /** ms duration; null while in-flight. */
  @Column({ type: 'int', nullable: true })
  durationMs: number | null;

  @Column({ type: 'int', default: 0 })
  sourcesAttempted: number;

  @Column({ type: 'int', default: 0 })
  sourcesSucceeded: number;

  @Column({ type: 'int', default: 0 })
  sourcesFailed: number;

  @Column({ type: 'int', default: 0 })
  articlesFetched: number;

  @Column({ type: 'int', default: 0 })
  articlesInserted: number;

  @Column({ type: 'int', default: 0 })
  articlesSkippedDuplicates: number;

  /**
   * Per-source breakdown. Stored as JSON so the operator UI can drill in
   * without us having to design a separate child table for what is
   * fundamentally diagnostic data.
   */
  @Column({ type: 'simple-json', nullable: true })
  perSource:
    | Array<{
        slug: string;
        name: string;
        status: 'ok' | 'error';
        fetched: number;
        inserted: number;
        skipped: number;
        error?: string | null;
        durationMs: number;
      }>
    | null;

  @CreateDateColumn()
  createdAt: Date;
}
