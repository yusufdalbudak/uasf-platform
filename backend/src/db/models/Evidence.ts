import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity()
export class EvidenceLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  campaignRunId: string;

  @Column()
  scenarioId: string;

  @Column()
  targetHostname: string;

  @Column()
  method: string;

  @Column()
  path: string;

  @Column({ nullable: true })
  requestLabel: string | null;

  @Column({ type: 'varchar', length: 24, nullable: true })
  deliveryChannel: string | null;

  @Column({ type: 'int', default: 1 })
  attemptNumber: number;

  @Column({ nullable: true })
  workerJobId: string | null;

  @Column({ type: 'text', nullable: true })
  attemptedUrl: string | null;

  @Column({ type: 'jsonb', nullable: true })
  requestHeaders: Record<string, string> | null;

  @Column({ type: 'text', nullable: true })
  requestBodyPreview: string | null;

  @Column({ nullable: true })
  payloadHash: string | null;

  @Column({ type: 'varchar', length: 24, default: 'completed' })
  executionStatus: string;

  @Column('int')
  responseStatusCode: number;

  @Column('int')
  latencyMs: number;

  @Column('jsonb', { nullable: true })
  responseHeaders: Record<string, string> | null;

  @Column({ type: 'text', nullable: true })
  responseBodyPreview: string | null;

  @Column({ type: 'text', nullable: true })
  errorMessage: string | null;

  /**
   * UASF verdict classification (blocked, challenged, edge_mitigated,
   * origin_rejected, allowed, network_error, ambiguous). Stored as varchar to
   * avoid migration churn when new verdict families are introduced.
   */
  @Column({ type: 'varchar', length: 32, default: 'ambiguous' })
  verdict: string;

  @Column({ type: 'int', default: 0 })
  verdictConfidence: number;

  /** Structured verdict signals used to derive the classification. */
  @Column({ type: 'jsonb', nullable: true })
  verdictSignals: Array<{ source: string; name: string; detail?: string }> | null;

  @Column({ type: 'text', nullable: true })
  verdictReason: string | null;

  /** Expected vs observed evaluation outcome. */
  @Column({ type: 'varchar', length: 24, default: 'ambiguous' })
  expectationOutcome: string;

  @Column({ type: 'jsonb', nullable: true })
  expectationDetails: Record<string, unknown> | null;

  @CreateDateColumn()
  timestamp: Date;
}
