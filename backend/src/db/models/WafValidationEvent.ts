import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { WafValidationRun } from './WafValidationRun';
import type { ExpectationOutcome } from '../../engine/expectation';
import type { Verdict } from '../../engine/verdict';

/**
 * One curated probe within a {@link WafValidationRun}.  Each event records
 * the request envelope (method / path / category) and the structured
 * verdict + expectation evaluation produced by the orchestrator so the UI
 * can render an evidence-traceable timeline without retaining raw exploit
 * payloads in the dashboard.
 */
@Entity('tech_intel_waf_validation_events')
@Index(['runId', 'createdAt'])
@Index(['runId', 'expectationOutcome'])
export class WafValidationEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  runId: string;

  @ManyToOne(() => WafValidationRun, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'runId' })
  run: WafValidationRun;

  /** Probe id from the curated profile (deterministic, no free-form payloads). */
  @Column({ type: 'varchar', length: 64 })
  probeId: string;

  @Column({ type: 'varchar', length: 128 })
  probeLabel: string;

  /** Coarse category for grouping in the UI. */
  @Column({ type: 'varchar', length: 32 })
  category: string;

  @Column({ type: 'varchar', length: 8 })
  method: string;

  @Column({ type: 'varchar', length: 512 })
  path: string;

  @Column({ type: 'integer' })
  responseStatus: number;

  @Column({ type: 'integer' })
  responseDurationMs: number;

  @Column({ type: 'varchar', length: 24 })
  observedVerdict: Verdict;

  @Column({ type: 'integer' })
  observedConfidence: number;

  /** Verdict signals captured at evaluation time. */
  @Column({ type: 'jsonb', default: () => "'[]'::jsonb" })
  verdictSignals: Array<{ source: string; name: string; detail?: string }>;

  /** Comma-joined verdict family operators expected (e.g. "blocked|challenged"). */
  @Column({ type: 'varchar', length: 128 })
  expectedVerdicts: string;

  @Column({ type: 'varchar', length: 24 })
  expectationOutcome: ExpectationOutcome;

  @Column({ type: 'jsonb', default: () => "'[]'::jsonb" })
  expectationReasons: string[];

  /** Trimmed body preview for evidence (≤512 chars). */
  @Column({ type: 'text', nullable: true })
  bodyPreview: string | null;

  /** Truncated response headers (lower-cased). */
  @Column({ type: 'jsonb', default: () => "'{}'::jsonb" })
  responseHeaders: Record<string, string>;

  @Column({ type: 'text', nullable: true })
  errorMessage: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
