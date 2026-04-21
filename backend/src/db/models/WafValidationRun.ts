import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import type { WafValidationEvent } from './WafValidationEvent';

/**
 * One execution of the **WAF Hardening Validation** profile against an
 * approved lab target.  This is *not* a bypass / evasion engine — it
 * issues a closed set of curated probes and records whether the WAF
 * detects, normalizes, blocks, or challenges them as expected.
 *
 * Operators use this to:
 *   - confirm a freshly-tuned ruleset still detects the basics
 *   - validate header / method / path-normalisation behaviour
 *   - see the expected-vs-observed delta for each probe
 */
export type WafValidationStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed';

@Entity('tech_intel_waf_validation_runs')
@Index(['targetKey', 'createdAt'])
@Index(['status'])
export class WafValidationRun {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255 })
  targetKey: string;

  @Column({ type: 'varchar', length: 255 })
  resolvedHostname: string;

  /** Curated profile id, e.g. `waf-baseline-detection-validation`. */
  @Column({ type: 'varchar', length: 64 })
  profileId: string;

  @Column({ type: 'varchar', length: 24, default: 'queued' })
  status: WafValidationStatus;

  @Column({ type: 'integer', default: 0 })
  totalEvents: number;

  @Column({ type: 'integer', default: 0 })
  matchedEvents: number;

  @Column({ type: 'integer', default: 0 })
  partiallyMatchedEvents: number;

  @Column({ type: 'integer', default: 0 })
  mismatchedEvents: number;

  @Column({ type: 'integer', default: 0 })
  ambiguousEvents: number;

  @Column({ type: 'integer', default: 0 })
  durationMs: number;

  @Column({ type: 'uuid', nullable: true })
  operatorId: string | null;

  @Column({ type: 'text', nullable: true })
  errorMessage: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany('WafValidationEvent', 'run')
  events: WafValidationEvent[];
}
