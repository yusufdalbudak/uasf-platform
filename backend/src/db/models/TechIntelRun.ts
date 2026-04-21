import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import type { DetectedTechnology } from './DetectedTechnology';
import type { VulnerabilityCorrelation } from './VulnerabilityCorrelation';

/**
 * One execution of the Tech Intelligence pipeline (fingerprinting +
 * version detection + vulnerability correlation) against an approved
 * target.
 *
 * The Tech Intel module is read-only: it observes the target and the
 * cached vulnerability feed; it never executes payloads.  WAF hardening
 * validation lives in {@link WafValidationRun} and is a separate run type.
 */
export type TechIntelRunStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed';

@Entity('tech_intel_runs')
@Index(['targetKey', 'createdAt'])
@Index(['status'])
export class TechIntelRun {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Operator-supplied target hostname or alias label (already approved). */
  @Column({ type: 'varchar', length: 255 })
  targetKey: string;

  /** DNS-resolvable hostname actually probed (from `resolveProtectedHostname`). */
  @Column({ type: 'varchar', length: 255 })
  resolvedHostname: string;

  /** Curated profile id, e.g. `web-stack-fingerprint`. */
  @Column({ type: 'varchar', length: 64 })
  profileId: string;

  @Column({ type: 'varchar', length: 24, default: 'queued' })
  status: TechIntelRunStatus;

  /** Free-form summary numbers used by list-views without re-joining. */
  @Column({ type: 'integer', default: 0 })
  technologyCount: number;

  @Column({ type: 'integer', default: 0 })
  correlationCount: number;

  @Column({ type: 'integer', default: 0 })
  highOrCriticalCount: number;

  @Column({ type: 'integer', default: 0 })
  durationMs: number;

  /** Operator id (auth_users.id) that launched the run. */
  @Column({ type: 'uuid', nullable: true })
  operatorId: string | null;

  /** Best-effort error string when the orchestrator partially or fully fails. */
  @Column({ type: 'text', nullable: true })
  errorMessage: string | null;

  /**
   * Snapshot of the actual probe execution for this run, captured at the
   * end of the orchestrator: which probes the chosen profile declared,
   * which probes the engine actually executed, and which probe-level
   * errors were collected.  Primary purpose is operator-facing
   * profile→backend integrity verification (the operator can confirm a
   * run actually used the probes the profile declared instead of trusting
   * the profile id alone).
   */
  @Column({ type: 'jsonb', nullable: true })
  executionTrace: {
    declaredProbes: string[];
    executedProbes: string[];
    httpProbed: boolean;
    tlsProbed: boolean;
    nmapProbed: boolean;
    probeErrors: string[];
  } | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Type-only back-references; we always resolve children with explicit
  // queries so the lazy relation never triggers an unbounded fetch.
  @OneToMany('DetectedTechnology', 'run')
  technologies: DetectedTechnology[];

  @OneToMany('VulnerabilityCorrelation', 'run')
  correlations: VulnerabilityCorrelation[];
}
