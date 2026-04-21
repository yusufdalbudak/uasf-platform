import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';
import type { DeepScanResult } from '../../engine/scanTypes';

/**
 * Persisted UASF assessment report. One row per completed `runVulnerabilityScan`
 * (and per completed Discovery run via `reportType = 'discovery'`).
 *
 * The full normalized {@link DeepScanResult} is preserved verbatim in
 * {@link resultJson}, so HTML and PDF renderers can produce reports without
 * re-executing any scan modules. Severity counts and durations are denormalized
 * to keep listing endpoints cheap.
 */
@Entity('reports')
@Index(['targetHostname', 'createdAt'])
@Index(['reportType', 'createdAt'])
export class Report {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** `assessment` (full DAST), `discovery` (recon-only), `campaign` (future). */
  @Column({ type: 'varchar', length: 24, default: 'assessment' })
  reportType: string;

  @Column({ type: 'varchar', length: 255 })
  targetHostname: string;

  /** Operator-friendly title rendered as the report heading. */
  @Column({ type: 'varchar', length: 255 })
  title: string;

  @Column({ type: 'int', default: 0 })
  durationMs: number;

  @Column({ type: 'int', default: 0 })
  totalFindings: number;

  @Column({ type: 'int', default: 0 })
  criticalCount: number;

  @Column({ type: 'int', default: 0 })
  highCount: number;

  @Column({ type: 'int', default: 0 })
  mediumCount: number;

  @Column({ type: 'int', default: 0 })
  lowCount: number;

  @Column({ type: 'int', default: 0 })
  infoCount: number;

  @Column({ type: 'int', default: 0 })
  modulesRun: number;

  @Column({ type: 'int', default: 0 })
  modulesSucceeded: number;

  @Column({ type: 'int', default: 0 })
  modulesFailed: number;

  /** Stored verbatim — required for HTML and PDF rendering on demand. */
  @Column({ type: 'jsonb' })
  resultJson: DeepScanResult;

  /** Optional operator note (not used by the renderers but surfaced in lists). */
  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
