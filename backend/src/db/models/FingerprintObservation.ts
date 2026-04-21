import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { TechIntelRun } from './TechIntelRun';

/**
 * One atomic signal captured during a fingerprint run.  Observations are
 * the primitive unit of evidence: every detected technology / version /
 * advisory correlation must be justifiable via one or more rows in this
 * table.
 *
 * An observation records:
 *
 *   - which signal family produced it (a layer in the OWASP-inspired
 *     multi-signal methodology — passive HTTP, TLS, markup, URL/route,
 *     DOM/structural, controlled behavior, service/infra)
 *   - which specific detection method inside that family fired
 *   - the exact signal that was captured (e.g. header name, meta-tag
 *     fragment, route status+path)
 *   - a short evidence snippet that a human operator can audit
 *   - the product candidate the signal points at (nullable — a structural
 *     signal may not pick a product but still counts for fusion weight)
 *   - whether the signal carries an explicit version claim
 *   - a per-signal confidence weight used by the fusion engine
 *
 * Observations are immutable after the run completes; the UI treats them
 * as an append-only evidence ledger.
 */
export type FingerprintSignalFamily =
  | 'passive_http'
  | 'tls'
  | 'markup'
  | 'url_route'
  | 'dom_structural'
  | 'behavior'
  | 'service';

/**
 * Stable machine id for a specific detection method.  The catalog lives in
 * `services/techIntel/detectionMethodsCatalog.ts` and the UI dereferences
 * these ids to the human-readable method name + description.
 *
 * We keep the column as `varchar(64)` instead of an enum because the
 * catalog is expected to grow.  Adding a new method is a code change but
 * not a migration.
 */
@Entity('tech_intel_fingerprint_observations')
@Index(['runId'])
@Index(['runId', 'family'])
@Index(['runId', 'methodId'])
@Index(['productKey'])
export class FingerprintObservation {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  runId: string;

  @ManyToOne(() => TechIntelRun, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'runId' })
  run: TechIntelRun;

  @Column({ type: 'varchar', length: 24 })
  family: FingerprintSignalFamily;

  /** Catalog id, e.g. `passive_http.server_header`, `markup.meta_generator`. */
  @Column({ type: 'varchar', length: 64 })
  methodId: string;

  /**
   * Short human-readable label.  Stored denormalised so the UI can render
   * run detail without re-joining against the catalog (which can evolve
   * independently across deployments).
   */
  @Column({ type: 'varchar', length: 128 })
  methodLabel: string;

  /**
   * Signal key: what was being probed (header name, meta-tag name,
   * route path, structural feature name…).  Used by the UI as the primary
   * grouping label inside a family.
   */
  @Column({ type: 'varchar', length: 128 })
  signalKey: string;

  /**
   * Signal value — kept short; long bodies are pre-truncated by the adapter.
   */
  @Column({ type: 'text' })
  signalValue: string;

  /** Evidence snippet an operator can cite (same or slightly shorter). */
  @Column({ type: 'text' })
  evidenceSnippet: string;

  /**
   * Candidate product key this observation points at (`nginx`, `cloudflare`,
   * `wordpress`, …).  Nullable because structural / behavior observations
   * often contribute weight without choosing a product on their own.
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  productKey: string | null;

  /** Version literal extracted from the signal (if any). */
  @Column({ type: 'varchar', length: 64, nullable: true })
  versionLiteral: string | null;

  /**
   * How much this single observation supports the conclusion, 0..1.
   * The fusion engine fuses per-signal weights into the final
   * DetectedTechnology confidence score.
   */
  @Column({ type: 'real' })
  weight: number;

  /**
   * True iff the signal value literally matched a vendor string — used to
   * distinguish structural hints from banner-grade evidence.
   */
  @Column({ type: 'boolean', default: false })
  vendorMatch: boolean;

  /** Free-form additional context (e.g. response status for route probes). */
  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, unknown> | null;

  @CreateDateColumn()
  capturedAt: Date;
}
