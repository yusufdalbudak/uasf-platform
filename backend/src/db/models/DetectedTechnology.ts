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
 * Confidence levels assigned to a fingerprint detection.  Calibrated so
 * upstream consumers (correlator, UI, report) never silently overstate
 * certainty.
 */
export type FingerprintConfidence = 'low' | 'medium' | 'high' | 'very_high';

/**
 * Version certainty buckets.  We keep these explicit instead of using a
 * single numeric score because the operator-facing UI needs to colour and
 * label them differently.
 */
export type VersionCertainty =
  | 'exact'        // version string was matched verbatim from a server header / banner
  | 'probable'     // version is strongly implied by 1+ converging signals
  | 'family'       // major-or-minor family only (e.g. nginx 1.x)
  | 'unknown';     // product detected but version evidence is absent or weak

/**
 * Coarse technology category used for grouping in the dashboard.  Drawn
 * from a closed vocabulary so the UI can render consistent group headers.
 */
export type TechnologyCategory =
  | 'web_server'
  | 'reverse_proxy'
  | 'cdn_edge'
  | 'waf'
  | 'application_framework'
  | 'cms_platform'
  | 'js_library'
  | 'api_framework'
  | 'tls'
  | 'service_banner'
  | 'cookie_marker'
  | 'language_runtime'
  | 'analytics'
  | 'other';

/**
 * One product/version observed on an approved target.  Each row carries
 * its own evidence array so the UI can render a fully traceable
 * "why we believe this" drawer without re-running the probes.
 */
@Entity('tech_intel_detected_technologies')
@Index(['runId'])
@Index(['runId', 'category'])
@Index(['productKey'])
export class DetectedTechnology {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  runId: string;

  @ManyToOne(() => TechIntelRun, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'runId' })
  run: TechIntelRun;

  /**
   * Stable, lower-cased identity of the product (e.g. `nginx`, `cloudflare`,
   * `express`, `wordpress`).  Used as the join key against the
   * vulnerability feed and as the de-duplication key inside a single run.
   */
  @Column({ type: 'varchar', length: 64 })
  productKey: string;

  /** Human-friendly name shown in the UI. */
  @Column({ type: 'varchar', length: 128 })
  productName: string;

  /** Optional vendor / origin label. */
  @Column({ type: 'varchar', length: 128, nullable: true })
  vendor: string | null;

  @Column({ type: 'varchar', length: 24 })
  category: TechnologyCategory;

  /**
   * Best-effort version string ("1.21.6", "2.4", etc.).  May be null if
   * only the product was identifiable.
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  version: string | null;

  /** Major/minor family (e.g. "1.21" extracted from "1.21.6"). */
  @Column({ type: 'varchar', length: 32, nullable: true })
  versionFamily: string | null;

  @Column({ type: 'varchar', length: 16, default: 'unknown' })
  versionCertainty: VersionCertainty;

  @Column({ type: 'varchar', length: 16, default: 'low' })
  confidence: FingerprintConfidence;

  /**
   * Signed array of evidence records.  Each entry is a tagged source so
   * the UI can render a small icon + label per row.  Stored as JSONB so
   * future evidence kinds (e.g. JA3 hashes) drop in without a migration.
   */
  @Column({ type: 'jsonb', default: () => "'[]'::jsonb" })
  evidence: Array<{
    source: 'header' | 'cookie' | 'body_marker' | 'tls' | 'banner' | 'meta_tag' | 'asset' | 'script' | 'rule';
    detail: string;
    matchedRule?: string;
  }>;

  /** Free-form notes for the operator (override / triage). */
  @Column({ type: 'text', nullable: true })
  notes: string | null;

  /**
   * Numeric confidence score (0..100) produced by the multi-signal fusion
   * engine.  Complements (does not replace) the coarse `confidence` tier
   * above.  Nullable so rows written before the fusion engine existed
   * (and rows persisted by legacy code paths that don't yet set a score)
   * do not fail the ORM schema check.
   */
  @Column({ type: 'integer', nullable: true })
  confidenceScore: number | null;

  /**
   * Signal-family breakdown that contributed to this detection — e.g.
   * `['passive_http','markup','tls']`.  The UI uses this to render a
   * "which layers saw this?" chip row per technology without re-scanning
   * the evidence array.  Drawn from `FingerprintSignalFamily` values.
   */
  @Column({ type: 'jsonb', nullable: true })
  signalFamilies: string[] | null;

  /**
   * Specific detection method ids that fired for this technology
   * (e.g. `passive_http.server_header`, `markup.meta_generator`).  A
   * denormalized slice of the observation ledger so the UI can show the
   * method trace without a second query.
   */
  @Column({ type: 'jsonb', nullable: true })
  detectionMethodIds: string[] | null;

  /**
   * Back-references to the FingerprintObservation rows that were fused
   * into this detection.  Used by the Evidence Trace tab to jump from
   * a detected technology to its supporting raw signals.
   */
  @Column({ type: 'jsonb', nullable: true })
  observationIds: string[] | null;

  @CreateDateColumn()
  createdAt: Date;
}
