/**
 * UASF Tech Intelligence — Shared signal types.
 *
 * The fingerprinting engine is deliberately modelled as a multi-layer
 * pipeline (passive HTTP / TLS / markup / URL-route / DOM-structural /
 * controlled behaviour / service).  Each layer emits atomic
 * {@link RawObservation} records which are later fused into detected
 * technologies by `signalFusion.ts`.
 *
 * Keeping the types in one place (a) prevents adapter drift, and
 * (b) means the observation entity, catalog, fusion engine, and frontend
 * DTOs share exactly the same vocabulary.
 */

import type {
  TechnologyCategory,
  VersionCertainty,
} from '../../db/models/DetectedTechnology';
import type { FingerprintSignalFamily } from '../../db/models/FingerprintObservation';

export type { FingerprintSignalFamily };

/**
 * Version state surfaced to operators.  Same semantics as the existing
 * `VersionCertainty` enum; re-exported under the more descriptive name
 * the new engine uses throughout.
 */
export type VersionState = VersionCertainty;

/**
 * Short textual description of what the signal contributed to the
 * fusion model.  Purely informational — used by the UI to show "why"
 * columns alongside each observation.
 */
export type ObservationIntent =
  | 'product_match'
  | 'version_match'
  | 'family_hint'
  | 'structural_hint'
  | 'behavior_hint'
  | 'advisory_hint';

/**
 * A single observation produced by an adapter.  Mirrors the persistent
 * entity (`FingerprintObservation`) except it carries no database id yet
 * (assigned when `persistObservations` writes the rows).
 */
export interface RawObservation {
  family: FingerprintSignalFamily;
  methodId: string;
  methodLabel: string;
  signalKey: string;
  signalValue: string;
  evidenceSnippet: string;
  /** Candidate product key (stable, lower-case). */
  productKey: string | null;
  productName?: string | null;
  vendor?: string | null;
  category?: TechnologyCategory;
  versionLiteral: string | null;
  versionState?: VersionState;
  /** 0..1 — per-signal fusion weight. Set conservatively by adapters. */
  weight: number;
  /** Whether the value literally matched a vendor/product string. */
  vendorMatch: boolean;
  intent: ObservationIntent;
  metadata?: Record<string, unknown>;
}

/**
 * The catalog entry for a detection method.  The catalog is the single
 * source of truth the UI uses on the "Detection Methods" tab — it lets
 * operators audit the toolbox without having to read adapter code.
 */
export interface DetectionMethodCatalogEntry {
  id: string;
  family: FingerprintSignalFamily;
  label: string;
  description: string;
  /** Which OWASP WSTG v4 test this technique is inspired by, if any. */
  owaspReference?: string;
  /**
   * Whether the method actively probes the target (`active`) or only
   * reads what the target already emits (`passive`).  Active probes
   * must remain safe-by-design and approved-target-only.
   */
  kind: 'passive' | 'active';
  /**
   * Broad fusion weight hint (0..1) — the adapter may scale per
   * observation, but this gives operators a sense of each method's
   * upper bound.
   */
  typicalWeight: number;
}
