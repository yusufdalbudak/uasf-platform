/**
 * UASF Tech Intelligence — Confidence Model
 *
 * Pure helpers that turn a bag of per-signal observation weights into a
 * calibrated confidence score + tier + version state.  The policy is
 * conservative: without converging evidence we stay low; without explicit
 * version literal we never label a version as `exact`.
 *
 * This module has no I/O.  It is covered by unit tests so the rest of
 * the engine can rely on stable math.
 */

import type {
  FingerprintConfidence,
  VersionCertainty,
} from '../../db/models/DetectedTechnology';
import type { FingerprintSignalFamily, RawObservation } from './signalTypes';

/**
 * Fuse weighted observation weights into a single 0..100 score using
 * a "probabilistic OR":
 *
 *     p_combined = 1 - Π (1 - w_i)
 *
 * This means (a) one strong signal converges toward its own weight,
 * (b) multiple weak signals compound (two 0.4 → 0.64, three → 0.78),
 * (c) weights above 1 are clamped so they cannot overwhelm the model.
 *
 * A small diversity bonus is added when observations come from multiple
 * signal families — a rule-of-thumb lift for cross-layer corroboration
 * that mirrors the OWASP multi-source testing philosophy.
 */
export function fuseSignalWeights(observations: RawObservation[]): number {
  if (observations.length === 0) return 0;

  let inverse = 1;
  const families = new Set<FingerprintSignalFamily>();
  for (const obs of observations) {
    const w = Math.max(0, Math.min(1, obs.weight));
    inverse *= 1 - w;
    families.add(obs.family);
  }
  let p = 1 - inverse;

  // Cross-family diversity bonus (at most +0.10 additive in the 0..1 space).
  if (families.size >= 2) p = Math.min(1, p + 0.05);
  if (families.size >= 3) p = Math.min(1, p + 0.05);

  return Math.round(p * 100);
}

/** Translate a 0..100 fused score into the coarse UI tier. */
export function scoreToTier(score: number): FingerprintConfidence {
  if (score >= 90) return 'very_high';
  if (score >= 70) return 'high';
  if (score >= 45) return 'medium';
  return 'low';
}

/**
 * Decide the version-state label given the observations that
 * contributed to a detected product.
 *
 * Rules:
 *  - `exact`    — at least one observation with `versionState = 'exact'`
 *                 (typically from a header/banner that includes a
 *                 verbatim version) AND a concrete version literal.
 *  - `probable` — at least two observations agree on the same version
 *                 family, OR a single `probable` observation with a
 *                 version literal.
 *  - `family`   — a version family is known (e.g. 1.21) but not the
 *                 exact patch level.
 *  - `unknown`  — otherwise.
 */
export function decideVersionState(observations: RawObservation[]): {
  versionState: VersionCertainty;
  version: string | null;
  versionFamily: string | null;
} {
  if (observations.length === 0) {
    return { versionState: 'unknown', version: null, versionFamily: null };
  }

  const withExact = observations.find(
    (o) => o.versionState === 'exact' && o.versionLiteral,
  );
  if (withExact) {
    return {
      versionState: 'exact',
      version: withExact.versionLiteral,
      versionFamily: extractFamily(withExact.versionLiteral ?? null),
    };
  }

  const withProbable = observations.find(
    (o) => o.versionState === 'probable' && o.versionLiteral,
  );

  const literalCounts = new Map<string, number>();
  for (const o of observations) {
    if (!o.versionLiteral) continue;
    literalCounts.set(o.versionLiteral, (literalCounts.get(o.versionLiteral) ?? 0) + 1);
  }
  const agreeingLiteral = [...literalCounts.entries()].find(([, n]) => n >= 2);

  if (agreeingLiteral) {
    const [v] = agreeingLiteral;
    return {
      versionState: 'probable',
      version: v,
      versionFamily: extractFamily(v),
    };
  }
  if (withProbable) {
    return {
      versionState: 'probable',
      version: withProbable.versionLiteral,
      versionFamily: extractFamily(withProbable.versionLiteral ?? null),
    };
  }

  // Family fallback — any observation that only picks up a family.
  const familyObs = observations.find(
    (o) => o.versionState === 'family' && (o.versionLiteral ?? null),
  );
  if (familyObs) {
    return {
      versionState: 'family',
      version: null,
      versionFamily: familyObs.versionLiteral,
    };
  }

  return { versionState: 'unknown', version: null, versionFamily: null };
}

/**
 * Advisory correlation match-type decision.  Rolls `versionState` +
 * range verdict into the four-state label surfaced by the UI.
 */
export function decideAdvisoryMatchType(
  versionState: VersionCertainty,
  rangeVerdict: 'in' | 'out' | 'unknown',
): 'exact' | 'probable' | 'family' | 'ambiguous' | null {
  if (rangeVerdict === 'out') return null;
  if (versionState === 'exact' && rangeVerdict === 'in') return 'exact';
  if (versionState === 'probable' && rangeVerdict === 'in') return 'probable';
  if (versionState === 'family') return 'family';
  return 'ambiguous';
}

/**
 * Extracts a major.minor family string ("1.21" ← "1.21.6").
 * Exposed for use by both the confidence model and the fusion engine.
 */
export function extractFamily(version: string | null): string | null {
  if (!version) return null;
  const m = /^(\d+)(?:\.(\d+))?/.exec(version);
  if (!m) return null;
  return m[2] !== undefined ? `${m[1]}.${m[2]}` : m[1];
}
