/**
 * UASF Tech Intelligence — Signal Fusion
 *
 * Takes the raw observations emitted by the adapter layer (and,
 * optionally, a legacy `FingerprintCandidate[]` list produced by the
 * declarative rule library for backwards compatibility), groups them by
 * product, and fuses them into a single {@link FusedCandidate} per
 * product.
 *
 * Fusion responsibilities:
 *
 *   - Group observations by `productKey`.
 *   - Decide the product's version state using the confidence model.
 *   - Produce a 0..100 confidence score via probabilistic OR of signal
 *     weights, with a diversity bonus for cross-family corroboration.
 *   - Track which detection method ids contributed, for the Detection
 *     Methods / Evidence Trace tabs in the UI.
 *
 * The fuser is deterministic and pure — same inputs, same outputs.
 */

import type {
  FingerprintConfidence,
  TechnologyCategory,
  VersionCertainty,
} from '../../db/models/DetectedTechnology';
import type { FingerprintSignalFamily } from '../../db/models/FingerprintObservation';
import {
  decideVersionState,
  extractFamily,
  fuseSignalWeights,
  scoreToTier,
} from './confidenceModel';
import type { RawObservation } from './signalTypes';

export interface FusedCandidate {
  productKey: string;
  productName: string;
  vendor: string | null;
  category: TechnologyCategory;
  version: string | null;
  versionFamily: string | null;
  versionCertainty: VersionCertainty;
  confidence: FingerprintConfidence;
  confidenceScore: number;
  signalFamilies: FingerprintSignalFamily[];
  detectionMethodIds: string[];
  /**
   * The subset of raw observations that contributed to this candidate.
   * The orchestrator persists these and links them by id via
   * `DetectedTechnology.observationIds`.
   */
  contributingObservations: RawObservation[];
}

/**
 * Fuse a flat list of observations into per-product candidates.
 * Observations whose `productKey` is null do not produce their own
 * candidate but still appear as structural / behavior context in the
 * observation ledger (the engine persists them regardless).
 */
export function fuseObservations(observations: RawObservation[]): FusedCandidate[] {
  const byProduct = new Map<string, RawObservation[]>();
  for (const obs of observations) {
    if (!obs.productKey) continue;
    const list = byProduct.get(obs.productKey) ?? [];
    list.push(obs);
    byProduct.set(obs.productKey, list);
  }

  const candidates: FusedCandidate[] = [];
  for (const [productKey, obsList] of byProduct.entries()) {
    const primary = pickPrimaryObservation(obsList);
    if (!primary) continue;

    const versionDecision = decideVersionState(obsList);
    const score = fuseSignalWeights(obsList);
    const families = uniqueFamilies(obsList);
    const methodIds = uniqueMethods(obsList);

    candidates.push({
      productKey,
      productName: primary.productName ?? primary.productKey ?? productKey,
      vendor: primary.vendor ?? null,
      category: primary.category ?? 'other',
      version: versionDecision.version,
      versionFamily:
        versionDecision.versionFamily ?? extractFamily(versionDecision.version),
      versionCertainty: versionDecision.versionState,
      confidence: scoreToTier(score),
      confidenceScore: score,
      signalFamilies: families,
      detectionMethodIds: methodIds,
      contributingObservations: obsList.slice(),
    });
  }

  return candidates.sort((a, b) => {
    if (a.category !== b.category) return a.category.localeCompare(b.category);
    return b.confidenceScore - a.confidenceScore;
  });
}

/**
 * Convenience wrapper: merge observations with a pre-existing list of
 * legacy rule-engine candidates.  Each legacy candidate is decomposed
 * back into a synthetic observation so the fuser produces one unified
 * set.  This keeps the declarative rule library valuable while letting
 * the adapter layer grow independently.
 */
export function fuseWithLegacyCandidates(
  observations: RawObservation[],
  legacyCandidates: Array<{
    productKey: string;
    productName: string;
    vendor: string | null;
    category: TechnologyCategory;
    version: string | null;
    versionFamily: string | null;
    versionCertainty: VersionCertainty;
    confidence: FingerprintConfidence;
    evidence: Array<{ source: string; detail: string; matchedRule?: string }>;
  }>,
): FusedCandidate[] {
  const synthesised: RawObservation[] = [];
  for (const cand of legacyCandidates) {
    // Map the legacy tier → per-signal weight.
    const baseWeight = tierToWeight(cand.confidence);
    for (const ev of cand.evidence) {
      synthesised.push({
        family: mapLegacySourceToFamily(ev.source),
        methodId: `legacy_rule.${ev.source}`,
        methodLabel: `Legacy rule · ${ev.source}`,
        signalKey: ev.matchedRule ?? cand.productKey,
        signalValue: ev.detail,
        evidenceSnippet: ev.detail,
        productKey: cand.productKey,
        productName: cand.productName,
        vendor: cand.vendor,
        category: cand.category,
        versionLiteral: cand.version,
        versionState: cand.versionCertainty,
        weight: baseWeight,
        vendorMatch: true,
        intent: cand.version ? 'version_match' : 'product_match',
      });
    }
    if (cand.evidence.length === 0) {
      // No evidence array — still record a minimal entry so fusion sees the candidate.
      synthesised.push({
        family: 'passive_http',
        methodId: 'legacy_rule.rule',
        methodLabel: 'Legacy rule',
        signalKey: cand.productKey,
        signalValue: `${cand.productName}${cand.version ? ` ${cand.version}` : ''}`,
        evidenceSnippet: `Legacy fingerprint rule asserted ${cand.productName}`,
        productKey: cand.productKey,
        productName: cand.productName,
        vendor: cand.vendor,
        category: cand.category,
        versionLiteral: cand.version,
        versionState: cand.versionCertainty,
        weight: baseWeight,
        vendorMatch: true,
        intent: cand.version ? 'version_match' : 'product_match',
      });
    }
  }
  return fuseObservations([...observations, ...synthesised]);
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function pickPrimaryObservation(list: RawObservation[]): RawObservation | null {
  if (list.length === 0) return null;
  // Prefer observations that carry a product name + highest weight.
  return [...list].sort((a, b) => {
    const ap = a.productName ? 1 : 0;
    const bp = b.productName ? 1 : 0;
    if (ap !== bp) return bp - ap;
    return b.weight - a.weight;
  })[0];
}

function uniqueFamilies(list: RawObservation[]): FingerprintSignalFamily[] {
  const s = new Set<FingerprintSignalFamily>();
  for (const o of list) s.add(o.family);
  return [...s];
}

function uniqueMethods(list: RawObservation[]): string[] {
  const s = new Set<string>();
  for (const o of list) s.add(o.methodId);
  return [...s];
}

function tierToWeight(tier: FingerprintConfidence): number {
  switch (tier) {
    case 'very_high':
      return 0.9;
    case 'high':
      return 0.75;
    case 'medium':
      return 0.55;
    case 'low':
    default:
      return 0.3;
  }
}

function mapLegacySourceToFamily(source: string): FingerprintSignalFamily {
  switch (source) {
    case 'tls':
      return 'tls';
    case 'banner':
      return 'service';
    case 'meta_tag':
    case 'body_marker':
    case 'asset':
    case 'script':
      return 'markup';
    case 'header':
    case 'cookie':
    case 'rule':
    default:
      return 'passive_http';
  }
}
