import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  decideAdvisoryMatchType,
  decideVersionState,
  extractFamily,
  fuseSignalWeights,
  scoreToTier,
} from '../confidenceModel';
import type { RawObservation } from '../signalTypes';

/**
 * Unit tests for the fusion-side confidence model.  These are pure
 * functions with no I/O, so we can assert exact values and be confident
 * the engine's math cannot silently regress.
 */

const obs = (partial: Partial<RawObservation>): RawObservation => ({
  family: 'passive_http',
  methodId: 'm',
  methodLabel: 'm',
  signalKey: 'k',
  signalValue: 'v',
  evidenceSnippet: 'v',
  productKey: 'nginx',
  versionLiteral: null,
  weight: 0.5,
  vendorMatch: true,
  intent: 'product_match',
  ...partial,
});

// ----------------------------------------------------------------------------
// fuseSignalWeights — probabilistic OR + diversity bonus
// ----------------------------------------------------------------------------

test('fuseSignalWeights returns 0 for no observations', () => {
  assert.equal(fuseSignalWeights([]), 0);
});

test('fuseSignalWeights with a single 0.5 observation returns 50', () => {
  const score = fuseSignalWeights([obs({ weight: 0.5 })]);
  assert.equal(score, 50);
});

test('fuseSignalWeights compounds two weak signals within a family (no diversity bonus)', () => {
  // Probabilistic OR of two 0.4 → 1 - 0.6*0.6 = 0.64.  Same family → no bonus.
  const score = fuseSignalWeights([
    obs({ weight: 0.4, family: 'passive_http' }),
    obs({ weight: 0.4, family: 'passive_http' }),
  ]);
  assert.equal(score, 64);
});

test('fuseSignalWeights applies +0.05 diversity bonus with two families', () => {
  // 1 - 0.6*0.6 = 0.64 → +0.05 (two families) = 0.69
  const score = fuseSignalWeights([
    obs({ weight: 0.4, family: 'passive_http' }),
    obs({ weight: 0.4, family: 'markup' }),
  ]);
  assert.equal(score, 69);
});

test('fuseSignalWeights applies +0.10 diversity bonus with three families', () => {
  // 1 - 0.7*0.7*0.7 = 0.657 → +0.10 (three families) = 0.757 → rounds to 76
  const score = fuseSignalWeights([
    obs({ weight: 0.3, family: 'passive_http' }),
    obs({ weight: 0.3, family: 'markup' }),
    obs({ weight: 0.3, family: 'tls' }),
  ]);
  assert.equal(score, 76);
});

test('fuseSignalWeights clamps weights > 1', () => {
  // Clamping to 1 ⇒ probability is 1 ⇒ score 100.
  const score = fuseSignalWeights([obs({ weight: 2.5 })]);
  assert.equal(score, 100);
});

test('fuseSignalWeights is 100 for a single weight of 1', () => {
  assert.equal(fuseSignalWeights([obs({ weight: 1 })]), 100);
});

// ----------------------------------------------------------------------------
// scoreToTier
// ----------------------------------------------------------------------------

test('scoreToTier thresholds map correctly', () => {
  assert.equal(scoreToTier(0), 'low');
  assert.equal(scoreToTier(44), 'low');
  assert.equal(scoreToTier(45), 'medium');
  assert.equal(scoreToTier(69), 'medium');
  assert.equal(scoreToTier(70), 'high');
  assert.equal(scoreToTier(89), 'high');
  assert.equal(scoreToTier(90), 'very_high');
  assert.equal(scoreToTier(100), 'very_high');
});

// ----------------------------------------------------------------------------
// decideVersionState
// ----------------------------------------------------------------------------

test('decideVersionState returns unknown on empty input', () => {
  const d = decideVersionState([]);
  assert.equal(d.versionState, 'unknown');
  assert.equal(d.version, null);
  assert.equal(d.versionFamily, null);
});

test('decideVersionState prefers exact when any observation declares exact + literal', () => {
  const d = decideVersionState([
    obs({ versionState: 'family', versionLiteral: '1.21' }),
    obs({ versionState: 'exact', versionLiteral: '1.21.6' }),
  ]);
  assert.equal(d.versionState, 'exact');
  assert.equal(d.version, '1.21.6');
  assert.equal(d.versionFamily, '1.21');
});

test('decideVersionState returns probable when two observations agree on the same literal', () => {
  const d = decideVersionState([
    obs({ versionState: 'probable', versionLiteral: '1.21.6' }),
    obs({ versionState: 'probable', versionLiteral: '1.21.6', family: 'markup' }),
  ]);
  assert.equal(d.versionState, 'probable');
  assert.equal(d.version, '1.21.6');
  assert.equal(d.versionFamily, '1.21');
});

test('decideVersionState falls back to family', () => {
  const d = decideVersionState([
    obs({ versionState: 'family', versionLiteral: '1.21' }),
  ]);
  assert.equal(d.versionState, 'family');
  assert.equal(d.version, null);
  assert.equal(d.versionFamily, '1.21');
});

test('decideVersionState stays unknown without any version literal', () => {
  const d = decideVersionState([obs({ versionLiteral: null })]);
  assert.equal(d.versionState, 'unknown');
  assert.equal(d.version, null);
});

// ----------------------------------------------------------------------------
// decideAdvisoryMatchType
// ----------------------------------------------------------------------------

test('decideAdvisoryMatchType returns null when the version is clearly out of range', () => {
  assert.equal(decideAdvisoryMatchType('exact', 'out'), null);
  assert.equal(decideAdvisoryMatchType('probable', 'out'), null);
});

test('decideAdvisoryMatchType returns exact only when versionState is exact and range is in', () => {
  assert.equal(decideAdvisoryMatchType('exact', 'in'), 'exact');
  assert.equal(decideAdvisoryMatchType('probable', 'in'), 'probable');
  assert.equal(decideAdvisoryMatchType('exact', 'unknown'), 'ambiguous');
});

test('decideAdvisoryMatchType returns family when versionState is family', () => {
  assert.equal(decideAdvisoryMatchType('family', 'in'), 'family');
  assert.equal(decideAdvisoryMatchType('family', 'unknown'), 'family');
});

test('decideAdvisoryMatchType returns ambiguous when nothing else matches', () => {
  assert.equal(decideAdvisoryMatchType('unknown', 'unknown'), 'ambiguous');
  assert.equal(decideAdvisoryMatchType('unknown', 'in'), 'ambiguous');
});

// ----------------------------------------------------------------------------
// extractFamily
// ----------------------------------------------------------------------------

test('extractFamily parses major.minor.patch', () => {
  assert.equal(extractFamily('1.21.6'), '1.21');
  assert.equal(extractFamily('14.2.5'), '14.2');
});

test('extractFamily parses a major-only version', () => {
  assert.equal(extractFamily('18'), '18');
});

test('extractFamily returns null for a null or non-numeric input', () => {
  assert.equal(extractFamily(null), null);
  assert.equal(extractFamily('unknown'), null);
});
