import { test } from 'node:test';
import assert from 'node:assert/strict';

import { fuseObservations, fuseWithLegacyCandidates } from '../signalFusion';
import type { RawObservation } from '../signalTypes';

const obs = (partial: Partial<RawObservation>): RawObservation => ({
  family: 'passive_http',
  methodId: 'm',
  methodLabel: 'm',
  signalKey: 'k',
  signalValue: 'v',
  evidenceSnippet: 'v',
  productKey: 'nginx',
  productName: 'nginx',
  category: 'web_server',
  versionLiteral: null,
  weight: 0.5,
  vendorMatch: true,
  intent: 'product_match',
  ...partial,
});

test('fuseObservations groups observations by productKey', () => {
  const out = fuseObservations([
    obs({ productKey: 'nginx', weight: 0.6, family: 'passive_http' }),
    obs({ productKey: 'nginx', weight: 0.5, family: 'markup' }),
    obs({
      productKey: 'wordpress',
      productName: 'WordPress',
      category: 'cms_platform',
      weight: 0.9,
      family: 'markup',
    }),
  ]);
  const keys = out.map((c) => c.productKey).sort();
  assert.deepEqual(keys, ['nginx', 'wordpress']);
});

test('fuseObservations drops observations without a productKey', () => {
  const out = fuseObservations([obs({ productKey: null })]);
  assert.equal(out.length, 0);
});

test('fuseObservations records every family that contributed', () => {
  const [c] = fuseObservations([
    obs({ family: 'passive_http', weight: 0.4 }),
    obs({ family: 'markup', weight: 0.4 }),
    obs({ family: 'tls', weight: 0.4 }),
  ]);
  assert.ok(c);
  assert.deepEqual(
    [...c.signalFamilies].sort(),
    ['markup', 'passive_http', 'tls'],
  );
  // Three families so the diversity bonus should lift the score clearly
  // above the per-signal weight.
  assert.ok(c.confidenceScore > 60);
});

test('fuseObservations infers version state from observations', () => {
  const [c] = fuseObservations([
    obs({
      weight: 0.9,
      versionState: 'exact',
      versionLiteral: '1.21.6',
      family: 'passive_http',
    }),
    obs({
      weight: 0.5,
      versionState: 'family',
      versionLiteral: '1.21',
      family: 'markup',
    }),
  ]);
  assert.ok(c);
  assert.equal(c.versionCertainty, 'exact');
  assert.equal(c.version, '1.21.6');
  assert.equal(c.versionFamily, '1.21');
});

test('fuseObservations deduplicates methodIds', () => {
  const [c] = fuseObservations([
    obs({ methodId: 'passive_http.server_header', weight: 0.6 }),
    obs({ methodId: 'passive_http.server_header', weight: 0.6, family: 'passive_http' }),
    obs({ methodId: 'markup.meta_generator', weight: 0.6, family: 'markup' }),
  ]);
  assert.ok(c);
  assert.deepEqual(
    [...c.detectionMethodIds].sort(),
    ['markup.meta_generator', 'passive_http.server_header'],
  );
});

test('fuseObservations sorts candidates by category then score', () => {
  const out = fuseObservations([
    obs({ productKey: 'nginx', category: 'web_server', weight: 0.4 }),
    obs({
      productKey: 'apache',
      productName: 'Apache',
      category: 'web_server',
      weight: 0.9,
    }),
    obs({
      productKey: 'wp',
      productName: 'WordPress',
      category: 'cms_platform',
      weight: 0.8,
    }),
  ]);
  // cms_platform < web_server, so wp first; apache before nginx by score.
  assert.deepEqual(out.map((c) => c.productKey), ['wp', 'apache', 'nginx']);
});

test('fuseWithLegacyCandidates merges legacy rule hits into the fusion output', () => {
  const out = fuseWithLegacyCandidates(
    [
      obs({
        productKey: 'nginx',
        family: 'passive_http',
        weight: 0.4,
        versionState: 'family',
        versionLiteral: '1.21',
      }),
    ],
    [
      {
        productKey: 'nginx',
        productName: 'nginx',
        vendor: null,
        category: 'web_server',
        version: '1.21.6',
        versionFamily: '1.21',
        versionCertainty: 'exact',
        confidence: 'high',
        evidence: [
          { source: 'header', detail: 'server: nginx/1.21.6', matchedRule: 'nginx.server' },
        ],
      },
    ],
  );
  const cand = out.find((c) => c.productKey === 'nginx');
  assert.ok(cand);
  // Legacy "exact" evidence wins: we now have an exact version.
  assert.equal(cand.versionCertainty, 'exact');
  assert.equal(cand.version, '1.21.6');
  // Both the adapter method id and the synthesised legacy_rule.* id appear.
  assert.ok(cand.detectionMethodIds.some((id) => id.startsWith('legacy_rule.')));
});

test('fuseWithLegacyCandidates still emits a candidate for a legacy hit with no evidence array', () => {
  const out = fuseWithLegacyCandidates(
    [],
    [
      {
        productKey: 'wp',
        productName: 'WordPress',
        vendor: 'Automattic',
        category: 'cms_platform',
        version: null,
        versionFamily: null,
        versionCertainty: 'unknown',
        confidence: 'low',
        evidence: [],
      },
    ],
  );
  assert.equal(out.length, 1);
  assert.equal(out[0].productKey, 'wp');
});
