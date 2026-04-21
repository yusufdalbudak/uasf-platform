import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  FINGERPRINT_RULES,
  extractVersionFamily,
  type FingerprintRule,
} from '../fingerprintRules';

/**
 * The fingerprint rule library is a public surface for the engine.  These
 * tests are intentionally minimal: they validate the library invariants
 * (well-formedness, no duplicate productKeys, regexes compile) and the
 * version-family extractor — i.e. the bits that should never silently
 * regress.
 */

test('every rule has at least one matcher and a unique productKey', () => {
  const seen = new Set<string>();
  for (const rule of FINGERPRINT_RULES) {
    assert.ok(rule.productKey, 'rule.productKey required');
    assert.ok(rule.productName, 'rule.productName required');
    assert.ok(Array.isArray(rule.matchers) && rule.matchers.length > 0, `rule ${rule.productKey} has no matchers`);
    assert.ok(!seen.has(rule.productKey), `duplicate productKey: ${rule.productKey}`);
    seen.add(rule.productKey);
  }
});

test('every matcher has a valid RegExp and a known source', () => {
  const allowed = new Set(['header', 'cookie', 'body_marker', 'tls', 'banner', 'meta_tag', 'asset', 'script']);
  for (const rule of FINGERPRINT_RULES) {
    for (const matcher of rule.matchers) {
      assert.ok(matcher.pattern instanceof RegExp, `bad pattern in ${rule.productKey}`);
      assert.ok(allowed.has(matcher.source), `bad source ${matcher.source} in ${rule.productKey}`);
      if (matcher.source === 'header' || matcher.source === 'cookie') {
        assert.ok(matcher.field, `header/cookie matcher requires field in ${rule.productKey}`);
      }
    }
  }
});

test('extractVersionFamily returns the major.minor when present', () => {
  assert.equal(extractVersionFamily('1.20.3'), '1.20');
  assert.equal(extractVersionFamily('8.1'), '8.1');
  assert.equal(extractVersionFamily('5'), '5');
});

test('extractVersionFamily returns null when raw version is null', () => {
  assert.equal(extractVersionFamily(null), null);
});

test('extractVersionFamily falls back to the raw value when not numeric-leading', () => {
  // This is desired: e.g. an opaque hash version still ends up shown
  // somewhere instead of being silently dropped.
  assert.equal(extractVersionFamily('abc-123'), 'abc-123');
});

test('extractVersionFamily honors a per-rule extractor override', () => {
  const rule: FingerprintRule = {
    productKey: 'fake',
    productName: 'Fake',
    category: 'web_server',
    matchers: [],
    versionFamilyExtractor: /^(\d+)/,
  };
  assert.equal(extractVersionFamily('1.20.3', rule), '1');
});

test('nginx server-header matcher captures the version', () => {
  const rule = FINGERPRINT_RULES.find((r) => r.productKey === 'nginx');
  assert.ok(rule, 'nginx rule must exist');
  const headerMatcher = rule!.matchers.find((m) => m.source === 'header' && m.field === 'server');
  assert.ok(headerMatcher);
  const match = headerMatcher!.pattern.exec('nginx/1.21.6');
  assert.ok(match);
  assert.equal(match![1], '1.21.6');
});
