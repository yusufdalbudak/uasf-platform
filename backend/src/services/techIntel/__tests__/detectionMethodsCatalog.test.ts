import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DETECTION_METHODS_CATALOG } from '../detectionMethodsCatalog';

/**
 * The catalog is a user-facing surface: it renders on the Detection
 * Methods tab and the operator uses it to audit the fingerprint engine's
 * toolbox.  These tests enforce the invariants that make the catalog
 * useful:
 *   - every id is unique and follows the `<family>.<slug>` shape
 *   - every family string is one of the declared fingerprint families
 *   - weights are in [0, 1]
 *   - kind is either passive or active
 */

const VALID_FAMILIES = new Set([
  'passive_http',
  'tls',
  'markup',
  'url_route',
  'dom_structural',
  'behavior',
  'service',
]);

test('detection methods catalog is non-empty', () => {
  assert.ok(DETECTION_METHODS_CATALOG.length > 0, 'catalog should contain entries');
});

test('every entry has a unique, well-formed id', () => {
  const seen = new Set<string>();
  for (const entry of DETECTION_METHODS_CATALOG) {
    assert.match(entry.id, /^[a-z0-9_]+\.[a-z0-9_]+$/, `bad id ${entry.id}`);
    assert.ok(!seen.has(entry.id), `duplicate id ${entry.id}`);
    seen.add(entry.id);
  }
});

test('every entry declares a known signal family matching its id prefix', () => {
  for (const entry of DETECTION_METHODS_CATALOG) {
    assert.ok(VALID_FAMILIES.has(entry.family), `unknown family ${entry.family}`);
    const [prefix] = entry.id.split('.');
    assert.equal(
      prefix,
      entry.family,
      `id prefix ${prefix} does not match family ${entry.family} on ${entry.id}`,
    );
  }
});

test('every entry has a label and a non-trivial description', () => {
  for (const entry of DETECTION_METHODS_CATALOG) {
    assert.ok(entry.label && entry.label.length > 0, `missing label on ${entry.id}`);
    assert.ok(
      entry.description && entry.description.length >= 10,
      `description too short on ${entry.id}`,
    );
  }
});

test('every entry declares a valid kind and typical weight', () => {
  for (const entry of DETECTION_METHODS_CATALOG) {
    assert.ok(
      entry.kind === 'passive' || entry.kind === 'active',
      `bad kind ${entry.kind} on ${entry.id}`,
    );
    assert.ok(
      typeof entry.typicalWeight === 'number' &&
        entry.typicalWeight >= 0 &&
        entry.typicalWeight <= 1,
      `bad typicalWeight ${entry.typicalWeight} on ${entry.id}`,
    );
  }
});

test('catalog covers every fingerprint family at least once', () => {
  const seen = new Set<string>();
  for (const entry of DETECTION_METHODS_CATALOG) seen.add(entry.family);
  for (const family of VALID_FAMILIES) {
    assert.ok(seen.has(family), `no catalog entry for family ${family}`);
  }
});
