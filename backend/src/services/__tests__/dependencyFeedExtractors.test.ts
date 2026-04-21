/**
 * Tests for the prose-to-structure extractors used by the mycve.com
 * dependency feed.  These extractors are what transform free-form CVE
 * descriptions into the structured `affectedRanges` / `fixedVersions`
 * fields that the vulnerability correlator uses to produce
 * version-aware proof.
 */

// Pin minimal env so config/env's `requireNonEmpty` doesn't blow up when this
// suite is run standalone (no docker / no .env on disk).  These extractors
// are pure functions but live in a module that transitively imports the
// DataSource bootstrap.
process.env.DATABASE_URL ??= 'postgres://test:test@localhost:5432/test';
process.env.ALLOWED_TARGETS ??= 'example.com';
process.env.JWT_ACCESS_SECRET ??= 'unit-test-secret-with-enough-entropy-aaaa';
process.env.REFRESH_TOKEN_PEPPER ??= 'unit-test-pepper-aaaaaaaaaaaaaaaaaaaa';

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import {
  extractAffectedRangesFromText,
  extractFixedVersionsFromText,
  extractProductHintFromText,
} from '../dependencyFeedService';

describe('extractAffectedRangesFromText', () => {
  it('captures simple "before X.Y.Z" prose as a strict upper bound', () => {
    const range = extractAffectedRangesFromText(
      'Apache HTTP Server before 2.4.49 mishandles a regular expression …',
    );
    assert.equal(range, '<2.4.49');
  });

  it('captures "X.Y.Z and earlier" / "up to X.Y.Z" as inclusive upper bounds', () => {
    assert.equal(
      extractAffectedRangesFromText('PHP 8.2.30 and earlier are affected.'),
      '<=8.2.30',
    );
    assert.equal(
      extractAffectedRangesFromText('Affects nginx up to 1.25.4 (inclusive).'),
      '<=1.25.4',
    );
  });

  it('captures bounded "X.Y.Z through A.B.C" ranges', () => {
    const range = extractAffectedRangesFromText(
      'WordPress core 6.0.0 through 6.4.2 contains a stored XSS …',
    );
    assert.equal(range, '>=6.0.0 <=6.4.2');
  });

  it('captures "from X up to and including Y" ranges', () => {
    const range = extractAffectedRangesFromText(
      'OpenSSL versions from 1.1.0 up to and including 1.1.1 are vulnerable.',
    );
    assert.equal(range, '>=1.1.0 <=1.1.1');
  });

  it('returns null when no version-shaped tokens are present', () => {
    assert.equal(
      extractAffectedRangesFromText('A logic flaw allows information disclosure.'),
      null,
    );
  });

  it('returns null on empty / undefined input without throwing', () => {
    assert.equal(extractAffectedRangesFromText(''), null);
    assert.equal(extractAffectedRangesFromText(undefined as unknown as string), null);
  });
});

describe('extractFixedVersionsFromText', () => {
  it('captures "fixed in X.Y.Z" prose', () => {
    assert.equal(
      extractFixedVersionsFromText('The issue was fixed in 1.2.4.'),
      '1.2.4',
    );
  });

  it('captures "addressed in version X.Y.Z" prose', () => {
    assert.equal(
      extractFixedVersionsFromText('Addressed in version 7.4.33.'),
      '7.4.33',
    );
  });

  it('returns null when no fixed version is mentioned', () => {
    assert.equal(
      extractFixedVersionsFromText('Apache before 2.4.49 mishandles a regex.'),
      null,
    );
  });
});

describe('extractProductHintFromText', () => {
  it('returns the leading capitalised noun phrase', () => {
    assert.equal(
      extractProductHintFromText('Apache HTTP Server before 2.4.49 mishandles …'),
      'apache http server',
    );
  });

  it('strips trailing version-y joiner tokens', () => {
    assert.equal(
      extractProductHintFromText('PHP versions 8.2.0 through 8.2.30 contain …'),
      'php',
    );
  });

  it('returns null on lowercase / unrecognisable openings', () => {
    assert.equal(extractProductHintFromText('a logic flaw allows …'), null);
  });
});
