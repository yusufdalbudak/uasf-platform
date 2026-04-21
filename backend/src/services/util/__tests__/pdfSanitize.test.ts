import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { sanitizeForPdf, sanitizePairs } from '../pdfSanitize';

describe('sanitizeForPdf', () => {
  it('returns the fallback for null/undefined/empty', () => {
    assert.equal(sanitizeForPdf(null), '');
    assert.equal(sanitizeForPdf(undefined, 'n/a'), 'n/a');
    assert.equal(sanitizeForPdf('', 'fallback'), 'fallback');
  });

  it('coerces non-strings to string', () => {
    assert.equal(sanitizeForPdf(42), '42');
    assert.equal(sanitizeForPdf(true), 'true');
    assert.equal(sanitizeForPdf({ a: 1 }), '[object Object]');
  });

  it('strips ASCII control bytes (except tab/newline) and DEL', () => {
    const dirty = 'AB\u0000C\u0001D\u0007\u007FE\tF\nG';
    assert.equal(sanitizeForPdf(dirty), 'ABCDE\tF\nG');
  });

  it('normalises curly quotes, em/en dashes, ellipsis to ASCII', () => {
    const input = '\u201CHello\u2019s \u2014 world\u2026\u201D';
    assert.equal(sanitizeForPdf(input), '"Hello\'s - world..."');
  });

  it('replaces non-Latin-1 codepoints with "?"', () => {
    const input = 'ASCII \u4E2D\u6587 emoji \uD83D\uDE00 done';
    const out = sanitizeForPdf(input);
    // CJK chars and emoji surrogate pair both reduced to "?"
    assert.equal(out, 'ASCII ?? emoji ? done');
  });

  it('preserves Latin-1 chars including middle dot, accented vowels', () => {
    const input = 'résumé · café — naïve';
    // em-dash gets normalised to "-"
    assert.equal(sanitizeForPdf(input), 'résumé · café - naïve');
  });

  it('removes zero-width characters entirely', () => {
    assert.equal(sanitizeForPdf('A\u200BB\uFEFFC'), 'ABC');
  });

  it('clamps absurdly long input to a sane length', () => {
    const huge = 'x'.repeat(10_000);
    const out = sanitizeForPdf(huge);
    // Hard ceiling is MAX_PDF_TEXT_LEN (4000) + the small "[...trim]"
    // suffix (~10 chars).  We assert with a small headroom so a future
    // tweak to the suffix wording doesn't break the test.
    assert.ok(out.length <= 4_020, `output should be clamped, got ${out.length}`);
    assert.ok(out.endsWith('[...trim]'));
  });

  it('is idempotent', () => {
    const input = '"smart" \u2014 quotes \u2018 \u2019 \uD83D\uDE00';
    const once = sanitizeForPdf(input);
    const twice = sanitizeForPdf(once);
    assert.equal(twice, once);
  });

  it('survives Buffer-stringification garbage', () => {
    // Anything that fails String() falls back; emulate by passing a
    // weird object that throws on toString.
    const evil = { toString() { throw new Error('boom'); } };
    assert.equal(sanitizeForPdf(evil, 'safe'), 'safe');
  });
});

describe('sanitizePairs', () => {
  it('sanitises both label and value of every pair', () => {
    const pairs = sanitizePairs([
      ['Name\u0000', 'Hello \u4E2D'],
      ['City', null],
      ['Note', undefined],
    ]);
    assert.deepEqual(pairs, [
      ['Name', 'Hello ?'],
      ['City', '-'],
      ['Note', '-'],
    ]);
  });
});
