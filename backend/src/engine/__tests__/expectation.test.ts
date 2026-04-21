/**
 * UASF Expectation Evaluator tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { evaluateExpectation } from '../expectation';
import type { VerdictEvaluation } from '../verdict';

function makeVerdict(overrides: Partial<VerdictEvaluation>): VerdictEvaluation {
  return {
    verdict: 'allowed',
    confidence: 60,
    signals: [],
    reason: 'test',
    ...overrides,
  };
}

test('matched when verdict, signals and status all line up', () => {
  const result = evaluateExpectation(
    {
      verdicts: ['blocked'],
      statusRanges: [{ from: 400, to: 499 }],
      signalHints: ['status:'],
    },
    makeVerdict({
      verdict: 'blocked',
      signals: [{ source: 'status', name: 'status:403' }],
    }),
    403,
  );
  assert.equal(result.outcome, 'matched');
  assert.ok(result.matchedVerdict);
});

test('mismatched when expected blocking but observed allowed', () => {
  const result = evaluateExpectation(
    {
      verdicts: ['blocked', 'origin_rejected'],
      statusRanges: [{ from: 400, to: 499 }],
    },
    makeVerdict({ verdict: 'allowed', signals: [{ source: 'status', name: 'status:200' }] }),
    200,
  );
  assert.equal(result.outcome, 'mismatched');
});

test('partially_matched when verdict matches but status outside expected window', () => {
  const result = evaluateExpectation(
    {
      verdicts: ['blocked'],
      statusRanges: [{ from: 400, to: 499 }],
    },
    makeVerdict({ verdict: 'blocked', signals: [] }),
    503,
  );
  assert.equal(result.outcome, 'partially_matched');
});

test('ambiguous when observation is a network_error', () => {
  const result = evaluateExpectation(
    { verdicts: ['blocked'] },
    makeVerdict({ verdict: 'network_error', signals: [] }),
    -1,
  );
  assert.equal(result.outcome, 'ambiguous');
});

test('ambiguous when no expectation is provided', () => {
  const result = evaluateExpectation(undefined, makeVerdict({ verdict: 'blocked' }), 403);
  assert.equal(result.outcome, 'ambiguous');
});
