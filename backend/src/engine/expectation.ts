/**
 * UASF Expected vs Observed Evaluation
 *
 * Each scenario request can declare a structured expectation of how the
 * platform under test should respond (verdict family, signal hints, status
 * windows). Runtime observations are then matched against those expectations
 * to produce one of: matched | partially_matched | mismatched | ambiguous.
 *
 * This is the layer that prevents misleading "allowed" telemetry: if a
 * scenario expected blocking/rejection but the response was challenged or
 * passed through, the mismatch is surfaced explicitly.
 */

import type { Verdict, VerdictEvaluation, VerdictSignal } from './verdict';

export type ExpectationOutcome = 'matched' | 'partially_matched' | 'mismatched' | 'ambiguous';

export interface ExpectationSpec {
  /** Acceptable verdicts; if observation falls into this set, that part matches. */
  verdicts: Verdict[];
  /** Optional substrings expected within signal names (case-insensitive). */
  signalHints?: string[];
  /** Optional acceptable HTTP status windows (inclusive). */
  statusRanges?: Array<{ from: number; to: number }>;
  /** Free-form note for operators. */
  rationale?: string;
}

export interface ExpectationEvaluation {
  outcome: ExpectationOutcome;
  matchedVerdict: boolean;
  matchedSignals: boolean;
  matchedStatus: boolean;
  reasons: string[];
  expected: ExpectationSpec;
}

const VERDICT_FAMILY: Record<string, Verdict[]> = {
  blocking: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
  reject: ['blocked', 'origin_rejected'],
  challenge: ['challenged'],
  passthrough: ['allowed'],
};

/** Convenience: build an ExpectationSpec from a high-level family keyword. */
export function expectationFromFamily(family: keyof typeof VERDICT_FAMILY, hints?: string[]): ExpectationSpec {
  return {
    verdicts: [...VERDICT_FAMILY[family]],
    signalHints: hints,
    rationale: `Expected verdict family: ${family}`,
  };
}

function statusInRange(status: number, ranges: ExpectationSpec['statusRanges']): boolean {
  if (!ranges || ranges.length === 0) return true;
  return ranges.some((range) => status >= range.from && status <= range.to);
}

function signalsMatch(signals: VerdictSignal[], hints?: string[]): boolean {
  if (!hints || hints.length === 0) return true;
  if (signals.length === 0) return false;
  const namespaced = signals.map((s) => s.name.toLowerCase());
  return hints.every((hint) => namespaced.some((name) => name.includes(hint.toLowerCase())));
}

/**
 * Evaluates a verdict against an expectation spec. Verdict mismatch dominates;
 * a status mismatch alone downgrades to partially_matched. Lack of signals
 * with a populated hint list is treated as partial.
 */
export function evaluateExpectation(
  expected: ExpectationSpec | undefined,
  observed: VerdictEvaluation,
  observedStatus: number,
): ExpectationEvaluation {
  if (!expected) {
    return {
      outcome: 'ambiguous',
      matchedVerdict: false,
      matchedSignals: false,
      matchedStatus: false,
      reasons: ['No expectation spec was provided for this scenario request.'],
      expected: { verdicts: [], rationale: 'No expectation declared.' },
    };
  }

  const matchedVerdict = expected.verdicts.length === 0 || expected.verdicts.includes(observed.verdict);
  const matchedSignals = signalsMatch(observed.signals, expected.signalHints);
  const matchedStatus = statusInRange(observedStatus, expected.statusRanges);

  const reasons: string[] = [];

  if (!matchedVerdict) {
    reasons.push(
      `Verdict mismatch: expected ${expected.verdicts.join(' | ') || 'any'}, observed ${observed.verdict}.`,
    );
  } else {
    reasons.push(`Verdict matched expectation (${observed.verdict}).`);
  }

  if (!matchedSignals) {
    reasons.push(
      `Signal hints not satisfied. Required: ${(expected.signalHints ?? []).join(', ') || 'none'}; observed: ${
        observed.signals.map((s) => s.name).join(', ') || 'none'
      }.`,
    );
  }

  if (!matchedStatus) {
    reasons.push(
      `HTTP status outside expected ranges: observed ${observedStatus}; expected ${(expected.statusRanges ?? [])
        .map((r) => `${r.from}-${r.to}`)
        .join(' | ') || 'unspecified'}.`,
    );
  }

  if (observed.verdict === 'network_error') {
    return {
      outcome: 'ambiguous',
      matchedVerdict,
      matchedSignals,
      matchedStatus,
      reasons: [
        ...reasons,
        'Observation was a transport-level failure; expectation cannot be confirmed.',
      ],
      expected,
    };
  }

  if (matchedVerdict && matchedSignals && matchedStatus) {
    return {
      outcome: 'matched',
      matchedVerdict,
      matchedSignals,
      matchedStatus,
      reasons,
      expected,
    };
  }

  if (!matchedVerdict) {
    return {
      outcome: 'mismatched',
      matchedVerdict,
      matchedSignals,
      matchedStatus,
      reasons,
      expected,
    };
  }

  return {
    outcome: 'partially_matched',
    matchedVerdict,
    matchedSignals,
    matchedStatus,
    reasons,
    expected,
  };
}
