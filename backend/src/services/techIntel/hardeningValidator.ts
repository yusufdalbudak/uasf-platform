/**
 * UASF Tech Intelligence — Hardening Validator
 *
 * Executes a curated {@link HardeningProfile} against an approved
 * target.  For each probe:
 *
 *   1. Issues the canonical request (no operator interpolation, no
 *      payload mutation, no proxy rotation, no decoys).
 *   2. Captures the response status, headers, and a trimmed body
 *      preview.
 *   3. Runs the existing UASF verdict classifier and expectation
 *      evaluator.
 *   4. Returns a normalized event ready for persistence.
 *
 * The validator is **safe-by-default**: it executes probes serially up
 * to `maxConcurrency`, with a hard per-request timeout, and skips any
 * probe that would talk to a non-approved target (the orchestrator
 * already enforces this at the request boundary, but we re-validate
 * here as defence in depth).
 */

import { assertSafeScanHostname } from '../../engine/modules/utils';
import { classifyResponseVerdict, type Verdict, type VerdictSignal } from '../../engine/verdict';
import { evaluateExpectation, type ExpectationOutcome } from '../../engine/expectation';
import {
  findHardeningProfile,
  type HardeningProbe,
  type HardeningProfile,
} from './hardeningProfiles';

export interface HardeningEvent {
  probeId: string;
  probeLabel: string;
  category: HardeningProbe['category'];
  method: string;
  path: string;
  responseStatus: number;
  responseDurationMs: number;
  observedVerdict: Verdict;
  observedConfidence: number;
  verdictSignals: VerdictSignal[];
  expectedVerdicts: string;
  expectationOutcome: ExpectationOutcome;
  expectationReasons: string[];
  bodyPreview: string | null;
  responseHeaders: Record<string, string>;
  errorMessage: string | null;
}

export interface HardeningResult {
  resolvedHostname: string;
  events: HardeningEvent[];
  durationMs: number;
}

const BODY_PREVIEW_MAX = 512;
const HEADER_LIMIT = 32;

const DEFAULT_HEADERS: Record<string, string> = {
  Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
  'User-Agent': 'UASF-Hardening-Validation/1.0 (+approved-target-only)',
};

export async function runHardeningValidation(
  hostname: string,
  profileId: string,
): Promise<HardeningResult> {
  const profile = findHardeningProfile(profileId);
  if (!profile) {
    throw new Error(`Unknown hardening profile: ${profileId}`);
  }
  const safeHostname = assertSafeScanHostname(hostname);
  const startedAt = Date.now();

  // Run probes in bounded-concurrency batches.  Order is preserved per
  // batch so the UI timeline shows them in declaration order.
  const events: HardeningEvent[] = [];
  const batches = chunk(profile.probes, profile.maxConcurrency);
  for (const batch of batches) {
    const settled = await Promise.allSettled(
      batch.map((probe) => executeProbe(safeHostname, profile, probe)),
    );
    for (let i = 0; i < settled.length; i += 1) {
      const probe = batch[i];
      const result = settled[i];
      if (result.status === 'fulfilled') {
        events.push(result.value);
      } else {
        events.push(buildErrorEvent(probe, result.reason));
      }
    }
  }

  return {
    resolvedHostname: safeHostname,
    events,
    durationMs: Date.now() - startedAt,
  };
}

async function executeProbe(
  safeHostname: string,
  profile: HardeningProfile,
  probe: HardeningProbe,
): Promise<HardeningEvent> {
  const startedAt = Date.now();
  const url = `https://${safeHostname}${probe.path.startsWith('/') ? probe.path : `/${probe.path}`}`;

  const headers: Record<string, string> = { ...DEFAULT_HEADERS, ...(probe.headers ?? {}) };
  if (probe.body && !headers['Content-Type']) {
    headers['Content-Type'] = probe.bodyContentType ?? 'application/octet-stream';
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), profile.perRequestTimeoutMs);

  try {
    const response = await fetch(url, {
      method: probe.method,
      headers,
      body: probe.body,
      redirect: 'follow',
      signal: controller.signal,
    });
    const body = await safeReadText(response);
    const responseHeaders = collectHeaders(response.headers);
    const verdict = classifyResponseVerdict({
      status: response.status,
      headers: responseHeaders,
      bodyPreview: body,
      finalUrl: response.url,
    });
    const expectation = evaluateExpectation(probe.expectation, verdict, response.status);

    return {
      probeId: probe.id,
      probeLabel: probe.label,
      category: probe.category,
      method: probe.method,
      path: probe.path,
      responseStatus: response.status,
      responseDurationMs: Date.now() - startedAt,
      observedVerdict: verdict.verdict,
      observedConfidence: verdict.confidence,
      verdictSignals: verdict.signals,
      expectedVerdicts: probe.expectation.verdicts.join('|'),
      expectationOutcome: expectation.outcome,
      expectationReasons: expectation.reasons,
      bodyPreview: body ? body.slice(0, BODY_PREVIEW_MAX) : null,
      responseHeaders,
      errorMessage: null,
    };
  } catch (err) {
    const message = (err as Error).message ?? 'unknown error';
    const verdict = classifyResponseVerdict({
      status: -1,
      headers: {},
      bodyPreview: null,
      errorMessage: message,
    });
    const expectation = evaluateExpectation(probe.expectation, verdict, -1);
    return {
      probeId: probe.id,
      probeLabel: probe.label,
      category: probe.category,
      method: probe.method,
      path: probe.path,
      responseStatus: -1,
      responseDurationMs: Date.now() - startedAt,
      observedVerdict: verdict.verdict,
      observedConfidence: verdict.confidence,
      verdictSignals: verdict.signals,
      expectedVerdicts: probe.expectation.verdicts.join('|'),
      expectationOutcome: expectation.outcome,
      expectationReasons: expectation.reasons,
      bodyPreview: null,
      responseHeaders: {},
      errorMessage: message,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function buildErrorEvent(probe: HardeningProbe, reason: unknown): HardeningEvent {
  const message = reason instanceof Error ? reason.message : String(reason);
  return {
    probeId: probe.id,
    probeLabel: probe.label,
    category: probe.category,
    method: probe.method,
    path: probe.path,
    responseStatus: -1,
    responseDurationMs: 0,
    observedVerdict: 'network_error',
    observedConfidence: 90,
    verdictSignals: [{ source: 'transport', name: 'transport:exception', detail: message }],
    expectedVerdicts: probe.expectation.verdicts.join('|'),
    expectationOutcome: 'ambiguous',
    expectationReasons: ['Probe execution failed before a response was received.'],
    bodyPreview: null,
    responseHeaders: {},
    errorMessage: message,
  };
}

function collectHeaders(source: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  let count = 0;
  source.forEach((value, key) => {
    if (count >= HEADER_LIMIT) return;
    out[key.toLowerCase()] = value;
    count += 1;
  });
  return out;
}

async function safeReadText(response: Response): Promise<string> {
  try {
    return (await response.text()) ?? '';
  } catch {
    return '';
  }
}

function chunk<T>(arr: T[], size: number): T[][] {
  if (size <= 0) return [arr];
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}
