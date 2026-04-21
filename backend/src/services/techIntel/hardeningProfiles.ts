/**
 * UASF Tech Intelligence — WAF Hardening Validation Profiles
 *
 * **This is a hardening / detection-validation surface, NOT a bypass
 * engine.**
 *
 *   - Every probe is hand-curated and exists to confirm that a properly
 *     configured WAF detects, normalizes, blocks, or challenges the
 *     request as expected.
 *   - There is NO operator-supplied payload field — payloads are baked
 *     into the probe definition so an admin reviewing this file can see
 *     the entire attack surface at a glance.
 *   - There is NO evasion / fragmentation / decoy / spoofing / stealth /
 *     proxy-rotation logic anywhere in the engine.  The probe defines
 *     what is sent; the orchestrator just sends it once and records the
 *     outcome.
 *   - Each probe declares its expected verdict family (`blocking`,
 *     `challenge`, `passthrough`).  The orchestrator compares observed
 *     vs expected via the existing UASF expectation engine.
 *
 * The probe payloads themselves are intentionally **canonical and
 * harmless** — they are widely-published WAF detection markers (such as
 * the `' OR 1=1 --` SQLi signature or `<script>alert(1)</script>`) used
 * specifically to validate that a defensive control is wired up.  No
 * exploit-grade payloads.
 */

import type { ExpectationSpec } from '../../engine/expectation';
import { expectationFromFamily } from '../../engine/expectation';

export type HardeningProbeCategory =
  | 'baseline_injection'
  | 'reflected_input'
  | 'path_normalization'
  | 'auth_token_invalidity'
  | 'header_trust_boundary'
  | 'method_override'
  | 'malformed_payload'
  | 'parser_schema'
  | 'rate_visibility'
  | 'cors_preflight'
  | 'telemetry_preservation';

export interface HardeningProbe {
  id: string;
  label: string;
  category: HardeningProbeCategory;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'HEAD';
  path: string;
  /** Static request body (string).  No operator interpolation. */
  body?: string;
  bodyContentType?: string;
  /**
   * Static request headers.  Only safe header keys are allowed (engine
   * filters anything starting with `X-Forwarded-` etc. is fine, but no
   * `Host` overrides — that is handled at the URL level).
   */
  headers?: Record<string, string>;
  /**
   * Operator-readable description shown next to the probe in the UI.  Be
   * specific about what the WAF should do.
   */
  rationale: string;
  /** Expectation evaluated by the existing UASF expectation engine. */
  expectation: ExpectationSpec;
}

export interface HardeningProfile {
  id: string;
  name: string;
  description: string;
  /** Hard cap on parallel probes.  Stays low to remain polite. */
  maxConcurrency: number;
  perRequestTimeoutMs: number;
  probes: HardeningProbe[];
}

// ---------------------------------------------------------------
// Probe definitions
// ---------------------------------------------------------------

/**
 * Baseline detection markers.  These are the canonical WAF unit-test
 * patterns; they are NOT tuned for evasion or stealth.
 */
const BASELINE_INJECTION_PROBES: HardeningProbe[] = [
  {
    id: 'baseline-sqli-or-1eq1',
    label: "Baseline SQLi marker (' OR 1=1 --)",
    category: 'baseline_injection',
    method: 'GET',
    path: "/?id=1' OR 1=1 --",
    rationale:
      'Confirms the WAF detects the canonical OR-equality SQLi marker on a query parameter and either blocks or challenges the request.',
    expectation: expectationFromFamily('blocking', ['mitigation:waf-block', 'edge', 'status:403']),
  },
  {
    id: 'baseline-xss-script-alert',
    label: 'Baseline reflected XSS marker (<script>alert(1)</script>)',
    category: 'baseline_injection',
    method: 'GET',
    path: '/?q=%3Cscript%3Ealert%281%29%3C/script%3E',
    rationale:
      'Confirms the WAF detects the canonical reflected XSS marker in a query parameter.',
    expectation: expectationFromFamily('blocking'),
  },
  {
    id: 'baseline-traversal-etcpasswd',
    label: 'Baseline path-traversal marker (../../../etc/passwd)',
    category: 'baseline_injection',
    method: 'GET',
    path: '/?file=..%2F..%2F..%2Fetc%2Fpasswd',
    rationale:
      'Confirms the WAF detects the canonical Linux path-traversal marker.',
    expectation: expectationFromFamily('blocking'),
  },
];

const REFLECTED_INPUT_PROBES: HardeningProbe[] = [
  {
    id: 'reflected-svg-onload',
    label: 'Reflected XSS marker (SVG/onload)',
    category: 'reflected_input',
    method: 'GET',
    path: '/?q=%3Csvg%2Fonload%3Dalert%281%29%3E',
    rationale:
      'Validates that the WAF normalizes uppercase-attribute and SVG-based XSS markers, not only the bare <script> form.',
    expectation: expectationFromFamily('blocking'),
  },
];

const PATH_NORMALIZATION_PROBES: HardeningProbe[] = [
  {
    id: 'pathnorm-double-encoded',
    label: 'Double-encoded path-traversal',
    category: 'path_normalization',
    method: 'GET',
    path: '/?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    rationale:
      'Validates whether the WAF performs canonicalisation of double-encoded sequences and still detects the underlying path-traversal marker.',
    expectation: expectationFromFamily('blocking'),
  },
  {
    id: 'pathnorm-mixed-case-script',
    label: 'Mixed-case <ScRiPt> tag',
    category: 'path_normalization',
    method: 'GET',
    path: '/?q=%3CScRiPt%3Ealert(1)%3C%2FScRiPt%3E',
    rationale:
      'Validates whether the WAF normalises tag case before evaluating XSS rules.',
    expectation: expectationFromFamily('blocking'),
  },
];

const AUTH_TOKEN_PROBES: HardeningProbe[] = [
  {
    id: 'auth-bearer-malformed',
    label: 'Malformed Bearer token (no signature)',
    category: 'auth_token_invalidity',
    method: 'GET',
    path: '/api/private',
    headers: { Authorization: 'Bearer not-a-real-token' },
    rationale:
      'Confirms the protected origin (or its WAF) rejects a malformed Bearer token rather than passing it through.',
    expectation: expectationFromFamily('reject', ['status:401', 'status:403']),
  },
];

const HEADER_TRUST_PROBES: HardeningProbe[] = [
  {
    id: 'header-x-forwarded-spoof',
    label: 'X-Forwarded-For spoof attempt',
    category: 'header_trust_boundary',
    method: 'GET',
    path: '/',
    headers: { 'X-Forwarded-For': '127.0.0.1' },
    rationale:
      'Validates the WAF normalises X-Forwarded-For for trust decisions (does not silently treat the client as 127.0.0.1).  Expected behaviour: response should be the same as without the header — no privileged response.',
    expectation: { verdicts: ['allowed', 'origin_rejected', 'edge_mitigated'], rationale: 'Spoof should not yield privileged content.' },
  },
];

const METHOD_OVERRIDE_PROBES: HardeningProbe[] = [
  {
    id: 'method-override-delete',
    label: 'X-HTTP-Method-Override: DELETE',
    category: 'method_override',
    method: 'POST',
    path: '/',
    headers: { 'X-HTTP-Method-Override': 'DELETE' },
    rationale:
      'Validates whether the origin or WAF respects X-HTTP-Method-Override semantics and treats this as a destructive call.  Expected: blocked or rejected; never silently accepted.',
    expectation: expectationFromFamily('reject'),
  },
];

const MALFORMED_PAYLOAD_PROBES: HardeningProbe[] = [
  {
    id: 'malformed-content-type-mismatch',
    label: 'Content-Type/body mismatch (XML body, JSON header)',
    category: 'malformed_payload',
    method: 'POST',
    path: '/api/echo',
    body: '<root><value>1</value></root>',
    bodyContentType: 'application/json',
    rationale:
      'Validates that the WAF / origin rejects requests where Content-Type and body parser are mismatched.',
    expectation: expectationFromFamily('reject'),
  },
];

const PARSER_SCHEMA_PROBES: HardeningProbe[] = [
  {
    id: 'parser-deeply-nested-json',
    label: 'Deeply-nested JSON (depth 64)',
    category: 'parser_schema',
    method: 'POST',
    path: '/api/echo',
    body: deeplyNestedJson(64),
    bodyContentType: 'application/json',
    rationale:
      'Validates the WAF / origin enforces a sane parser depth limit and does not silently process JSON of arbitrary depth.',
    expectation: expectationFromFamily('reject'),
  },
];

const RATE_VISIBILITY_PROBES: HardeningProbe[] = [
  {
    id: 'rate-visibility-marker',
    label: 'Rate visibility marker request',
    category: 'rate_visibility',
    method: 'GET',
    path: '/?ratecheck=1',
    headers: { 'User-Agent': 'UASF-Validation/1.0 (+rate-visibility-probe)' },
    rationale:
      'Visibility probe only — confirms that single, well-identified requests are not flagged as automation by themselves.',
    expectation: { verdicts: ['allowed', 'edge_mitigated'], rationale: 'Single request should not trip rate-limiting.' },
  },
];

const CORS_PROBES: HardeningProbe[] = [
  {
    id: 'cors-preflight-disallowed-origin',
    label: 'CORS preflight from a non-allowed origin',
    category: 'cors_preflight',
    method: 'OPTIONS',
    path: '/api',
    headers: {
      Origin: 'https://uasf-cors-validator.invalid',
      'Access-Control-Request-Method': 'GET',
    },
    rationale:
      'Validates that the origin server enforces a CORS allowlist on its preflight response and does not echo arbitrary origins.',
    expectation: { verdicts: ['allowed', 'origin_rejected', 'edge_mitigated'], rationale: 'Inspect ACAO header in evidence rather than verdict.' },
  },
];

const TELEMETRY_PROBES: HardeningProbe[] = [
  {
    id: 'telemetry-error-page-leak',
    label: 'Error-page telemetry preservation',
    category: 'telemetry_preservation',
    method: 'GET',
    path: '/this-path-should-not-exist-uasf-' + Date.now().toString(36),
    rationale:
      'Validates that 404 / error pages do not disclose stack traces, framework versions, or internal paths.',
    expectation: { verdicts: ['origin_rejected', 'edge_mitigated', 'allowed'], rationale: 'Verdict is informational; evidence drawer shows body.' },
  },
];

function deeplyNestedJson(depth: number): string {
  let body = '0';
  for (let i = 0; i < depth; i += 1) body = `{"a":${body}}`;
  return body;
}

// ---------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------

export const HARDENING_PROFILES: HardeningProfile[] = [
  {
    id: 'waf-baseline-detection-validation',
    name: 'WAF Baseline Detection Validation',
    description:
      'Issues canonical SQLi, XSS, and path-traversal markers to confirm the WAF is actively detecting baseline attack signatures.  Safe for approved lab targets.',
    maxConcurrency: 2,
    perRequestTimeoutMs: 8_000,
    probes: [...BASELINE_INJECTION_PROBES, ...REFLECTED_INPUT_PROBES],
  },
  {
    id: 'waf-normalization-validation',
    name: 'Path & Encoding Normalization Validation',
    description:
      'Sends double-encoded and mixed-case variants of canonical attack markers to confirm the WAF normalises encodings before rule evaluation.',
    maxConcurrency: 2,
    perRequestTimeoutMs: 8_000,
    probes: [...PATH_NORMALIZATION_PROBES],
  },
  {
    id: 'waf-trust-boundary-validation',
    name: 'Trust Boundary & Method Override Validation',
    description:
      'Validates header trust handling (X-Forwarded-For), method override, and auth-token rejection paths.',
    maxConcurrency: 2,
    perRequestTimeoutMs: 8_000,
    probes: [...HEADER_TRUST_PROBES, ...METHOD_OVERRIDE_PROBES, ...AUTH_TOKEN_PROBES],
  },
  {
    id: 'waf-parser-resilience-validation',
    name: 'Parser & Schema Resilience Validation',
    description:
      'Sends malformed Content-Type / body combinations and deeply-nested JSON to confirm parser limits and schema enforcement.',
    maxConcurrency: 2,
    perRequestTimeoutMs: 8_000,
    probes: [...MALFORMED_PAYLOAD_PROBES, ...PARSER_SCHEMA_PROBES],
  },
  {
    id: 'waf-observability-validation',
    name: 'Observability & Telemetry Preservation',
    description:
      'CORS preflight, rate-visibility, and error-page telemetry probes.  Useful to confirm WAF telemetry remains intact and error pages do not leak stack traces.',
    maxConcurrency: 2,
    perRequestTimeoutMs: 8_000,
    probes: [...CORS_PROBES, ...RATE_VISIBILITY_PROBES, ...TELEMETRY_PROBES],
  },
  {
    id: 'waf-comprehensive-hardening-validation',
    name: 'Comprehensive Hardening Validation',
    description:
      'Runs every curated probe set in a single sweep.  Approved lab targets only.',
    maxConcurrency: 3,
    perRequestTimeoutMs: 8_000,
    probes: [
      ...BASELINE_INJECTION_PROBES,
      ...REFLECTED_INPUT_PROBES,
      ...PATH_NORMALIZATION_PROBES,
      ...HEADER_TRUST_PROBES,
      ...METHOD_OVERRIDE_PROBES,
      ...AUTH_TOKEN_PROBES,
      ...MALFORMED_PAYLOAD_PROBES,
      ...PARSER_SCHEMA_PROBES,
      ...CORS_PROBES,
      ...RATE_VISIBILITY_PROBES,
      ...TELEMETRY_PROBES,
    ],
  },
];

export function findHardeningProfile(profileId: string): HardeningProfile | null {
  return HARDENING_PROFILES.find((p) => p.id === profileId) ?? null;
}
