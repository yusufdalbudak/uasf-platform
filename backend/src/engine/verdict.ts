/**
 * UASF Verdict Classification
 *
 * Vendor-agnostic classification of HTTP response telemetry into a structured
 * verdict that respects mitigation, challenge, edge interception, and origin
 * behavior. Avoids the historical mistake of treating "HTTP 200" as a clean
 * pass-through success when an edge protector served a challenge or mitigation
 * page.
 */

export type Verdict =
  | 'blocked'
  | 'challenged'
  | 'edge_mitigated'
  | 'origin_rejected'
  | 'allowed'
  | 'network_error'
  | 'ambiguous';

export interface VerdictSignal {
  source: 'header' | 'body' | 'status' | 'transport';
  name: string;
  detail?: string;
}

export interface VerdictEvaluation {
  verdict: Verdict;
  confidence: number;
  signals: VerdictSignal[];
  reason: string;
}

export interface VerdictInput {
  status: number;
  headers: Record<string, string> | null | undefined;
  bodyPreview: string | null | undefined;
  errorMessage?: string | null;
  /** Final URL the response actually came from (after redirects), if known. */
  finalUrl?: string | null;
}

interface SignalIndicator {
  name: string;
  /** Header value substring or regex (case-insensitive). */
  pattern: RegExp;
  /** Verdict to assign when the indicator is observed. */
  verdict: Verdict;
}

const HEADER_INDICATORS: Array<{
  header: string;
  patterns: SignalIndicator[];
}> = [
  {
    header: 'server',
    patterns: [
      { name: 'edge:cloudflare', pattern: /\bcloudflare\b/i, verdict: 'edge_mitigated' },
      { name: 'edge:akamai', pattern: /\bakamaighost\b|\bakamai\b/i, verdict: 'edge_mitigated' },
      { name: 'edge:fastly', pattern: /\bfastly\b/i, verdict: 'edge_mitigated' },
      { name: 'edge:cloudfront', pattern: /\bcloudfront\b/i, verdict: 'edge_mitigated' },
      { name: 'edge:apptrana', pattern: /\bapptrana\b/i, verdict: 'edge_mitigated' },
      { name: 'edge:imperva', pattern: /\bimperva\b/i, verdict: 'edge_mitigated' },
      { name: 'edge:f5-bigip', pattern: /\bbig-?ip\b/i, verdict: 'edge_mitigated' },
      { name: 'edge:awselb', pattern: /\bawselb\b/i, verdict: 'edge_mitigated' },
    ],
  },
  {
    header: 'cf-ray',
    patterns: [{ name: 'edge:cloudflare-ray', pattern: /.+/i, verdict: 'edge_mitigated' }],
  },
  {
    header: 'cf-mitigated',
    patterns: [{ name: 'mitigation:cloudflare', pattern: /\bchallenge\b/i, verdict: 'challenged' }],
  },
  {
    header: 'x-akamai-transformed',
    patterns: [{ name: 'edge:akamai-transformed', pattern: /.+/, verdict: 'edge_mitigated' }],
  },
  {
    header: 'x-amz-cf-id',
    patterns: [{ name: 'edge:cloudfront-id', pattern: /.+/, verdict: 'edge_mitigated' }],
  },
  {
    header: 'x-sucuri-id',
    patterns: [{ name: 'edge:sucuri', pattern: /.+/, verdict: 'edge_mitigated' }],
  },
  {
    header: 'x-iinfo',
    patterns: [{ name: 'edge:imperva-iinfo', pattern: /.+/, verdict: 'edge_mitigated' }],
  },
  {
    header: 'x-apptrana',
    patterns: [{ name: 'edge:apptrana-block', pattern: /\bblock(ed)?\b|\bdeny\b/i, verdict: 'blocked' }],
  },
];

const BODY_INDICATORS: SignalIndicator[] = [
  { name: 'challenge:cloudflare-attention', pattern: /attention required\s*\|\s*cloudflare/i, verdict: 'challenged' },
  { name: 'challenge:cloudflare-cf-error', pattern: /cf-error-details|cloudflare ray id/i, verdict: 'challenged' },
  { name: 'challenge:cf-turnstile', pattern: /turnstile|cf-?challenge|__cf_chl_/i, verdict: 'challenged' },
  { name: 'challenge:akamai-bm', pattern: /pixel_[0-9a-f]{5,}\.js|akam_/i, verdict: 'challenged' },
  { name: 'challenge:imperva-incapsula', pattern: /incapsula incident id|_incapsula_resource/i, verdict: 'challenged' },
  { name: 'challenge:perimeterx', pattern: /please verify you are a human|px-captcha|perimeterx/i, verdict: 'challenged' },
  { name: 'challenge:datadome', pattern: /datadome|please enable js and disable any ad blocker/i, verdict: 'challenged' },
  { name: 'challenge:hcaptcha', pattern: /h-captcha|hcaptcha\.com/i, verdict: 'challenged' },
  { name: 'challenge:recaptcha', pattern: /g-recaptcha|recaptcha\/api\.js/i, verdict: 'challenged' },
  { name: 'mitigation:waf-block', pattern: /access denied|request blocked|forbidden by (security|firewall)|blocked by .* (firewall|waf)/i, verdict: 'blocked' },
];

function lowerHeaders(headers: Record<string, string> | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') {
      out[key.toLowerCase()] = value;
    }
  }
  return out;
}

function pushUnique(list: VerdictSignal[], signal: VerdictSignal): void {
  if (list.some((existing) => existing.name === signal.name)) return;
  list.push(signal);
}

function dominantVerdict(observed: Verdict[]): Verdict {
  // Severity precedence: explicit block > challenge > edge_mitigated > origin_rejected > allowed > ambiguous > network_error
  const order: Verdict[] = [
    'network_error',
    'blocked',
    'challenged',
    'edge_mitigated',
    'origin_rejected',
    'allowed',
    'ambiguous',
  ];
  for (const candidate of order) {
    if (observed.includes(candidate)) return candidate;
  }
  return 'ambiguous';
}

/**
 * Classifies an HTTP exchange into a structured UASF verdict using header,
 * body, status, and transport-level signals. Never collapses uncertainty into
 * an "allowed" success.
 */
export function classifyResponseVerdict(input: VerdictInput): VerdictEvaluation {
  const signals: VerdictSignal[] = [];

  if (input.errorMessage || input.status === -1 || input.status === 0) {
    return {
      verdict: 'network_error',
      confidence: 95,
      signals: [
        {
          source: 'transport',
          name: 'transport:network-error',
          detail: input.errorMessage ?? 'No status code returned by transport.',
        },
      ],
      reason: 'Transport-level failure: connection or timeout error before a complete HTTP response was received.',
    };
  }

  const headers = lowerHeaders(input.headers);
  const body = input.bodyPreview ?? '';

  const observedVerdicts: Verdict[] = [];

  for (const indicator of HEADER_INDICATORS) {
    const value = headers[indicator.header];
    if (typeof value !== 'string' || value.length === 0) continue;
    for (const pattern of indicator.patterns) {
      if (pattern.pattern.test(value)) {
        pushUnique(signals, {
          source: 'header',
          name: pattern.name,
          detail: `${indicator.header}: ${value}`,
        });
        observedVerdicts.push(pattern.verdict);
      }
    }
  }

  if (typeof body === 'string' && body.length > 0) {
    for (const indicator of BODY_INDICATORS) {
      if (indicator.pattern.test(body)) {
        pushUnique(signals, { source: 'body', name: indicator.name });
        observedVerdicts.push(indicator.verdict);
      }
    }
  }

  // Status code signals (only used as supporting evidence, never as sole verdict).
  if (input.status === 401 || input.status === 403) {
    pushUnique(signals, { source: 'status', name: `status:${input.status}` });
    if (!observedVerdicts.includes('challenged') && !observedVerdicts.includes('edge_mitigated')) {
      observedVerdicts.push('blocked');
    }
  } else if (input.status === 406 || input.status === 418 || input.status === 429) {
    pushUnique(signals, { source: 'status', name: `status:${input.status}` });
    observedVerdicts.push('blocked');
  } else if (input.status >= 400 && input.status < 500) {
    pushUnique(signals, { source: 'status', name: `status:${input.status}` });
    if (!observedVerdicts.length) {
      observedVerdicts.push('origin_rejected');
    }
  } else if (input.status >= 500 && input.status < 600) {
    pushUnique(signals, { source: 'status', name: `status:${input.status}` });
    observedVerdicts.push('origin_rejected');
  } else if (input.status >= 200 && input.status < 400) {
    pushUnique(signals, { source: 'status', name: `status:${input.status}` });
    if (!observedVerdicts.length) {
      observedVerdicts.push('allowed');
    }
  } else {
    pushUnique(signals, { source: 'status', name: `status:${input.status}` });
    observedVerdicts.push('ambiguous');
  }

  // Body-derived challenge while status is 200 is a classic "mitigated success".
  // Force at least challenged/edge_mitigated rather than allowed.
  if (
    observedVerdicts.includes('allowed') &&
    (observedVerdicts.includes('challenged') ||
      observedVerdicts.includes('edge_mitigated') ||
      observedVerdicts.includes('blocked'))
  ) {
    const filtered = observedVerdicts.filter((v) => v !== 'allowed');
    observedVerdicts.length = 0;
    observedVerdicts.push(...filtered);
  }

  const verdict = dominantVerdict(observedVerdicts);
  const confidence = computeConfidence(verdict, signals.length, input.status);
  const reason = describeVerdict(verdict, signals, input.status);

  return { verdict, confidence, signals, reason };
}

function computeConfidence(verdict: Verdict, signalCount: number, status: number): number {
  if (verdict === 'network_error') return 95;
  if (verdict === 'blocked' && status >= 400 && status < 500) {
    return Math.min(95, 70 + signalCount * 5);
  }
  if (verdict === 'challenged') return Math.min(90, 65 + signalCount * 5);
  if (verdict === 'edge_mitigated') return Math.min(80, 55 + signalCount * 5);
  if (verdict === 'origin_rejected') return Math.min(85, 60 + signalCount * 5);
  if (verdict === 'allowed') return Math.min(75, 50 + signalCount * 5);
  return 40;
}

function describeVerdict(verdict: Verdict, signals: VerdictSignal[], status: number): string {
  const tag = signals.map((s) => s.name).join(', ');
  switch (verdict) {
    case 'blocked':
      return `Request blocked by upstream control (HTTP ${status}). Indicators: ${tag || 'status only'}.`;
    case 'challenged':
      return `Edge served a verification/challenge response (HTTP ${status}). Indicators: ${tag}.`;
    case 'edge_mitigated':
      return `Response was mediated by an edge platform (HTTP ${status}). Indicators: ${tag}.`;
    case 'origin_rejected':
      return `Origin returned an error response (HTTP ${status}).`;
    case 'allowed':
      return `Response appears to have reached the origin without observable mitigation (HTTP ${status}).`;
    case 'network_error':
      return 'Transport-level failure; no complete HTTP response observed.';
    case 'ambiguous':
      return `Insufficient signals to classify the response (HTTP ${status}).`;
    default:
      return 'Unclassified response.';
  }
}
