import { env } from '../config/env';

/**
 * VirusTotal Public API v3 lookup proxy.
 *
 * Why this lives on the backend, not the browser:
 *   - VirusTotal explicitly warns against embedding the API key in any
 *     client-shippable artifact (the value would leak to every visitor).
 *   - The free tier is metered (4 lookups/min, 500/day, 15.5K/month) so we
 *     also need a single chokepoint for rate-limit enforcement and caching.
 *
 * Hardening:
 *   - Every lookup has an aggressive in-memory TTL cache so repeated clicks
 *     on the same indicator never spend extra quota.
 *   - We refuse to forward any indicator that doesn't match a strict regex
 *     for its declared kind, so the backend can't be coerced into making
 *     arbitrary requests on behalf of a caller.
 *   - We never echo the API key back; only normalized verdict data is
 *     returned to the frontend.
 *   - All upstream errors are mapped to a small, explicit set of statuses
 *     so the UI can render them without leaking provider implementation
 *     details.
 */

const VT_BASE = 'https://www.virustotal.com/api/v3';
const REQUEST_TIMEOUT_MS = 15_000;
/** Cache TTL: 10 minutes. Aligns well with the 4 req/min free quota and
 *  is short enough that recently-changed verdicts surface quickly. */
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX_ENTRIES = 500;

export type VtLookupKind = 'sha256' | 'sha1' | 'md5' | 'url' | 'domain' | 'ipv4';

const HEX_64 = /^[a-f0-9]{64}$/i;
const HEX_40 = /^[a-f0-9]{40}$/i;
const HEX_32 = /^[a-f0-9]{32}$/i;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
// RFC-style hostname (labels of 1-63 chars, total <= 253). Accepts xn-- (IDN).
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

/**
 * Validate the indicator matches the declared kind. Returns the normalized
 * value (lowercased / trimmed) or `null` when the value is malformed.
 */
function validateIndicator(kind: VtLookupKind, raw: string): string | null {
  const v = String(raw ?? '').trim();
  if (!v) return null;
  switch (kind) {
    case 'sha256':
      return HEX_64.test(v) ? v.toLowerCase() : null;
    case 'sha1':
      return HEX_40.test(v) ? v.toLowerCase() : null;
    case 'md5':
      return HEX_32.test(v) ? v.toLowerCase() : null;
    case 'ipv4':
      return IPV4.test(v) ? v : null;
    case 'domain':
      return DOMAIN.test(v) ? v.toLowerCase() : null;
    case 'url': {
      try {
        const u = new URL(v);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
        return u.toString();
      } catch {
        return null;
      }
    }
    default:
      return null;
  }
}

/** Build the request path used by VT v3 for a given kind. */
function buildVtPath(kind: VtLookupKind, value: string): string {
  switch (kind) {
    case 'sha256':
    case 'sha1':
    case 'md5':
      return `/files/${value}`;
    case 'ipv4':
      return `/ip_addresses/${value}`;
    case 'domain':
      return `/domains/${value}`;
    case 'url': {
      // VT v3 wants the URL-id, which is the URL-safe base64 of the URL with
      // padding stripped. Computed inline so we don't pull a new dep.
      const id = Buffer.from(value).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      return `/urls/${id}`;
    }
  }
}

function buildPermalink(kind: VtLookupKind, value: string): string {
  switch (kind) {
    case 'sha256':
    case 'sha1':
    case 'md5':
      return `https://www.virustotal.com/gui/file/${value}`;
    case 'ipv4':
      return `https://www.virustotal.com/gui/ip-address/${value}`;
    case 'domain':
      return `https://www.virustotal.com/gui/domain/${value}`;
    case 'url':
      return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
  }
}

// ---------------------------------------------------------------------------
// Tiny in-memory TTL cache. Per-process and lost on restart, which is fine
// because the goal is just to absorb repeated clicks on the same indicator.
// ---------------------------------------------------------------------------

interface CacheEntry {
  expiresAt: number;
  payload: VtLookupResult;
}
const cache = new Map<string, CacheEntry>();

function cacheKey(kind: VtLookupKind, value: string): string {
  return `${kind}:${value}`;
}

function cacheGet(key: string): VtLookupResult | null {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() > hit.expiresAt) {
    cache.delete(key);
    return null;
  }
  return hit.payload;
}

function cacheSet(key: string, payload: VtLookupResult): void {
  if (cache.size >= CACHE_MAX_ENTRIES) {
    // Drop the oldest entry (Map preserves insertion order).
    const first = cache.keys().next().value;
    if (first !== undefined) cache.delete(first);
  }
  cache.set(key, { expiresAt: Date.now() + CACHE_TTL_MS, payload });
}

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

export type VtVerdict = 'malicious' | 'suspicious' | 'harmless' | 'undetected' | 'unknown';

export interface VtLookupResult {
  kind: VtLookupKind;
  value: string;
  verdict: VtVerdict;
  /** Raw last_analysis_stats from VT, if present. */
  stats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    timeout: number;
  } | null;
  /** Total engines that contributed to last_analysis_stats. */
  engines: number;
  /** Community reputation score (positive = trusted, negative = flagged). */
  reputation: number | null;
  /** ISO timestamp of the most recent analysis we know about. */
  lastAnalysisDate: string | null;
  /** Indicator-specific metadata (file type, sizes, registrar, asn, ...). */
  meta: Record<string, string | number | null>;
  /** Direct human-readable VT page for the indicator. */
  permalink: string;
  /** True when the indicator is unknown to VT (HTTP 404 from upstream). */
  notFound: boolean;
  /** True when this verdict came from the in-memory cache. */
  cached: boolean;
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

interface VtAttributes {
  last_analysis_stats?: {
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
    timeout?: number;
  };
  reputation?: number;
  last_analysis_date?: number;
  type_description?: string;
  meaningful_name?: string;
  size?: number;
  magic?: string;
  registrar?: string;
  whois_date?: number;
  as_owner?: string;
  asn?: number;
  country?: string;
  network?: string;
  title?: string;
  final_url?: string;
}

interface VtResponse {
  data?: { attributes?: VtAttributes };
}

function pickVerdict(stats: VtAttributes['last_analysis_stats']): VtVerdict {
  if (!stats) return 'unknown';
  const m = stats.malicious ?? 0;
  const s = stats.suspicious ?? 0;
  const h = stats.harmless ?? 0;
  const u = stats.undetected ?? 0;
  if (m > 0) return 'malicious';
  if (s > 0) return 'suspicious';
  if (h > 0) return 'harmless';
  if (u > 0) return 'undetected';
  return 'unknown';
}

function buildMeta(kind: VtLookupKind, attrs: VtAttributes): Record<string, string | number | null> {
  const meta: Record<string, string | number | null> = {};
  if (kind === 'sha256' || kind === 'sha1' || kind === 'md5') {
    if (attrs.meaningful_name) meta.name = attrs.meaningful_name;
    if (attrs.type_description) meta.type = attrs.type_description;
    if (typeof attrs.size === 'number') meta.size = attrs.size;
    if (attrs.magic) meta.magic = attrs.magic;
  } else if (kind === 'domain') {
    if (attrs.registrar) meta.registrar = attrs.registrar;
    if (attrs.whois_date) meta.whoisDate = new Date(attrs.whois_date * 1000).toISOString();
  } else if (kind === 'ipv4') {
    if (attrs.as_owner) meta.asOwner = attrs.as_owner;
    if (typeof attrs.asn === 'number') meta.asn = attrs.asn;
    if (attrs.country) meta.country = attrs.country;
    if (attrs.network) meta.network = attrs.network;
  } else if (kind === 'url') {
    if (attrs.title) meta.title = attrs.title;
    if (attrs.final_url) meta.finalUrl = attrs.final_url;
  }
  return meta;
}

function normalize(
  kind: VtLookupKind,
  value: string,
  body: VtResponse,
  cached: boolean,
): VtLookupResult {
  const attrs = body.data?.attributes ?? {};
  const stats = attrs.last_analysis_stats
    ? {
        malicious: attrs.last_analysis_stats.malicious ?? 0,
        suspicious: attrs.last_analysis_stats.suspicious ?? 0,
        harmless: attrs.last_analysis_stats.harmless ?? 0,
        undetected: attrs.last_analysis_stats.undetected ?? 0,
        timeout: attrs.last_analysis_stats.timeout ?? 0,
      }
    : null;
  const engines = stats
    ? stats.malicious + stats.suspicious + stats.harmless + stats.undetected + stats.timeout
    : 0;
  return {
    kind,
    value,
    verdict: pickVerdict(attrs.last_analysis_stats),
    stats,
    engines,
    reputation: typeof attrs.reputation === 'number' ? attrs.reputation : null,
    lastAnalysisDate: attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null,
    meta: buildMeta(kind, attrs),
    permalink: buildPermalink(kind, value),
    notFound: false,
    cached,
  };
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class VtLookupError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code: 'not_configured' | 'invalid_input' | 'rate_limited' | 'upstream_error' | 'timeout',
  ) {
    super(message);
    this.name = 'VtLookupError';
  }
}

// ---------------------------------------------------------------------------
// Public lookup function
// ---------------------------------------------------------------------------

/**
 * Whether the provider is configured. Cheap; safe to call on every request.
 */
export function isVirusTotalConfigured(): boolean {
  return !!env.virustotalApiKey;
}

export async function virustotalLookup(
  rawKind: string,
  rawValue: string,
): Promise<VtLookupResult> {
  if (!env.virustotalApiKey) {
    throw new VtLookupError(
      'VirusTotal lookups are not configured on this server.',
      503,
      'not_configured',
    );
  }
  const kind = rawKind as VtLookupKind;
  const validKinds: VtLookupKind[] = ['sha256', 'sha1', 'md5', 'url', 'domain', 'ipv4'];
  if (!validKinds.includes(kind)) {
    throw new VtLookupError(`Unsupported lookup kind: ${rawKind}`, 400, 'invalid_input');
  }
  const value = validateIndicator(kind, rawValue);
  if (value === null) {
    throw new VtLookupError(
      `Indicator does not match the declared kind (${kind}).`,
      400,
      'invalid_input',
    );
  }

  const key = cacheKey(kind, value);
  const cached = cacheGet(key);
  if (cached) return { ...cached, cached: true };

  const path = buildVtPath(kind, value);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(`${VT_BASE}${path}`, {
      headers: {
        'x-apikey': env.virustotalApiKey,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timer);
    const msg = (e as Error).message;
    if (msg.includes('aborted')) {
      throw new VtLookupError('VirusTotal request timed out.', 504, 'timeout');
    }
    throw new VtLookupError(`Upstream network error: ${msg}`, 502, 'upstream_error');
  }
  clearTimeout(timer);

  if (response.status === 404) {
    const result: VtLookupResult = {
      kind,
      value,
      verdict: 'unknown',
      stats: null,
      engines: 0,
      reputation: null,
      lastAnalysisDate: null,
      meta: {},
      permalink: buildPermalink(kind, value),
      notFound: true,
      cached: false,
    };
    cacheSet(key, result);
    return result;
  }

  if (response.status === 429) {
    throw new VtLookupError(
      'VirusTotal quota exhausted (free tier: 4/min, 500/day). Try again shortly.',
      429,
      'rate_limited',
    );
  }

  if (response.status === 401 || response.status === 403) {
    throw new VtLookupError(
      'VirusTotal rejected the API key (unauthorized).',
      response.status,
      'upstream_error',
    );
  }

  if (!response.ok) {
    throw new VtLookupError(
      `VirusTotal responded with HTTP ${response.status}.`,
      502,
      'upstream_error',
    );
  }

  const body = (await response.json().catch(() => ({}))) as VtResponse;
  const normalized = normalize(kind, value, body, false);
  cacheSet(key, normalized);
  return normalized;
}
