import { env } from '../config/env';

/**
 * abuse.ch API client — covers ThreatFox, URLhaus, and MalwareBazaar.
 *
 * Why one file:
 *   - All three services authenticate with the same `Auth-Key` header issued
 *     by https://auth.abuse.ch/, so credential and timeout handling collapse
 *     to one shared helper.
 *   - The response shapes differ but they all answer the same question
 *     ("does this provider know this indicator?"), so we normalize to one
 *     compact `AbuseChLookupResult` for the multi-source orchestrator.
 *
 * Hardening notes (matches `virustotalService.ts` posture):
 *   - The Auth-Key is only loaded from `env.abuseChAuthKey` and is never
 *     echoed in responses or logs.
 *   - Indicators are validated with the same strict regexes used elsewhere,
 *     so the backend cannot be coerced into making arbitrary upstream calls.
 *   - Each provider declares which kinds it supports; unsupported kinds are
 *     short-circuited locally instead of being forwarded.
 *   - All upstream errors collapse into a small set of statuses so the UI
 *     never sees provider-specific failure detail.
 */

const REQUEST_TIMEOUT_MS = 15_000;

export type AbuseLookupKind =
  | 'sha256'
  | 'sha1'
  | 'md5'
  | 'url'
  | 'domain'
  | 'ipv4';

const HEX_64 = /^[a-f0-9]{64}$/i;
const HEX_40 = /^[a-f0-9]{40}$/i;
const HEX_32 = /^[a-f0-9]{32}$/i;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

function validateIndicator(kind: AbuseLookupKind, raw: string): string | null {
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
    case 'url':
      try {
        const u = new URL(v);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
        return u.toString();
      } catch {
        return null;
      }
    default:
      return null;
  }
}

export type AbuseProviderId = 'threatfox' | 'urlhaus' | 'malwarebazaar';

/** Normalized cross-provider verdict so the UI can colour-code consistently. */
export type AbuseVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface AbuseChLookupResult {
  provider: AbuseProviderId;
  providerName: string;
  kind: AbuseLookupKind;
  value: string;
  /** True when the provider returned a hit for this indicator. */
  found: boolean;
  verdict: AbuseVerdict;
  /** Short, human-readable label (malware family, threat type, ...). */
  threatLabel: string | null;
  /** Confidence as reported by the provider (0-100), if available. */
  confidence: number | null;
  /** ISO timestamp the provider first observed the indicator, if available. */
  firstSeen: string | null;
  /** ISO timestamp of the most recent observation, if available. */
  lastSeen: string | null;
  /** Provider-specific tags (malware aliases, families, etc.). */
  tags: string[];
  /** Compact key/value pairs for the UI metadata block. */
  meta: Record<string, string | number | null>;
  /** Human-readable URL pointing back to the upstream record. */
  permalink: string;
}

export class AbuseLookupError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code:
      | 'not_configured'
      | 'invalid_input'
      | 'unsupported_kind'
      | 'rate_limited'
      | 'unauthorized'
      | 'upstream_error'
      | 'timeout',
    public provider: AbuseProviderId,
  ) {
    super(message);
    this.name = 'AbuseLookupError';
  }
}

export function isAbuseChConfigured(): boolean {
  return !!env.abuseChAuthKey;
}

// ---------------------------------------------------------------------------
// Per-provider capability matrix.
//
// Centralising this avoids forwarding a request to a provider that physically
// can't answer it (e.g. URLhaus has no concept of a SHA-1 file hash).
// ---------------------------------------------------------------------------

const PROVIDER_SUPPORT: Record<AbuseProviderId, ReadonlySet<AbuseLookupKind>> = {
  threatfox: new Set<AbuseLookupKind>(['sha256', 'sha1', 'md5', 'url', 'domain', 'ipv4']),
  urlhaus: new Set<AbuseLookupKind>(['url', 'domain', 'ipv4', 'sha256', 'md5']),
  malwarebazaar: new Set<AbuseLookupKind>(['sha256', 'sha1', 'md5']),
};

export function abuseProviderSupports(
  provider: AbuseProviderId,
  kind: AbuseLookupKind,
): boolean {
  return PROVIDER_SUPPORT[provider].has(kind);
}

// ---------------------------------------------------------------------------
// Shared HTTP helper. abuse.ch endpoints are picky about Content-Type
// (ThreatFox: JSON; URLhaus + MalwareBazaar: x-www-form-urlencoded).
// ---------------------------------------------------------------------------

interface UpstreamCallOptions {
  url: string;
  bodyJson?: unknown;
  bodyForm?: Record<string, string>;
  provider: AbuseProviderId;
}

async function callAbuseCh<T>(opts: UpstreamCallOptions): Promise<T> {
  if (!env.abuseChAuthKey) {
    throw new AbuseLookupError(
      'abuse.ch lookups are not configured on this server.',
      503,
      'not_configured',
      opts.provider,
    );
  }

  const headers: Record<string, string> = {
    'Auth-Key': env.abuseChAuthKey,
    Accept: 'application/json',
  };

  let body: string;
  if (opts.bodyJson !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.bodyJson);
  } else if (opts.bodyForm) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(opts.bodyForm).toString();
  } else {
    throw new AbuseLookupError('Internal: no body provided.', 500, 'upstream_error', opts.provider);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(opts.url, {
      method: 'POST',
      headers,
      body,
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timer);
    const msg = (e as Error).message;
    if (msg.includes('aborted')) {
      throw new AbuseLookupError(
        `${opts.provider} request timed out.`,
        504,
        'timeout',
        opts.provider,
      );
    }
    throw new AbuseLookupError(
      `Upstream network error from ${opts.provider}: ${msg}`,
      502,
      'upstream_error',
      opts.provider,
    );
  }
  clearTimeout(timer);

  if (response.status === 401 || response.status === 403) {
    throw new AbuseLookupError(
      `abuse.ch rejected the Auth-Key for ${opts.provider}.`,
      response.status,
      'unauthorized',
      opts.provider,
    );
  }
  if (response.status === 429) {
    throw new AbuseLookupError(
      `abuse.ch ${opts.provider} rate limit reached. Try again shortly.`,
      429,
      'rate_limited',
      opts.provider,
    );
  }
  if (!response.ok) {
    throw new AbuseLookupError(
      `${opts.provider} responded with HTTP ${response.status}.`,
      502,
      'upstream_error',
      opts.provider,
    );
  }

  return (await response.json().catch(() => ({}))) as T;
}

// ---------------------------------------------------------------------------
// ThreatFox
// ---------------------------------------------------------------------------

const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';

interface ThreatFoxApiResponse {
  query_status?: string;
  data?: Array<{
    id?: string | number;
    ioc?: string;
    threat_type?: string;
    ioc_type?: string;
    malware?: string;
    malware_printable?: string;
    malware_alias?: string | null;
    confidence_level?: number | string;
    first_seen?: string;
    last_seen?: string | null;
    reference?: string | null;
    tags?: string[] | null;
  }>;
}

function parseConfidence(raw: number | string | undefined): number | null {
  if (raw === undefined || raw === null) return null;
  const n = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function confidenceVerdict(conf: number | null, found: boolean): AbuseVerdict {
  if (!found) return 'unknown';
  if (conf === null) return 'malicious';
  if (conf >= 75) return 'malicious';
  if (conf >= 25) return 'suspicious';
  return 'clean';
}

function isoOrNull(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.replace(' ', 'T');
  const candidates = [trimmed.endsWith('Z') ? trimmed : `${trimmed}Z`, raw];
  for (const c of candidates) {
    const d = new Date(c);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  return null;
}

export async function threatfoxLookup(
  rawKind: string,
  rawValue: string,
): Promise<AbuseChLookupResult> {
  const kind = rawKind as AbuseLookupKind;
  if (!abuseProviderSupports('threatfox', kind)) {
    throw new AbuseLookupError(
      `ThreatFox does not support ${rawKind} indicators.`,
      400,
      'unsupported_kind',
      'threatfox',
    );
  }
  const value = validateIndicator(kind, rawValue);
  if (value === null) {
    throw new AbuseLookupError(
      `Indicator does not match the declared kind (${kind}).`,
      400,
      'invalid_input',
      'threatfox',
    );
  }

  const body = await callAbuseCh<ThreatFoxApiResponse>({
    url: THREATFOX_API,
    provider: 'threatfox',
    bodyJson: { query: 'search_ioc', search_term: value },
  });

  const ok = body.query_status === 'ok' && Array.isArray(body.data) && body.data.length > 0;
  const top = ok ? body.data![0] : null;
  const conf = parseConfidence(top?.confidence_level);
  const tags = Array.isArray(top?.tags) ? top!.tags!.filter((t): t is string => !!t) : [];
  const family = top?.malware_printable || top?.malware || null;
  const threatType = top?.threat_type || null;
  const meta: Record<string, string | number | null> = {};
  if (family) meta.family = family;
  if (threatType) meta.threatType = threatType;
  if (top?.malware_alias) meta.aliases = String(top.malware_alias);
  if (top?.id !== undefined) meta.threatfoxId = String(top.id);
  if (top?.reference) meta.reference = String(top.reference);

  return {
    provider: 'threatfox',
    providerName: 'abuse.ch ThreatFox',
    kind,
    value,
    found: ok,
    verdict: confidenceVerdict(conf, ok),
    threatLabel:
      family && threatType ? `${family} (${threatType})` : family || threatType || null,
    confidence: conf,
    firstSeen: isoOrNull(top?.first_seen),
    lastSeen: isoOrNull(top?.last_seen ?? null),
    tags,
    meta,
    permalink: top?.id
      ? `https://threatfox.abuse.ch/ioc/${encodeURIComponent(String(top.id))}/`
      : `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(value)}`,
  };
}

// ---------------------------------------------------------------------------
// URLhaus
// ---------------------------------------------------------------------------

const URLHAUS_URL = 'https://urlhaus-api.abuse.ch/v1/url/';
const URLHAUS_HOST = 'https://urlhaus-api.abuse.ch/v1/host/';
const URLHAUS_PAYLOAD = 'https://urlhaus-api.abuse.ch/v1/payload/';

interface UrlhausUrlResponse {
  query_status?: string;
  url?: string;
  url_status?: string;
  threat?: string;
  tags?: string[] | null;
  date_added?: string;
  last_online?: string | null;
  reporter?: string;
  urlhaus_reference?: string;
  payloads?: Array<{
    file_type?: string;
    response_md5?: string;
    response_sha256?: string;
    signature?: string | null;
  }>;
}

interface UrlhausHostResponse {
  query_status?: string;
  host?: string;
  firstseen?: string;
  url_count?: string;
  blacklists?: Record<string, string>;
  urls?: Array<{
    url?: string;
    threat?: string;
    url_status?: string;
    date_added?: string;
    urlhaus_reference?: string;
  }>;
}

interface UrlhausPayloadResponse {
  query_status?: string;
  md5_hash?: string;
  sha256_hash?: string;
  file_type?: string;
  file_size?: string;
  signature?: string | null;
  firstseen?: string;
  lastseen?: string | null;
  urlhaus_reference?: string;
  urls?: Array<unknown>;
}

export async function urlhausLookup(
  rawKind: string,
  rawValue: string,
): Promise<AbuseChLookupResult> {
  const kind = rawKind as AbuseLookupKind;
  if (!abuseProviderSupports('urlhaus', kind)) {
    throw new AbuseLookupError(
      `URLhaus does not support ${rawKind} indicators.`,
      400,
      'unsupported_kind',
      'urlhaus',
    );
  }
  const value = validateIndicator(kind, rawValue);
  if (value === null) {
    throw new AbuseLookupError(
      `Indicator does not match the declared kind (${kind}).`,
      400,
      'invalid_input',
      'urlhaus',
    );
  }

  if (kind === 'url') {
    const body = await callAbuseCh<UrlhausUrlResponse>({
      url: URLHAUS_URL,
      provider: 'urlhaus',
      bodyForm: { url: value },
    });
    const found = body.query_status === 'ok';
    const tags = Array.isArray(body.tags) ? body.tags.filter((t): t is string => !!t) : [];
    const meta: Record<string, string | number | null> = {};
    if (body.url_status) meta.status = body.url_status;
    if (body.reporter) meta.reporter = body.reporter;
    if (body.payloads && body.payloads.length > 0) {
      const p = body.payloads[0];
      if (p.file_type) meta.payloadType = p.file_type;
      if (p.signature) meta.signature = p.signature;
      if (p.response_sha256) meta.payloadSha256 = p.response_sha256;
    }
    return {
      provider: 'urlhaus',
      providerName: 'abuse.ch URLhaus',
      kind,
      value,
      found,
      verdict: found ? (body.url_status === 'online' ? 'malicious' : 'suspicious') : 'unknown',
      threatLabel: body.threat ?? null,
      confidence: found ? 100 : null,
      firstSeen: isoOrNull(body.date_added),
      lastSeen: isoOrNull(body.last_online ?? null),
      tags,
      meta,
      permalink:
        body.urlhaus_reference || `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}`,
    };
  }

  if (kind === 'domain' || kind === 'ipv4') {
    const body = await callAbuseCh<UrlhausHostResponse>({
      url: URLHAUS_HOST,
      provider: 'urlhaus',
      bodyForm: { host: value },
    });
    const found = body.query_status === 'ok';
    const meta: Record<string, string | number | null> = {};
    if (body.url_count) meta.urlCount = Number(body.url_count) || body.url_count;
    if (body.blacklists) {
      const flagged = Object.entries(body.blacklists)
        .filter(([, status]) => status && status !== 'not listed')
        .map(([list]) => list);
      if (flagged.length > 0) meta.blacklists = flagged.join(', ');
    }
    const sampleThreat = body.urls?.[0]?.threat ?? null;
    return {
      provider: 'urlhaus',
      providerName: 'abuse.ch URLhaus',
      kind,
      value,
      found,
      verdict: found ? 'malicious' : 'unknown',
      threatLabel: sampleThreat,
      confidence: found ? 100 : null,
      firstSeen: isoOrNull(body.firstseen),
      lastSeen: null,
      tags: [],
      meta,
      permalink:
        kind === 'ipv4'
          ? `https://urlhaus.abuse.ch/host/${encodeURIComponent(value)}/`
          : `https://urlhaus.abuse.ch/host/${encodeURIComponent(value)}/`,
    };
  }

  // sha256 / md5 — query the payload endpoint.
  const body = await callAbuseCh<UrlhausPayloadResponse>({
    url: URLHAUS_PAYLOAD,
    provider: 'urlhaus',
    bodyForm: kind === 'sha256' ? { sha256_hash: value } : { md5_hash: value },
  });
  const found = body.query_status === 'ok';
  const meta: Record<string, string | number | null> = {};
  if (body.file_type) meta.fileType = body.file_type;
  if (body.file_size) meta.fileSize = Number(body.file_size) || body.file_size;
  if (body.signature) meta.signature = body.signature;
  if (Array.isArray(body.urls)) meta.distributionUrls = body.urls.length;
  return {
    provider: 'urlhaus',
    providerName: 'abuse.ch URLhaus',
    kind,
    value,
    found,
    verdict: found ? 'malicious' : 'unknown',
    threatLabel: body.signature ?? null,
    confidence: found ? 100 : null,
    firstSeen: isoOrNull(body.firstseen),
    lastSeen: isoOrNull(body.lastseen ?? null),
    tags: [],
    meta,
    permalink:
      body.urlhaus_reference ||
      (body.sha256_hash
        ? `https://urlhaus.abuse.ch/sample/${encodeURIComponent(body.sha256_hash)}/`
        : `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}`),
  };
}

// ---------------------------------------------------------------------------
// MalwareBazaar
// ---------------------------------------------------------------------------

const MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/';

interface MalwareBazaarResponse {
  query_status?: string;
  data?: Array<{
    sha256_hash?: string;
    sha1_hash?: string;
    md5_hash?: string;
    file_name?: string;
    file_size?: number;
    file_type?: string;
    file_type_mime?: string;
    signature?: string | null;
    first_seen?: string;
    last_seen?: string | null;
    tags?: string[] | null;
    reporter?: string;
    intelligence?: {
      clamav?: string[] | null;
      downloads?: string;
      uploads?: string;
    };
  }>;
}

export async function malwareBazaarLookup(
  rawKind: string,
  rawValue: string,
): Promise<AbuseChLookupResult> {
  const kind = rawKind as AbuseLookupKind;
  if (!abuseProviderSupports('malwarebazaar', kind)) {
    throw new AbuseLookupError(
      `MalwareBazaar only supports file hash indicators.`,
      400,
      'unsupported_kind',
      'malwarebazaar',
    );
  }
  const value = validateIndicator(kind, rawValue);
  if (value === null) {
    throw new AbuseLookupError(
      `Indicator does not match the declared kind (${kind}).`,
      400,
      'invalid_input',
      'malwarebazaar',
    );
  }

  const body = await callAbuseCh<MalwareBazaarResponse>({
    url: MALWAREBAZAAR_API,
    provider: 'malwarebazaar',
    bodyForm: { query: 'get_info', hash: value },
  });

  const found = body.query_status === 'ok' && Array.isArray(body.data) && body.data.length > 0;
  const top = found ? body.data![0] : null;
  const tags = Array.isArray(top?.tags) ? top!.tags!.filter((t): t is string => !!t) : [];
  const meta: Record<string, string | number | null> = {};
  if (top?.file_name) meta.fileName = top.file_name;
  if (top?.file_type) meta.fileType = top.file_type;
  if (top?.file_size) meta.fileSize = top.file_size;
  if (top?.file_type_mime) meta.mime = top.file_type_mime;
  if (top?.signature) meta.signature = top.signature;
  if (top?.reporter) meta.reporter = top.reporter;
  if (top?.intelligence?.downloads) meta.downloads = Number(top.intelligence.downloads) || top.intelligence.downloads;

  return {
    provider: 'malwarebazaar',
    providerName: 'abuse.ch MalwareBazaar',
    kind,
    value,
    found,
    verdict: found ? 'malicious' : 'unknown',
    threatLabel: top?.signature ?? top?.file_type ?? null,
    confidence: found ? 100 : null,
    firstSeen: isoOrNull(top?.first_seen),
    lastSeen: isoOrNull(top?.last_seen ?? null),
    tags,
    meta,
    permalink: top?.sha256_hash
      ? `https://bazaar.abuse.ch/sample/${encodeURIComponent(top.sha256_hash)}/`
      : `https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent(value)}`,
  };
}
