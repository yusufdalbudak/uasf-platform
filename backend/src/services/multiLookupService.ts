import { AppDataSource } from '../db/connection';
import { IocIndicator } from '../db/models/IocIndicator';
import {
  isVirusTotalConfigured,
  virustotalLookup,
  VtLookupError,
  VtLookupResult,
} from './virustotalService';
import {
  abuseProviderSupports,
  AbuseChLookupResult,
  AbuseLookupError,
  AbuseLookupKind,
  AbuseProviderId,
  isAbuseChConfigured,
  malwareBazaarLookup,
  threatfoxLookup,
  urlhausLookup,
} from './abuseChService';

/**
 * Multi-source reputation lookup orchestrator.
 *
 * Fans a single indicator out to every configured provider in parallel and
 * returns one compact `ProviderResult` per provider (always — including for
 * providers that are unreachable or unconfigured) so the UI can render a
 * stable grid where each cell explains itself.
 *
 * Providers checked:
 *   1. Local IOC database  — needs no key, covers every feed we ingest
 *      (GitHub Advisories, OpenPhish, abuse.ch ThreatFox).
 *   2. VirusTotal Public v3 — uses VIRUSTOTAL_API_KEY.
 *   3. abuse.ch ThreatFox  — uses ABUSE_CH_AUTH_KEY.
 *   4. abuse.ch URLhaus    — uses ABUSE_CH_AUTH_KEY.
 *   5. abuse.ch MalwareBazaar — uses ABUSE_CH_AUTH_KEY.
 *
 * The orchestrator never throws on per-provider failure: each provider's
 * outcome is captured as `ok | not_configured | unsupported | error` so a
 * partial result still ships and the UI can clearly show which sources were
 * actually checked.
 */

export type LookupKind = AbuseLookupKind;

export type ProviderId =
  | 'local_db'
  | 'virustotal'
  | 'threatfox'
  | 'urlhaus'
  | 'malwarebazaar';

export type ProviderStatus =
  | 'ok'
  | 'not_found'
  | 'not_configured'
  | 'unsupported'
  | 'error';

export type Verdict =
  | 'malicious'
  | 'suspicious'
  | 'harmless'
  | 'undetected'
  | 'clean'
  | 'unknown';

export interface ProviderResult {
  provider: ProviderId;
  providerName: string;
  status: ProviderStatus;
  /** Best-effort verdict; 'unknown' when the provider had no opinion. */
  verdict: Verdict;
  /** Short human-readable label (malware family, threat type, ...). */
  threatLabel: string | null;
  /** Provider-specific summary like "5 / 72 engines" or "Known phishing URL". */
  summary: string | null;
  /** ISO timestamps from the provider, if present. */
  firstSeen: string | null;
  lastSeen: string | null;
  /** Tags (malware aliases, families, etc.). */
  tags: string[];
  /** Compact key/value pairs for the UI metadata block. */
  meta: Record<string, string | number | null>;
  /** Direct link to the provider's page for the indicator (if known). */
  permalink: string | null;
  /** Human-readable error/explanation when status !== 'ok' / 'not_found'. */
  detail: string | null;
}

export interface MultiLookupResponse {
  kind: LookupKind;
  value: string;
  startedAt: string;
  durationMs: number;
  /** Highest-severity verdict observed across providers that returned 'ok'. */
  aggregateVerdict: Verdict;
  /** How many providers returned a 'ok' (hit) verdict. */
  hitCount: number;
  /** How many providers were actually queried (excludes not_configured + unsupported). */
  checkedCount: number;
  providers: ProviderResult[];
}

const SEVERITY_RANK: Record<Verdict, number> = {
  malicious: 5,
  suspicious: 4,
  unknown: 3,
  undetected: 2,
  harmless: 1,
  clean: 0,
};

function aggregate(results: ProviderResult[]): Verdict {
  let best: Verdict = 'unknown';
  let bestRank = -1;
  for (const r of results) {
    if (r.status !== 'ok') continue;
    const rank = SEVERITY_RANK[r.verdict] ?? -1;
    if (rank > bestRank) {
      bestRank = rank;
      best = r.verdict;
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// Local IOC DB lookup — never makes outbound calls; queries the rows we've
// already ingested from GitHub Advisories / OpenPhish / ThreatFox.
// ---------------------------------------------------------------------------

async function lookupLocalDb(kind: LookupKind, value: string): Promise<ProviderResult> {
  const repo = AppDataSource.getRepository(IocIndicator);
  // Match on exact indicator string. We deliberately do NOT lowercase here for
  // URLs because URL casing is significant; for everything else our ingest
  // pipeline already lowercases hashes and domains.
  const matches = await repo.find({
    where: { indicator: value },
    order: { lastSeen: 'DESC' },
    take: 5,
  });
  if (matches.length === 0) {
    return {
      provider: 'local_db',
      providerName: 'Local IOC database',
      status: 'not_found',
      verdict: 'unknown',
      threatLabel: null,
      summary: 'Indicator not present in any ingested feed.',
      firstSeen: null,
      lastSeen: null,
      tags: [],
      meta: {},
      permalink: null,
      detail: null,
    };
  }
  const top = matches[0];
  const sources = Array.from(new Set(matches.map((m) => m.sourceName ?? m.source))).filter(
    (s): s is string => !!s,
  );
  const meta: Record<string, string | number | null> = {
    feeds: sources.join(', '),
    occurrences: matches.reduce((acc, m) => acc + (m.occurrences ?? 1), 0),
    type: top.indicatorType,
  };
  // Local-DB confidence becomes the verdict: 'malicious' if any matched row
  // is high confidence, otherwise 'suspicious'.
  const isHigh = matches.some((m) => (m.confidence ?? 'medium').toLowerCase() === 'high');
  return {
    provider: 'local_db',
    providerName: 'Local IOC database',
    status: 'ok',
    verdict: isHigh ? 'malicious' : 'suspicious',
    threatLabel: top.threatLabel ?? null,
    summary: `Matched ${matches.length} record(s) across ${sources.length} feed(s).`,
    firstSeen: top.firstSeen ? top.firstSeen.toISOString() : null,
    lastSeen: top.lastSeen ? top.lastSeen.toISOString() : null,
    tags: [],
    meta,
    permalink: top.sourceUrl ?? null,
    detail: null,
  };
}

// ---------------------------------------------------------------------------
// Adapters that translate provider-native results into the unified shape.
// ---------------------------------------------------------------------------

function adaptVt(vt: VtLookupResult): ProviderResult {
  const stats = vt.stats;
  const summary = stats
    ? `${stats.malicious} / ${vt.engines} engines flagged`
    : vt.notFound
      ? 'Indicator not in VirusTotal corpus.'
      : 'No analysis stats returned.';
  const meta: Record<string, string | number | null> = { ...vt.meta };
  if (vt.reputation !== null) meta.reputation = vt.reputation;
  if (vt.engines) meta.engines = vt.engines;
  return {
    provider: 'virustotal',
    providerName: 'VirusTotal',
    status: vt.notFound ? 'not_found' : 'ok',
    verdict: vt.verdict,
    threatLabel: stats?.malicious ? `${stats.malicious} engine detection(s)` : null,
    summary,
    firstSeen: null,
    lastSeen: vt.lastAnalysisDate,
    tags: [],
    meta,
    permalink: vt.permalink,
    detail: null,
  };
}

function adaptAbuseCh(provider: AbuseProviderId, r: AbuseChLookupResult): ProviderResult {
  const meta: Record<string, string | number | null> = { ...r.meta };
  if (r.confidence !== null) meta.confidence = r.confidence;
  if (r.tags.length) meta.tags = r.tags.join(', ');
  return {
    provider,
    providerName: r.providerName,
    status: r.found ? 'ok' : 'not_found',
    verdict: r.verdict,
    threatLabel: r.threatLabel,
    summary: r.found
      ? `Hit on ${r.providerName}.`
      : `No record for this indicator on ${r.providerName}.`,
    firstSeen: r.firstSeen,
    lastSeen: r.lastSeen,
    tags: r.tags,
    meta,
    permalink: r.permalink,
    detail: null,
  };
}

// ---------------------------------------------------------------------------
// Per-provider safe wrappers — every error becomes a `ProviderResult` so the
// orchestrator's `Promise.all()` never rejects.
// ---------------------------------------------------------------------------

async function safeVirustotal(kind: LookupKind, value: string): Promise<ProviderResult> {
  if (!isVirusTotalConfigured()) {
    return {
      provider: 'virustotal',
      providerName: 'VirusTotal',
      status: 'not_configured',
      verdict: 'unknown',
      threatLabel: null,
      summary: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      meta: {},
      permalink: null,
      detail: 'VIRUSTOTAL_API_KEY is not set on the backend.',
    };
  }
  try {
    const vt = await virustotalLookup(kind, value);
    return adaptVt(vt);
  } catch (e) {
    if (e instanceof VtLookupError) {
      return {
        provider: 'virustotal',
        providerName: 'VirusTotal',
        status: 'error',
        verdict: 'unknown',
        threatLabel: null,
        summary: null,
        firstSeen: null,
        lastSeen: null,
        tags: [],
        meta: {},
        permalink: null,
        detail: e.message,
      };
    }
    return {
      provider: 'virustotal',
      providerName: 'VirusTotal',
      status: 'error',
      verdict: 'unknown',
      threatLabel: null,
      summary: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      meta: {},
      permalink: null,
      detail: (e as Error).message,
    };
  }
}

const ABUSE_PROVIDERS: ReadonlyArray<{
  id: AbuseProviderId;
  name: string;
  fn: (k: string, v: string) => Promise<AbuseChLookupResult>;
}> = [
  { id: 'threatfox', name: 'abuse.ch ThreatFox', fn: threatfoxLookup },
  { id: 'urlhaus', name: 'abuse.ch URLhaus', fn: urlhausLookup },
  { id: 'malwarebazaar', name: 'abuse.ch MalwareBazaar', fn: malwareBazaarLookup },
];

async function safeAbuseCh(
  provider: { id: AbuseProviderId; name: string; fn: (k: string, v: string) => Promise<AbuseChLookupResult> },
  kind: LookupKind,
  value: string,
): Promise<ProviderResult> {
  if (!isAbuseChConfigured()) {
    return {
      provider: provider.id,
      providerName: provider.name,
      status: 'not_configured',
      verdict: 'unknown',
      threatLabel: null,
      summary: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      meta: {},
      permalink: null,
      detail: 'ABUSE_CH_AUTH_KEY is not set on the backend.',
    };
  }
  if (!abuseProviderSupports(provider.id, kind)) {
    return {
      provider: provider.id,
      providerName: provider.name,
      status: 'unsupported',
      verdict: 'unknown',
      threatLabel: null,
      summary: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      meta: {},
      permalink: null,
      detail: `${provider.name} does not support ${kind} indicators.`,
    };
  }
  try {
    const r = await provider.fn(kind, value);
    return adaptAbuseCh(provider.id, r);
  } catch (e) {
    if (e instanceof AbuseLookupError) {
      return {
        provider: provider.id,
        providerName: provider.name,
        status: 'error',
        verdict: 'unknown',
        threatLabel: null,
        summary: null,
        firstSeen: null,
        lastSeen: null,
        tags: [],
        meta: {},
        permalink: null,
        detail: e.message,
      };
    }
    return {
      provider: provider.id,
      providerName: provider.name,
      status: 'error',
      verdict: 'unknown',
      threatLabel: null,
      summary: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      meta: {},
      permalink: null,
      detail: (e as Error).message,
    };
  }
}

async function safeLocalDb(kind: LookupKind, value: string): Promise<ProviderResult> {
  try {
    return await lookupLocalDb(kind, value);
  } catch (e) {
    return {
      provider: 'local_db',
      providerName: 'Local IOC database',
      status: 'error',
      verdict: 'unknown',
      threatLabel: null,
      summary: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      meta: {},
      permalink: null,
      detail: (e as Error).message,
    };
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const HEX_64 = /^[a-f0-9]{64}$/i;
const HEX_40 = /^[a-f0-9]{40}$/i;
const HEX_32 = /^[a-f0-9]{32}$/i;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

/** Server-side helper so the UI can submit a free-form indicator and let the
 *  backend pick the best `kind`. Mirrors the frontend `detectLookupKind`. */
export function detectKind(raw: string): LookupKind | null {
  const v = String(raw ?? '').trim();
  if (!v) return null;
  if (HEX_64.test(v)) return 'sha256';
  if (HEX_40.test(v)) return 'sha1';
  if (HEX_32.test(v)) return 'md5';
  if (IPV4.test(v)) return 'ipv4';
  try {
    const u = new URL(v);
    if (u.protocol === 'http:' || u.protocol === 'https:') return 'url';
  } catch {
    /* not a URL */
  }
  if (DOMAIN.test(v)) return 'domain';
  return null;
}

export interface MultiLookupStatus {
  providers: Array<{
    id: ProviderId;
    name: string;
    configured: boolean;
    /** docs URL for the provider so the UI can link "how to enable". */
    docs: string;
  }>;
}

export function multiLookupStatus(): MultiLookupStatus {
  return {
    providers: [
      {
        id: 'local_db',
        name: 'Local IOC database',
        configured: true,
        docs: 'https://github.com/advisories',
      },
      {
        id: 'virustotal',
        name: 'VirusTotal',
        configured: isVirusTotalConfigured(),
        docs: 'https://docs.virustotal.com/reference/overview',
      },
      {
        id: 'threatfox',
        name: 'abuse.ch ThreatFox',
        configured: isAbuseChConfigured(),
        docs: 'https://threatfox.abuse.ch/api/',
      },
      {
        id: 'urlhaus',
        name: 'abuse.ch URLhaus',
        configured: isAbuseChConfigured(),
        docs: 'https://urlhaus-api.abuse.ch/',
      },
      {
        id: 'malwarebazaar',
        name: 'abuse.ch MalwareBazaar',
        configured: isAbuseChConfigured(),
        docs: 'https://bazaar.abuse.ch/api/',
      },
    ],
  };
}

export async function multiLookup(
  rawKind: string | null,
  rawValue: string,
): Promise<MultiLookupResponse> {
  const value = String(rawValue ?? '').trim();
  if (!value) throw new Error('value is required');

  const kind: LookupKind | null =
    rawKind && ['sha256', 'sha1', 'md5', 'url', 'domain', 'ipv4'].includes(rawKind)
      ? (rawKind as LookupKind)
      : detectKind(value);
  if (!kind) {
    throw new Error(
      'Indicator type could not be detected. Provide a SHA-256 / SHA-1 / MD5 hash, URL, domain, or IPv4 address.',
    );
  }

  const startedAt = new Date();
  const t0 = Date.now();

  const providerResults = await Promise.all([
    safeLocalDb(kind, value),
    safeVirustotal(kind, value),
    ...ABUSE_PROVIDERS.map((p) => safeAbuseCh(p, kind, value)),
  ]);

  const checkedCount = providerResults.filter((p) => p.status === 'ok' || p.status === 'not_found').length;
  const hitCount = providerResults.filter((p) => p.status === 'ok').length;

  return {
    kind,
    value,
    startedAt: startedAt.toISOString(),
    durationMs: Date.now() - t0,
    aggregateVerdict: aggregate(providerResults),
    checkedCount,
    hitCount,
    providers: providerResults,
  };
}
