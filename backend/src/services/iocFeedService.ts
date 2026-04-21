import { AppDataSource } from '../db/connection';
import { IocIndicator } from '../db/models/IocIndicator';

/**
 * Multi-source ingestion of public IOC / threat-context data.
 *
 * Sources currently wired in:
 *   1. GitHub Advisory Database — https://github.com/advisories
 *      Authoritative software-vulnerability advisories (GHSA + CVE aliases),
 *      pulled through the public REST endpoint
 *      https://api.github.com/advisories?type=reviewed&...
 *      Each advisory becomes one or two normalized indicators (one for the
 *      GHSA id, one for the CVE id when present).
 *
 *   2. OpenPhish Community Feed — https://openphish.com/feed.txt
 *      Plain-text list of currently-active phishing URLs maintained by the
 *      OpenPhish team. The OpenPhish "OPDB" client at
 *      https://github.com/openphish/pyopdb wraps a licensed commercial
 *      database; this ingester deliberately uses the *free* community feed
 *      so no OPDB credentials are required and no commercial terms apply.
 *      Each line of the feed becomes one `url`-typed indicator with high
 *      confidence and the threat label "Phishing".
 *
 *   3. abuse.ch ThreatFox — https://threatfox.abuse.ch/browse/
 *      Public CSV export of IOCs (URLs, domains, ip:port, hashes) recently
 *      added to ThreatFox: https://threatfox.abuse.ch/export/csv/recent/.
 *      The JSON API at https://threatfox-api.abuse.ch/ now requires an
 *      auth key (free, registration-gated). We deliberately consume the
 *      anonymous CSV export so no credentials are needed. Each row carries
 *      a malware family attribution and a 0–100 confidence score, both of
 *      which we preserve in the normalized indicator.
 *
 * Hard guarantees:
 *   - We never authenticate to GitHub. Anonymous use of the public REST
 *     endpoint stays inside GitHub's documented rate limits.
 *   - We do not ship OPDB API keys; the community feed is fetched
 *     anonymously over HTTPS and is published explicitly for redistribution.
 *   - Per-source caps prevent a single run from filling the database.
 *   - Indicators are upserted by `(source, indicator, indicatorType)` so
 *     re-running just bumps `lastSeen` / `occurrences` rather than creating
 *     duplicates. This means historical phishing URLs are preserved for
 *     retro-hunting even after they roll off the active community feed.
 *   - All failures are aggregated into the returned summary; nothing is
 *     thrown to the caller, and one source failing never blocks the others.
 */

interface NormalizedIndicator {
  indicator: string;
  /** Free-form indicator type: ghsa | cve | url | domain | ipv4 | ... */
  indicatorType: string;
  threatLabel: string | null;
  confidence: 'high' | 'medium' | 'low';
  source: string;
  sourceName: string;
  sourceUrl: string | null;
  notes: string | null;
  observedAt: Date;
}

const REQUEST_TIMEOUT_MS = 25_000;
const USER_AGENT = 'UASF/1.0 (security validation platform; +https://uasf.local)';

// ---------------------------------------------------------------------------
// Source #1 — GitHub Advisory Database
// ---------------------------------------------------------------------------

const GITHUB_ADVISORIES_URL =
  'https://api.github.com/advisories?per_page=100&type=reviewed&sort=updated&direction=desc';
const MAX_ADVISORIES_PER_REFRESH = 200;

interface GhAdvisoryIdentifier {
  type?: string;
  value?: string;
}

interface GhAdvisoryCwe {
  cwe_id?: string;
  name?: string;
}

interface GhAdvisoryVuln {
  package?: { ecosystem?: string; name?: string };
  vulnerable_version_range?: string;
}

interface GhAdvisory {
  ghsa_id?: string;
  cve_id?: string | null;
  url?: string;
  html_url?: string;
  summary?: string;
  description?: string;
  severity?: 'critical' | 'high' | 'medium' | 'moderate' | 'low' | 'unknown';
  identifiers?: GhAdvisoryIdentifier[];
  published_at?: string;
  updated_at?: string;
  cwes?: GhAdvisoryCwe[];
  vulnerabilities?: GhAdvisoryVuln[];
}

function severityToConfidence(
  severity: GhAdvisory['severity'],
): 'high' | 'medium' | 'low' {
  const s = (severity ?? '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'moderate' || s === 'medium') return 'medium';
  return 'low';
}

function buildThreatLabel(advisory: GhAdvisory): string | null {
  const cwe = advisory.cwes?.find((entry) => entry?.cwe_id);
  if (cwe?.cwe_id && cwe?.name) return `${cwe.cwe_id}: ${cwe.name}`;
  if (cwe?.cwe_id) return cwe.cwe_id;
  if (advisory.severity) {
    return `${advisory.severity.toUpperCase()} severity advisory`;
  }
  return null;
}

function buildAdvisoryNotes(advisory: GhAdvisory): string | null {
  const parts: string[] = [];
  if (advisory.summary) parts.push(advisory.summary.trim());
  const ecosystems = new Set<string>();
  for (const v of advisory.vulnerabilities ?? []) {
    if (v?.package?.ecosystem) ecosystems.add(v.package.ecosystem);
  }
  if (ecosystems.size > 0) {
    parts.push(`affected ecosystems: ${Array.from(ecosystems).sort().join(', ')}`);
  }
  if (parts.length === 0) return null;
  return parts.join(' — ').slice(0, 1000);
}

function normalizeAdvisory(advisory: GhAdvisory): NormalizedIndicator[] {
  const out: NormalizedIndicator[] = [];
  const observedAt = advisory.updated_at
    ? new Date(advisory.updated_at)
    : advisory.published_at
      ? new Date(advisory.published_at)
      : new Date();
  if (Number.isNaN(observedAt.getTime())) return out;

  const sourceUrl = advisory.html_url ?? advisory.url ?? null;
  const confidence = severityToConfidence(advisory.severity);
  const threatLabel = buildThreatLabel(advisory);
  const notes = buildAdvisoryNotes(advisory);

  if (advisory.ghsa_id) {
    out.push({
      indicator: advisory.ghsa_id,
      indicatorType: 'ghsa',
      threatLabel,
      confidence,
      source: 'github_advisories',
      sourceName: 'GitHub Advisory Database',
      sourceUrl,
      notes,
      observedAt,
    });
  }

  if (advisory.cve_id) {
    out.push({
      indicator: advisory.cve_id,
      indicatorType: 'cve',
      threatLabel,
      confidence,
      source: 'github_advisories',
      sourceName: 'GitHub Advisory Database',
      sourceUrl,
      notes,
      observedAt,
    });
  }

  return out;
}

async function fetchGitHubAdvisories(): Promise<GhAdvisory[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(GITHUB_ADVISORIES_URL, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`GitHub advisories API responded ${response.status}`);
    }
    const data = (await response.json()) as GhAdvisory[];
    return Array.isArray(data) ? data : [];
  } finally {
    clearTimeout(timer);
  }
}

async function collectGitHubAdvisories(): Promise<NormalizedIndicator[]> {
  const advisories = await fetchGitHubAdvisories();
  const normalized: NormalizedIndicator[] = [];
  for (const advisory of advisories) {
    for (const indicator of normalizeAdvisory(advisory)) {
      normalized.push(indicator);
      if (normalized.length >= MAX_ADVISORIES_PER_REFRESH) return normalized;
    }
  }
  return normalized;
}

// ---------------------------------------------------------------------------
// Source #2 — OpenPhish Community Feed
// ---------------------------------------------------------------------------

const OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt';
/** OpenPhish currently publishes ~500 active URLs; cap defensively. */
const MAX_OPENPHISH_PER_REFRESH = 1000;
/** Hard upper bound; matches IocIndicator.indicator column length. */
const MAX_INDICATOR_LENGTH = 1024;

function safeUrlHost(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).host || null;
  } catch {
    return null;
  }
}

function buildOpenPhishNotes(rawUrl: string): string {
  const host = safeUrlHost(rawUrl);
  if (host) return `Active phishing URL hosted at ${host}`;
  return 'Active phishing URL';
}

async function fetchOpenPhishFeed(): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(OPENPHISH_FEED_URL, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/plain, */*;q=0.1',
      },
      redirect: 'follow',
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`OpenPhish feed responded ${response.status}`);
    }
    const text = await response.text();
    return text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
  } finally {
    clearTimeout(timer);
  }
}

async function collectOpenPhishIndicators(): Promise<NormalizedIndicator[]> {
  const lines = await fetchOpenPhishFeed();
  const observedAt = new Date();
  const seen = new Set<string>();
  const out: NormalizedIndicator[] = [];

  for (const raw of lines) {
    if (out.length >= MAX_OPENPHISH_PER_REFRESH) break;
    if (raw.length > MAX_INDICATOR_LENGTH) continue;
    if (!/^https?:\/\//i.test(raw)) continue;
    if (seen.has(raw)) continue;
    seen.add(raw);

    out.push({
      indicator: raw,
      indicatorType: 'url',
      threatLabel: 'Phishing',
      confidence: 'high',
      source: 'openphish',
      sourceName: 'OpenPhish Community Feed',
      sourceUrl: 'https://openphish.com/',
      notes: buildOpenPhishNotes(raw),
      observedAt,
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// Source #3 — abuse.ch ThreatFox (anonymous CSV export)
// ---------------------------------------------------------------------------

const THREATFOX_FEED_URL = 'https://threatfox.abuse.ch/export/csv/recent/';
const MAX_THREATFOX_PER_REFRESH = 1500;

/** ThreatFox ioc_type → our `IocIndicator.indicatorType` (varchar(16)). */
const THREATFOX_TYPE_MAP: Record<string, string> = {
  domain: 'domain',
  url: 'url',
  'ip:port': 'ipv4',
  ipv4: 'ipv4',
  ipv6: 'ipv6',
  sha256_hash: 'sha256',
  sha1_hash: 'sha1',
  md5_hash: 'md5',
  email: 'email',
};

interface ThreatFoxRow {
  firstSeen: string;
  iocId: string;
  iocValue: string;
  iocType: string;
  threatType: string;
  malwareFamily: string;
  malwarePrintable: string;
  lastSeen: string;
  confidenceLevel: string;
  reference: string;
  tags: string;
  reporter: string;
}

/**
 * Parse a single CSV row produced by ThreatFox. Their dialect quotes every
 * field with double quotes, so a field can contain commas (the `tags` column
 * does this). RFC 4180 escaping rules apply: doubled `""` inside a quoted
 * value means a literal quote.
 */
function parseCsvRow(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      out.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  out.push(cur.trim());
  return out;
}

function parseThreatFoxCsv(csv: string): ThreatFoxRow[] {
  const rows: ThreatFoxRow[] = [];
  for (const rawLine of csv.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const cols = parseCsvRow(line);
    // Documented column order (14 columns).
    if (cols.length < 14) continue;
    rows.push({
      firstSeen: cols[0],
      iocId: cols[1],
      iocValue: cols[2],
      iocType: cols[3],
      threatType: cols[4],
      malwareFamily: cols[5],
      malwarePrintable: cols[7],
      lastSeen: cols[8],
      confidenceLevel: cols[9],
      reference: cols[11],
      tags: cols[12],
      reporter: cols[13],
    });
  }
  return rows;
}

function threatFoxConfidence(level: string): 'high' | 'medium' | 'low' {
  const n = parseInt(level, 10);
  if (Number.isFinite(n)) {
    if (n >= 75) return 'high';
    if (n >= 50) return 'medium';
  }
  return 'low';
}

function buildThreatFoxLabel(row: ThreatFoxRow): string | null {
  const family = row.malwarePrintable && row.malwarePrintable !== 'None' ? row.malwarePrintable : '';
  const threat = row.threatType && row.threatType !== 'None'
    ? row.threatType.replace(/_/g, ' ')
    : '';
  if (family && threat) return `${family} — ${threat}`;
  if (family) return family;
  if (threat) return threat;
  return null;
}

function buildThreatFoxNotes(row: ThreatFoxRow): string | null {
  const parts: string[] = [];
  if (row.malwareFamily && row.malwareFamily !== 'None') parts.push(`family: ${row.malwareFamily}`);
  if (row.tags && row.tags !== 'None') parts.push(`tags: ${row.tags}`);
  if (row.reporter && row.reporter !== 'None') parts.push(`reporter: ${row.reporter}`);
  if (row.reference && row.reference !== 'None') parts.push(`ref: ${row.reference}`);
  if (parts.length === 0) return null;
  return parts.join(' — ').slice(0, 1000);
}

function parseThreatFoxDate(raw: string): Date | null {
  if (!raw) return null;
  // ThreatFox emits "2026-04-19 01:40:09" in UTC.
  const parsed = new Date(`${raw.replace(' ', 'T')}Z`);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

async function fetchThreatFoxFeed(): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(THREATFOX_FEED_URL, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/csv, text/plain;q=0.9, */*;q=0.1',
      },
      redirect: 'follow',
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`ThreatFox CSV export responded ${response.status}`);
    }
    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

async function collectThreatFoxIndicators(): Promise<NormalizedIndicator[]> {
  const csv = await fetchThreatFoxFeed();
  const rows = parseThreatFoxCsv(csv);
  const out: NormalizedIndicator[] = [];
  const seen = new Set<string>();

  for (const row of rows) {
    if (out.length >= MAX_THREATFOX_PER_REFRESH) break;
    const indicatorType = THREATFOX_TYPE_MAP[row.iocType.toLowerCase()];
    if (!indicatorType) continue;
    const value = row.iocValue?.trim();
    if (!value || value.length > MAX_INDICATOR_LENGTH) continue;
    const dedupeKey = `${indicatorType}|${value}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const observedAt =
      parseThreatFoxDate(row.lastSeen) ?? parseThreatFoxDate(row.firstSeen) ?? new Date();
    const sourceUrl = row.iocId ? `https://threatfox.abuse.ch/ioc/${row.iocId}/` : null;

    out.push({
      indicator: value,
      indicatorType,
      threatLabel: buildThreatFoxLabel(row),
      confidence: threatFoxConfidence(row.confidenceLevel),
      source: 'threatfox',
      sourceName: 'abuse.ch ThreatFox',
      sourceUrl,
      notes: buildThreatFoxNotes(row),
      observedAt,
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

async function upsertIndicator(item: NormalizedIndicator): Promise<'inserted' | 'updated'> {
  const repo = AppDataSource.getRepository(IocIndicator);
  const existing = await repo.findOne({
    where: {
      source: item.source,
      indicator: item.indicator,
      indicatorType: item.indicatorType,
    },
  });

  if (existing) {
    await repo.update(
      { id: existing.id },
      {
        lastSeen: item.observedAt > existing.lastSeen ? item.observedAt : existing.lastSeen,
        occurrences: existing.occurrences + 1,
        threatLabel: item.threatLabel ?? existing.threatLabel,
        confidence: item.confidence,
        notes: item.notes ?? existing.notes,
        sourceUrl: item.sourceUrl ?? existing.sourceUrl,
      },
    );
    return 'updated';
  }

  await repo.save(
    repo.create({
      indicator: item.indicator,
      indicatorType: item.indicatorType,
      threatLabel: item.threatLabel,
      confidence: item.confidence,
      source: item.source,
      sourceName: item.sourceName,
      sourceUrl: item.sourceUrl,
      notes: item.notes,
      occurrences: 1,
      firstSeen: item.observedAt,
      lastSeen: item.observedAt,
    }),
  );
  return 'inserted';
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface IocSourceSummary {
  source: string;
  sourceName: string;
  fetched: number;
  inserted: number;
  updated: number;
  failures: Array<{ indicator: string; error: string }>;
  startedAt: string;
  endedAt: string;
}

export interface IocIngestSummary {
  /** Back-compat: comma-separated source ids that participated in this run. */
  source: string;
  fetched: number;
  inserted: number;
  updated: number;
  failures: Array<{ indicator: string; error: string }>;
  startedAt: string;
  endedAt: string;
  /** Per-source breakdown so the UI can show what each feed contributed. */
  sources: IocSourceSummary[];
}

interface FeedSource {
  id: string;
  displayName: string;
  collect: () => Promise<NormalizedIndicator[]>;
}

const FEED_SOURCES: FeedSource[] = [
  {
    id: 'github_advisories',
    displayName: 'GitHub Advisory Database',
    collect: collectGitHubAdvisories,
  },
  {
    id: 'openphish',
    displayName: 'OpenPhish Community Feed',
    collect: collectOpenPhishIndicators,
  },
  {
    id: 'threatfox',
    displayName: 'abuse.ch ThreatFox',
    collect: collectThreatFoxIndicators,
  },
];

async function refreshSingleSource(source: FeedSource): Promise<IocSourceSummary> {
  const startedAt = new Date();
  let inserted = 0;
  let updated = 0;
  const failures: IocSourceSummary['failures'] = [];

  let normalized: NormalizedIndicator[] = [];
  try {
    normalized = await source.collect();
  } catch (error) {
    return {
      source: source.id,
      sourceName: source.displayName,
      fetched: 0,
      inserted: 0,
      updated: 0,
      failures: [{ indicator: 'fetch', error: (error as Error).message }],
      startedAt: startedAt.toISOString(),
      endedAt: new Date().toISOString(),
    };
  }

  for (const item of normalized) {
    try {
      const result = await upsertIndicator(item);
      if (result === 'inserted') inserted += 1;
      else updated += 1;
    } catch (error) {
      failures.push({ indicator: item.indicator, error: (error as Error).message });
    }
  }

  return {
    source: source.id,
    sourceName: source.displayName,
    fetched: normalized.length,
    inserted,
    updated,
    failures,
    startedAt: startedAt.toISOString(),
    endedAt: new Date().toISOString(),
  };
}

/**
 * Refresh the IOC / threat-context cache from every wired-in public source.
 * Idempotent and non-throwing; per-source failures are returned in the summary.
 */
export async function refreshIocFeed(): Promise<IocIngestSummary> {
  const startedAt = new Date();
  const perSource: IocSourceSummary[] = [];

  for (const source of FEED_SOURCES) {
    perSource.push(await refreshSingleSource(source));
  }

  const aggregate = perSource.reduce(
    (acc, s) => {
      acc.fetched += s.fetched;
      acc.inserted += s.inserted;
      acc.updated += s.updated;
      acc.failures.push(...s.failures);
      return acc;
    },
    { fetched: 0, inserted: 0, updated: 0, failures: [] as IocSourceSummary['failures'] },
  );

  return {
    source: perSource.map((s) => s.source).join(','),
    fetched: aggregate.fetched,
    inserted: aggregate.inserted,
    updated: aggregate.updated,
    failures: aggregate.failures,
    startedAt: startedAt.toISOString(),
    endedAt: new Date().toISOString(),
    sources: perSource,
  };
}

let scheduleHandle: NodeJS.Timeout | null = null;

/**
 * Schedule a periodic IOC refresh. Default cadence: every 2h, with an initial
 * tick 60s after startup. Idempotent; the previous schedule is cleared first.
 *
 * The 2h cadence aligns with the dependency-feed schedule and keeps the
 * OpenPhish view fresh enough for active-phishing investigations while
 * staying well within the upstream feeds' polite-polling guidance.
 */
export function startIocFeedSchedule(everyMs = 2 * 60 * 60 * 1000): void {
  if (scheduleHandle) clearInterval(scheduleHandle);
  setTimeout(() => {
    void refreshIocFeed().catch(() => undefined);
  }, 60_000);
  scheduleHandle = setInterval(() => {
    void refreshIocFeed().catch(() => undefined);
  }, everyMs);
}
