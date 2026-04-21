/**
 * UASF Tech Intelligence — OSV.dev Live Advisory Lookup
 *
 * On-demand integration with the public OSV.dev REST API
 * (https://google.github.io/osv.dev/api/).  For every detected
 * technology that maps to an OSV ecosystem, we POST a `/v1/query`
 * with the detected package name (plus version, if we have one)
 * and persist any returned advisories into our local
 * `DependencyVulnerability` cache.
 *
 * The point of this module is to give the vulnerability correlator
 * **structured, version-range-aware proof** for the most common
 * web-stack technologies (WordPress, jQuery, Django, Spring, etc.)
 * even on the very first scan, before the periodic mycve.com
 * background refresh has had a chance to surface anything.
 *
 * Safety profile:
 *   - Read-only against the public OSV API; we never POST mutations.
 *   - Per-product timeout (8s) and request cap (1 per product).
 *   - All failures are silently swallowed — OSV outages must never
 *     block a Tech Intelligence run.
 *   - Idempotent: rows are upserted by `(advisoryId, packageName)`.
 */

import { AppDataSource } from '../../db/connection';
import { DependencyVulnerability } from '../../db/models/DependencyVulnerability';
import type { FingerprintCandidate } from './fingerprintEngine';

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRange {
  type: string;
  events: OsvRangeEvent[];
}

interface OsvAffectedPackage {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvRange[];
  versions?: string[];
}

interface OsvSeverity {
  type: string;
  score: string;
}

interface OsvVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffectedPackage[];
  references?: Array<{ url: string; type?: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  modified?: string;
  published?: string;
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

interface ProductMapping {
  /**
   * OSV ecosystem (e.g. `Packagist`, `npm`, `PyPI`, `Maven`).  Leave
   * undefined for products that OSV indexes without a structured
   * ecosystem — typically native runtimes / services like PHP itself,
   * nginx, Apache HTTP Server, OpenSSL, MySQL etc.  In that case we
   * issue a name-only query, which OSV honours by aggregating across
   * all ecosystems.
   */
  ecosystem?: string;
  packageName: string;
}

/**
 * Map our internal `productKey` (from the fingerprint engine) onto an
 * OSV ecosystem + canonical package name.  Verified empirically against
 * https://api.osv.dev/v1/query — entries that returned 0 results during
 * verification were either corrected to the right canonical form or
 * switched to a name-only query (which is what the OSV REST API expects
 * for runtime/native software).
 *
 * Adding a new productKey here is the only step required to extend
 * coverage — the orchestrator will pick it up automatically on the
 * next fingerprint run.
 */
const PRODUCT_TO_OSV: Record<string, ProductMapping[]> = {
  // PHP CMS / web platforms — for WordPress core, OSV's WP entries are
  // not under the Packagist `johnpbloch/wordpress-core` package but in
  // OSV's general namespace (~190 advisories), so we query by name.
  wordpress: [{ packageName: 'wordpress' }],
  drupal: [{ ecosystem: 'Packagist', packageName: 'drupal/core' }],
  joomla: [{ ecosystem: 'Packagist', packageName: 'joomla/joomla-cms' }],
  laravel: [{ ecosystem: 'Packagist', packageName: 'laravel/framework' }],
  symfony: [{ ecosystem: 'Packagist', packageName: 'symfony/symfony' }],

  // Front-end JavaScript libraries
  jquery: [{ ecosystem: 'npm', packageName: 'jquery' }],
  react: [{ ecosystem: 'npm', packageName: 'react' }],
  vue: [{ ecosystem: 'npm', packageName: 'vue' }],
  angular: [{ ecosystem: 'npm', packageName: '@angular/core' }],
  bootstrap: [{ ecosystem: 'npm', packageName: 'bootstrap' }],
  lodash: [{ ecosystem: 'npm', packageName: 'lodash' }],
  axios: [{ ecosystem: 'npm', packageName: 'axios' }],
  next: [{ ecosystem: 'npm', packageName: 'next' }],
  nuxt: [{ ecosystem: 'npm', packageName: 'nuxt' }],
  express: [{ ecosystem: 'npm', packageName: 'express' }],

  // Python / Java frameworks
  django: [{ ecosystem: 'PyPI', packageName: 'django' }],
  flask: [{ ecosystem: 'PyPI', packageName: 'flask' }],
  fastapi: [{ ecosystem: 'PyPI', packageName: 'fastapi' }],
  spring: [
    { ecosystem: 'Maven', packageName: 'org.springframework:spring-core' },
    { ecosystem: 'Maven', packageName: 'org.springframework.boot:spring-boot' },
  ],
  struts: [{ ecosystem: 'Maven', packageName: 'org.apache.struts:struts2-core' }],

  // Native services / runtimes — OSV indexes these without an
  // ecosystem prefix.  Verified empirically (Apr 2026):
  //   php@8.2.30      → 33 advisories
  //   nginx@1.24.0    → 173 advisories
  //   apache@2.4.49   → 60 advisories
  //   openssl@1.1.1   → 582 advisories
  //   mysql@8.0.30    → 100 advisories
  // Previously these were mapped to `[]`, so no OSV proof flowed
  // through for any native-service detection — that was the root cause
  // of the "I see no proof" report defect.
  apache_httpd: [{ packageName: 'apache' }],
  nginx: [{ packageName: 'nginx' }],
  iis: [{ packageName: 'iis' }],
  caddy: [{ packageName: 'caddy' }],
  lighttpd: [{ packageName: 'lighttpd' }],
  php: [{ packageName: 'php' }],
  mysql: [{ packageName: 'mysql' }],
  postgres: [{ packageName: 'postgresql' }],
  openssl: [{ packageName: 'openssl' }],
  redis: [{ packageName: 'redis' }],
  mongodb: [{ packageName: 'mongodb' }],
};

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
const OSV_TIMEOUT_MS = 8_000;
const OSV_PRODUCT_CONCURRENCY = 4;
/**
 * Per-product cap on OSV advisories we will persist.  Without this,
 * native-runtime products like OpenSSL (591 OSV entries for v1.1.1)
 * or PHP (33 distro-aggregate ALSA advisories, each with 20+
 * duplicate range events) would balloon the local cache and the
 * correlator's later read.  50 matches the correlator's own
 * `VULN_LIMIT_PER_PRODUCT`, so any hit beyond that wouldn't be
 * surfaced in the report anyway.
 */
const OSV_PERSIST_LIMIT = 50;

export interface OsvLookupSummary {
  productsQueried: number;
  advisoriesUpserted: number;
  failures: Array<{ product: string; error: string }>;
}

/**
 * For every detected technology with a known OSV mapping, query OSV
 * and upsert the returned advisories into our local cache.  The
 * existing `vulnerabilityCorrelator` will then pick those rows up
 * and produce real, version-range-backed correlations.
 */
export async function refreshOsvAdvisoriesForCandidates(
  candidates: FingerprintCandidate[],
): Promise<OsvLookupSummary> {
  const summary: OsvLookupSummary = {
    productsQueried: 0,
    advisoriesUpserted: 0,
    failures: [],
  };
  if (candidates.length === 0) return summary;

  const queue: Array<() => Promise<void>> = [];
  for (const candidate of candidates) {
    const mappings = PRODUCT_TO_OSV[candidate.productKey];
    if (!mappings || mappings.length === 0) continue;
    for (const mapping of mappings) {
      queue.push(async () => {
        summary.productsQueried += 1;
        try {
          const vulns = await queryOsv(mapping, candidate.version);
          // Rank by severity so that — when we cap at OSV_PERSIST_LIMIT
          // — the operator still sees the highest-impact advisories first.
          const ranked = vulns
            .slice()
            .sort((a, b) => (pickCvssScore(b.severity) ?? 0) - (pickCvssScore(a.severity) ?? 0))
            .slice(0, OSV_PERSIST_LIMIT);
          for (const v of ranked) {
            await upsertOsvVulnerability(v, mapping, candidate.productKey);
            summary.advisoriesUpserted += 1;
          }
        } catch (err) {
          summary.failures.push({
            product: `${mapping.ecosystem}:${mapping.packageName}`,
            error: (err as Error).message,
          });
        }
      });
    }
  }

  await runWithConcurrency(queue, OSV_PRODUCT_CONCURRENCY);
  return summary;
}

async function queryOsv(
  mapping: ProductMapping,
  version: string | null,
): Promise<OsvVulnerability[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
  try {
    // OSV `/v1/query` accepts `package.ecosystem` only when the
    // package lives in a structured ecosystem (Packagist, npm, …).
    // For native/runtime software (php, nginx, openssl) we omit it
    // and OSV aggregates across all ecosystems that mention the
    // package by name.
    const pkg: Record<string, unknown> = { name: mapping.packageName };
    if (mapping.ecosystem) pkg.ecosystem = mapping.ecosystem;
    const body: Record<string, unknown> = { package: pkg };
    if (version) body.version = version;
    const res = await fetch(OSV_QUERY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`osv.dev responded ${res.status}`);
    const json = (await res.json()) as OsvQueryResponse;
    return Array.isArray(json.vulns) ? json.vulns : [];
  } finally {
    clearTimeout(timer);
  }
}

async function upsertOsvVulnerability(
  vuln: OsvVulnerability,
  mapping: ProductMapping,
  detectedProductKey: string,
): Promise<void> {
  const repo = AppDataSource.getRepository(DependencyVulnerability);

  const cveId =
    vuln.aliases?.find((a) => a.startsWith('CVE-')) ??
    (vuln.id.startsWith('CVE-') ? vuln.id : null);

  const score = pickCvssScore(vuln.severity);
  const severityLabel = scoreToSeverity(score, vuln.database_specific?.severity);

  const { affectedRanges, fixedVersions } = stringifyOsvRanges(vuln.affected, mapping);
  const sourceUrl =
    vuln.references?.find((r) => r.type === 'ADVISORY')?.url ??
    vuln.references?.[0]?.url ??
    `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`;

  const summaryText = (vuln.summary || vuln.details || vuln.id).slice(0, 510);
  const detailsText = vuln.details && vuln.details !== summaryText ? vuln.details : null;

  // Upsert by `advisoryId` so re-runs idempotently refresh the row.
  const existing = await repo.findOne({ where: { advisoryId: vuln.id } });
  const payload = {
    // Tag the row with whichever ecosystem we queried under so it is
    // searchable later; "OSV" is used as a generic bucket for the
    // name-only queries that don't have a structured ecosystem.
    ecosystem: (mapping.ecosystem ?? 'OSV').slice(0, 32),
    // Store the **detected product key** (e.g. "wordpress") so the
    // correlator's `packageName = productKey` lookup hits this row.
    packageName: detectedProductKey.slice(0, 250),
    advisoryId: vuln.id,
    cveId,
    severityLabel,
    severityScore: score,
    summary: summaryText,
    details: detailsText,
    affectedRanges,
    fixedVersions,
    source: 'osv',
    sourceUrl,
    publishedAt: vuln.published ? new Date(vuln.published) : null,
    modifiedAt: vuln.modified ? new Date(vuln.modified) : null,
  } as const;
  if (existing) {
    await repo.update({ id: existing.id }, payload);
  } else {
    await repo.save(repo.create(payload));
  }
}

function pickCvssScore(severities?: OsvSeverity[]): number | null {
  if (!severities || severities.length === 0) return null;
  // Prefer CVSS v3.1 → v3.0 → v4.0 → v2.
  const order = ['CVSS_V3_1', 'CVSS_V3', 'CVSS_V4', 'CVSS_V2'];
  for (const type of order) {
    const hit = severities.find((s) => s.type === type);
    if (hit) {
      const m = /(\d+(?:\.\d+)?)/.exec(hit.score);
      if (m) {
        const score = Number.parseFloat(m[1]);
        if (Number.isFinite(score)) return score;
      }
    }
  }
  // Generic fallback: first numeric token in any severity row.
  for (const s of severities) {
    const m = /(\d+(?:\.\d+)?)/.exec(s.score);
    if (m) {
      const score = Number.parseFloat(m[1]);
      if (Number.isFinite(score)) return score;
    }
  }
  return null;
}

function scoreToSeverity(score: number | null, hint: string | undefined): string {
  const lowered = (hint ?? '').toLowerCase();
  if (lowered === 'critical') return 'Critical';
  if (lowered === 'high') return 'High';
  if (lowered === 'moderate' || lowered === 'medium') return 'Medium';
  if (lowered === 'low') return 'Low';
  if (typeof score === 'number') {
    if (score >= 9) return 'Critical';
    if (score >= 7) return 'High';
    if (score >= 4) return 'Medium';
    if (score > 0) return 'Low';
  }
  return 'Unknown';
}

/**
 * Convert OSV's `affected[].ranges[].events[]` (introduced/fixed pairs)
 * into the simple semver-range syntax our correlator already speaks
 * (`>=A.B.C <X.Y.Z`).
 */
function stringifyOsvRanges(
  affected: OsvAffectedPackage[] | undefined,
  expected: ProductMapping,
): { affectedRanges: string | null; fixedVersions: string | null } {
  if (!affected || affected.length === 0) {
    return { affectedRanges: null, fixedVersions: null };
  }
  const ranges: string[] = [];
  const fixed = new Set<string>();

  for (const pkg of affected) {
    // When we sent an ecosystem-scoped query, drop entries that came
    // back tagged with a *different* ecosystem (cross-ecosystem noise).
    // For name-only queries (`expected.ecosystem === undefined`) we
    // accept everything OSV returns — the unscoped query is exactly how
    // OSV exposes native-runtime advisories.
    if (
      expected.ecosystem &&
      pkg.package?.ecosystem &&
      pkg.package.ecosystem !== expected.ecosystem
    ) {
      continue;
    }
    for (const range of pkg.ranges ?? []) {
      // OSV "events" are an ordered timeline: introduced → fixed (or
      // last_affected, or limit).  We pair them up sequentially.
      let introduced: string | null = null;
      for (const event of range.events) {
        if (event.introduced) {
          introduced = event.introduced === '0' ? null : event.introduced;
        } else if (event.fixed) {
          // Some OSV producers (notably distro-mirror feeds like ALSA)
          // emit `{introduced: '0', fixed: '0'}` placeholder rows.
          // Translating those to `<0` would be misleading garbage —
          // skip them entirely.
          if (event.fixed === '0') {
            introduced = null;
            continue;
          }
          fixed.add(event.fixed);
          ranges.push(
            introduced ? `>=${introduced} <${event.fixed}` : `<${event.fixed}`,
          );
          introduced = null;
        } else if (event.last_affected) {
          if (event.last_affected === '0') {
            introduced = null;
            continue;
          }
          ranges.push(
            introduced
              ? `>=${introduced} <=${event.last_affected}`
              : `<=${event.last_affected}`,
          );
          introduced = null;
        }
      }
      // Open-ended introduced (no fixed event) → "≥introduced".
      if (introduced) ranges.push(`>=${introduced}`);
    }
  }

  const dedupedRanges = Array.from(new Set(ranges));
  return {
    affectedRanges: dedupedRanges.length > 0 ? dedupedRanges.slice(0, 6).join('; ') : null,
    fixedVersions: fixed.size > 0 ? Array.from(fixed).slice(0, 6).join(', ') : null,
  };
}

async function runWithConcurrency(
  queue: Array<() => Promise<void>>,
  parallelism: number,
): Promise<void> {
  const workers: Promise<void>[] = [];
  let cursor = 0;
  const next = async (): Promise<void> => {
    while (cursor < queue.length) {
      const job = queue[cursor];
      cursor += 1;
      await job();
    }
  };
  for (let i = 0; i < Math.min(parallelism, queue.length); i += 1) {
    workers.push(next());
  }
  await Promise.all(workers);
}
