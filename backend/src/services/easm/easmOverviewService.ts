/**
 * UASF — External Attack Surface Management (EASM) overview aggregator.
 *
 * Produces the single, denormalised view-model that powers:
 *   - the EASM dashboard page
 *   - the Executive Summary report (HTML + PDF)
 *
 * The pattern is intentional: every consumer reads the SAME shape from
 * the SAME aggregator so the dashboard tile and the PDF cover page can
 * never disagree.  The model is composed from data that already exists
 * in the platform (Targets, DiscoveredService, DetectedTechnology,
 * VulnerabilityCorrelation, DependencyVulnerability, SecurityFinding,
 * Report) — no new sources are introduced.
 *
 * The overall security score / grade is derived from the issue and
 * vulnerability severity distribution of the most-recent scan history,
 * weighted so a single Critical eats the score harder than ten Low.
 */

import psl from 'psl';
import { AppDataSource } from '../../db/connection';
import { Target } from '../../db/models/Target';
import { DetectedTechnology, type FingerprintConfidence } from '../../db/models/DetectedTechnology';
import { VulnerabilityCorrelation } from '../../db/models/VulnerabilityCorrelation';
import { DependencyVulnerability } from '../../db/models/DependencyVulnerability';
import { DiscoveredService } from '../../db/models/DiscoveredService';
import { SecurityFinding } from '../../db/models/SecurityFinding';
import { Report } from '../../db/models/Report';
import { TechIntelRun } from '../../db/models/TechIntelRun';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SeverityLabel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface SeverityCount {
  label: SeverityLabel;
  count: number;
}

export interface MetricTile {
  /** Card label shown in the UI / report (e.g. "Total Assets"). */
  label: string;
  /** Current value, rendered large. */
  value: number;
  /** Period delta (last 7 days vs. prior 7 days).  `null` if unknown. */
  delta: number | null;
  /** Sub-line shown beneath the delta (e.g. "Last week: 7 Assets"). */
  subline: string;
}

export interface ScoreSummary {
  /** 0-1000 numeric score (higher = healthier). */
  score: number;
  /** A / B / C / D / F letter grade. */
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  /** Per-severity weight applied (informational). */
  weights: Record<SeverityLabel, number>;
  /** One-liner describing what dragged the score down. */
  summary: string;
}

export interface TopAssetRow {
  hostname: string;
  assetType: string;
  rating: 'A' | 'B' | 'C' | 'D' | 'F';
  ratingScore: number;
  issues: number;
  technologies: number;
}

export interface TopIssueRow {
  title: string;
  severity: SeverityLabel;
  category: string;
  /** Distinct asset count where this issue was observed. */
  assetCount: number;
}

export interface TopTechnologyRow {
  productKey: string;
  productName: string;
  category: string;
  vendor: string | null;
  version: string | null;
  versionFamily: string | null;
  /** Distinct assets carrying this technology. */
  assetCount: number;
  /** Correlated CVE/advisory count across all observations. */
  vulnerabilityCount: number;
}

export interface AssetTypeBreakdown {
  type: string;
  count: number;
}

export interface TimelineBucket {
  /** ISO date (UTC, day-truncated). */
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface EasmOverview {
  generatedAt: string;
  /** ISO window the report covers (last 7 days). */
  window: { from: string; to: string };

  /** 4 cover-page tiles, in the same order the PDF renders them. */
  tiles: {
    assets: MetricTile;
    technologies: MetricTile;
    issues: MetricTile;
    vulnerabilities: MetricTile;
  };

  /** Headline security score + letter grade. */
  score: ScoreSummary;

  /** 14-day daily issue-volume buckets (used by the timeline chart). */
  timeline: TimelineBucket[];

  /** Asset rollup. */
  assets: {
    total: number;
    domains: number;
    subdomains: number;
    ipAddresses: number;
    byType: AssetTypeBreakdown[];
    top: TopAssetRow[];
  };

  /** Issue rollup. */
  issues: {
    total: number;
    bySeverity: SeverityCount[];
    byCategory: Array<{ category: string; count: number }>;
    mostCritical: TopIssueRow[];
    mostSeen: TopIssueRow[];
  };

  /** Technology rollup. */
  technologies: {
    total: number;
    byCategory: Array<{ category: string; count: number }>;
    mostUsed: TopTechnologyRow[];
    mostVulnerable: TopTechnologyRow[];
  };

  /** Vulnerability rollup (CVE/advisory correlations + dependency feed hits). */
  vulnerabilities: {
    total: number;
    bySeverity: SeverityCount[];
  };
}

// ---------------------------------------------------------------------------
// Public entrypoint
// ---------------------------------------------------------------------------

export async function buildEasmOverview(): Promise<EasmOverview> {
  const now = new Date();
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const fourteenDaysAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

  const [
    targets,
    detectedTechs,
    correlations,
    dependencyVulns,
    securityFindings,
    discoveredServices,
    reports,
    techIntelRuns,
  ] = await Promise.all([
    AppDataSource.getRepository(Target).find(),
    AppDataSource.getRepository(DetectedTechnology).find(),
    AppDataSource.getRepository(VulnerabilityCorrelation).find(),
    AppDataSource.getRepository(DependencyVulnerability).find(),
    AppDataSource.getRepository(SecurityFinding).find(),
    AppDataSource.getRepository(DiscoveredService).find(),
    AppDataSource.getRepository(Report).find({
      order: { createdAt: 'DESC' },
      take: 200,
    }),
    AppDataSource.getRepository(TechIntelRun).find({
      order: { createdAt: 'DESC' },
      take: 200,
    }),
  ]);

  // -------------------- Assets --------------------
  const approvedTargets = targets.filter((t) => t.approvalStatus === 'approved');
  const { domains, subdomains, ipAddresses } = bucketAssetsByShape(approvedTargets);
  const byTypeMap = new Map<string, number>();
  for (const t of approvedTargets) {
    const key = t.assetType || 'web';
    byTypeMap.set(key, (byTypeMap.get(key) ?? 0) + 1);
  }
  const assetByType: AssetTypeBreakdown[] = [...byTypeMap.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);

  // -------------------- Technologies --------------------
  // De-dupe across runs so the "Total Technologies" tile matches the
  // intent of the EASM report (distinct technology surface), not the
  // observation count.
  const techByProduct = new Map<string, DetectedTechnology[]>();
  for (const tech of detectedTechs) {
    const list = techByProduct.get(tech.productKey) ?? [];
    list.push(tech);
    techByProduct.set(tech.productKey, list);
  }

  const techByCategory = new Map<string, number>();
  for (const productKey of techByProduct.keys()) {
    const sample = techByProduct.get(productKey)![0];
    techByCategory.set(sample.category, (techByCategory.get(sample.category) ?? 0) + 1);
  }
  const technologyByCategory = [...techByCategory.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);

  // Map run -> targetKey so we can compute per-asset technology coverage.
  const techIntelRunIndex = new Map<string, TechIntelRun>();
  for (const run of techIntelRuns) techIntelRunIndex.set(run.id, run);

  const correlationsByProduct = new Map<string, VulnerabilityCorrelation[]>();
  for (const c of correlations) {
    const list = correlationsByProduct.get(c.productKey) ?? [];
    list.push(c);
    correlationsByProduct.set(c.productKey, list);
  }

  const mostUsedTech: TopTechnologyRow[] = [...techByProduct.entries()]
    .map(([productKey, observations]) => {
      const sample = observations[0];
      const distinctAssets = new Set(
        observations
          .map((o) => techIntelRunIndex.get(o.runId)?.targetKey)
          .filter((s): s is string => Boolean(s)),
      );
      const vulnerabilityCount = correlationsByProduct.get(productKey)?.length ?? 0;
      return {
        productKey,
        productName: sample.productName,
        category: sample.category,
        vendor: sample.vendor,
        version: sample.version,
        versionFamily: sample.versionFamily,
        assetCount: distinctAssets.size || 1,
        vulnerabilityCount,
      };
    })
    .sort((a, b) => b.assetCount - a.assetCount || a.productName.localeCompare(b.productName))
    .slice(0, 10);

  const mostVulnerableTech: TopTechnologyRow[] = [...mostUsedTech]
    .filter((t) => t.vulnerabilityCount > 0)
    .sort((a, b) => b.vulnerabilityCount - a.vulnerabilityCount || b.assetCount - a.assetCount)
    .slice(0, 10);

  // -------------------- Issues --------------------
  // Issues = SecurityFinding rows (cross-domain DAST/SAST/etc) +
  //         high-severity Discovery findings (encoded in Report.resultJson)
  // We keep the model honest by counting every Report's severity rollups,
  // already-denormalised at write time, on top of SecurityFinding.
  const issuesBySeverity: Record<SeverityLabel, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  const issuesByCategory = new Map<string, number>();

  for (const f of securityFindings) {
    const sev = normaliseSeverity(f.severity);
    issuesBySeverity[sev] += 1;
    const cat = friendlyCategory(f.category, f.findingDomain);
    issuesByCategory.set(cat, (issuesByCategory.get(cat) ?? 0) + 1);
  }
  for (const r of reports) {
    issuesBySeverity.Critical += r.criticalCount;
    issuesBySeverity.High += r.highCount;
    issuesBySeverity.Medium += r.mediumCount;
    issuesBySeverity.Low += r.lowCount;
    issuesBySeverity.Info += r.infoCount;
    const reportCat = r.reportType === 'discovery' ? 'Network' : 'Web Application';
    const total = r.criticalCount + r.highCount + r.mediumCount + r.lowCount + r.infoCount;
    issuesByCategory.set(reportCat, (issuesByCategory.get(reportCat) ?? 0) + total);
  }

  const totalIssues = sum(Object.values(issuesBySeverity));

  // Most-critical issues — group by title, keep highest severity, count
  // distinct assets.  Synthesise from SecurityFinding (real per-asset
  // mapping exists there).  Reports are aggregated rollups so they
  // contribute to the count totals but not to the per-asset listing.
  const issueGroups = new Map<
    string,
    {
      title: string;
      category: string;
      severity: SeverityLabel;
      assetIds: Set<string>;
    }
  >();
  for (const f of securityFindings) {
    const key = f.title;
    const cur =
      issueGroups.get(key) ??
      {
        title: f.title,
        category: friendlyCategory(f.category, f.findingDomain),
        severity: normaliseSeverity(f.severity),
        assetIds: new Set<string>(),
      };
    cur.severity = pickWorseSeverity(cur.severity, normaliseSeverity(f.severity));
    if (f.assetId) cur.assetIds.add(f.assetId);
    issueGroups.set(key, cur);
  }
  // Synthesise the high-impact issues that our existing reportSummariser
  // emits (Database Service Detected, Exploitable Vulnerability on jQuery,
  // etc.) from each Report's findings JSON, so the executive summary
  // matches the rest of the platform.
  for (const r of reports) {
    const findings = (r.resultJson?.findings ?? []) as Array<{
      title: string;
      severity?: string;
      category?: string;
    }>;
    for (const f of findings.slice(0, 50)) {
      if (!f?.title) continue;
      const cur =
        issueGroups.get(f.title) ??
        {
          title: f.title,
          category: f.category ?? (r.reportType === 'discovery' ? 'Network' : 'Web Application'),
          severity: normaliseSeverity(f.severity ?? 'Info'),
          assetIds: new Set<string>(),
        };
      cur.severity = pickWorseSeverity(cur.severity, normaliseSeverity(f.severity ?? 'Info'));
      cur.assetIds.add(r.targetHostname);
      issueGroups.set(f.title, cur);
    }
  }
  const issueRows: TopIssueRow[] = [...issueGroups.values()].map((g) => ({
    title: g.title,
    severity: g.severity,
    category: g.category,
    assetCount: g.assetIds.size,
  }));

  const mostCriticalIssues = [...issueRows]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.assetCount - a.assetCount)
    .slice(0, 5);
  const mostSeenIssues = [...issueRows]
    .sort((a, b) => b.assetCount - a.assetCount || severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 5);

  // -------------------- Vulnerabilities (CVE/advisory) --------------------
  // IMPORTANT: only count correlations that are bound to a tech actually
  // detected on the approved surface. We previously summed the entire
  // `dependency_vulnerabilities` cache (the global NVD/OSV/mycve feed
  // we ingest for fast lookups), which inflated the Total Vulnerabilities
  // tile by hundreds of unrelated CVEs and made the dashboard read like
  // every customer was carrying the whole NVD database. The dependency
  // feed cache is a lookup table, not part of the customer's surface.
  const vulnsBySeverity: Record<SeverityLabel, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  const observedProductKeys = new Set<string>();
  for (const tech of detectedTechs) observedProductKeys.add(tech.productKey);

  for (const c of correlations) {
    if (!observedProductKeys.has(c.productKey)) continue;
    const sev = normaliseSeverity(c.severityLabel);
    vulnsBySeverity[sev] += 1;
  }
  // Dependency feed CVEs only count when they correspond to a package we
  // have actually fingerprinted on at least one approved asset (loose
  // case-insensitive match against productName / productKey).
  const observedProductNames = new Set<string>();
  for (const tech of detectedTechs) {
    if (tech.productName) observedProductNames.add(tech.productName.toLowerCase());
    if (tech.productKey) observedProductNames.add(tech.productKey.toLowerCase());
  }
  for (const v of dependencyVulns) {
    const pkg = (v.packageName ?? '').toLowerCase();
    if (!pkg || !observedProductNames.has(pkg)) continue;
    const sev = normaliseSeverity(v.severityLabel);
    vulnsBySeverity[sev] += 1;
  }
  const totalVulns = sum(Object.values(vulnsBySeverity));

  // -------------------- Top assets table --------------------
  // Use SecurityFinding + DiscoveredService + DetectedTechnology to score
  // each asset, then rank by per-asset risk.
  const findingsByAsset = new Map<string, SecurityFinding[]>();
  for (const f of securityFindings) {
    if (!f.assetId) continue;
    const list = findingsByAsset.get(f.assetId) ?? [];
    list.push(f);
    findingsByAsset.set(f.assetId, list);
  }
  const techByAssetKey = new Map<string, Set<string>>();
  for (const tech of detectedTechs) {
    const key = techIntelRunIndex.get(tech.runId)?.targetKey ?? '';
    if (!key) continue;
    const set = techByAssetKey.get(key) ?? new Set<string>();
    set.add(tech.productKey);
    techByAssetKey.set(key, set);
  }
  const servicesByAsset = new Map<string, number>();
  for (const s of discoveredServices) {
    servicesByAsset.set(s.assetId, (servicesByAsset.get(s.assetId) ?? 0) + 1);
  }

  const topAssets: TopAssetRow[] = approvedTargets
    .map((t) => {
      const fset = findingsByAsset.get(t.id) ?? [];
      const issues = fset.length;
      const techCount = techByAssetKey.get(t.hostname)?.size ?? 0;
      // Per-asset score uses the same weighting as the global score.
      const sevCounts: Record<SeverityLabel, number> = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Info: 0,
      };
      for (const f of fset) sevCounts[normaliseSeverity(f.severity)] += 1;
      const { score, grade } = computeScore(sevCounts);
      return {
        hostname: t.hostname,
        assetType: t.assetType,
        rating: grade,
        ratingScore: score,
        issues,
        technologies: techCount,
      };
    })
    .sort((a, b) => a.ratingScore - b.ratingScore || b.issues - a.issues)
    .slice(0, 10);

  // -------------------- Score --------------------
  const score = computeScore(issuesBySeverity);

  // -------------------- Timeline --------------------
  const timeline = buildTimeline(reports, fourteenDaysAgo, now);

  // -------------------- Period deltas --------------------
  const recentlyAddedTargets = approvedTargets.filter((t) => t.createdAt >= sevenDaysAgo).length;
  const recentlyAddedTechs = detectedTechs.filter((t) => t.createdAt >= sevenDaysAgo).length;
  const recentlyAddedReports = reports.filter((r) => r.createdAt >= sevenDaysAgo);
  const recentlyAddedIssuesDelta =
    recentlyAddedReports.reduce(
      (acc, r) =>
        acc + r.criticalCount + r.highCount + r.mediumCount + r.lowCount + r.infoCount,
      0,
    ) +
    securityFindings.filter((f) => f.createdAt >= sevenDaysAgo).length;
  const recentlyAddedVulnsDelta = correlations.filter(
    (c) => c.createdAt >= sevenDaysAgo && observedProductKeys.has(c.productKey),
  ).length;

  return {
    generatedAt: now.toISOString(),
    window: { from: sevenDaysAgo.toISOString(), to: now.toISOString() },
    tiles: {
      assets: makeTile('Total Assets', approvedTargets.length, recentlyAddedTargets, 'Assets'),
      technologies: makeTile(
        'Total Technologies',
        techByProduct.size,
        recentlyAddedTechs,
        'Technologies',
      ),
      issues: makeTile('Total Issues', totalIssues, recentlyAddedIssuesDelta, 'Issues'),
      vulnerabilities: makeTile(
        'Total Vulnerabilities',
        totalVulns,
        recentlyAddedVulnsDelta,
        'Vulnerabilities',
      ),
    },
    score,
    timeline,
    assets: {
      total: approvedTargets.length,
      domains,
      subdomains,
      ipAddresses,
      byType: assetByType,
      top: topAssets,
    },
    issues: {
      total: totalIssues,
      bySeverity: orderedSeverityCounts(issuesBySeverity),
      byCategory: [...issuesByCategory.entries()]
        .map(([category, count]) => ({ category, count }))
        .sort((a, b) => b.count - a.count),
      mostCritical: mostCriticalIssues,
      mostSeen: mostSeenIssues,
    },
    technologies: {
      total: techByProduct.size,
      byCategory: technologyByCategory,
      mostUsed: mostUsedTech,
      mostVulnerable: mostVulnerableTech,
    },
    vulnerabilities: {
      total: totalVulns,
      bySeverity: orderedSeverityCounts(vulnsBySeverity),
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTile(label: string, value: number, delta: number, unit: string): MetricTile {
  return {
    label,
    value,
    delta,
    subline: `Last 7 days: ${delta} ${unit}`,
  };
}

/**
 * Bucket approved targets into "domain", "subdomain", or "ipAddress" using
 * the official Mozilla Public Suffix List via the `psl` package.
 *
 * A hostname is classified as a "domain" when it equals its registrable
 * (eTLD+1) name, e.g. `southwark.gov.uk`, `bermondseyantiquemarket.co.uk`,
 * `example.com`. It is a "subdomain" when there are additional labels
 * to the left of the registrable name, e.g. `www.vulnhub.com`,
 * `juiceshopnew.testapptrana.net`.
 *
 * The previous heuristic (>=3 labels => subdomain) misclassified every
 * host on a multi-label public suffix (`.co.uk`, `.gov.uk`, `.org.tr`,
 * `.com.tr`) as a subdomain, inflating the subdomain count.
 */
function bucketAssetsByShape(targets: Target[]): {
  domains: number;
  subdomains: number;
  ipAddresses: number;
} {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[a-f0-9:]+$/i;

  let ipAddresses = 0;
  let domains = 0;
  let subdomains = 0;

  for (const t of targets) {
    const h = t.hostname.trim().toLowerCase();
    if (!h) continue;
    if (ipv4.test(h) || (h.includes(':') && ipv6.test(h))) {
      ipAddresses += 1;
      continue;
    }
    const parsed = psl.parse(h) as { domain?: string | null; subdomain?: string | null; error?: unknown };
    if (parsed.error || !parsed.domain) {
      // Unparseable host (private TLD, etc.) — fall back to the count of
      // labels: <=2 => domain, otherwise treat as subdomain.
      h.split('.').length <= 2 ? (domains += 1) : (subdomains += 1);
      continue;
    }
    if (parsed.subdomain) {
      subdomains += 1;
    } else {
      domains += 1;
    }
  }
  return { domains, subdomains, ipAddresses };
}

function normaliseSeverity(label: string | null | undefined): SeverityLabel {
  const l = (label ?? '').toLowerCase();
  if (l.startsWith('crit')) return 'Critical';
  if (l.startsWith('high')) return 'High';
  if (l.startsWith('med')) return 'Medium';
  if (l.startsWith('low')) return 'Low';
  return 'Info';
}

function severityRank(s: SeverityLabel): number {
  switch (s) {
    case 'Critical':
      return 5;
    case 'High':
      return 4;
    case 'Medium':
      return 3;
    case 'Low':
      return 2;
    case 'Info':
      return 1;
  }
}

function pickWorseSeverity(a: SeverityLabel, b: SeverityLabel): SeverityLabel {
  return severityRank(a) >= severityRank(b) ? a : b;
}

function orderedSeverityCounts(input: Record<SeverityLabel, number>): SeverityCount[] {
  const order: SeverityLabel[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  return order.map((label) => ({ label, count: input[label] }));
}

/**
 * Friendly category label.  Maps the engine-internal `findingDomain`
 * onto the same vocabulary the cover page uses (Web Application,
 * Network, DNS, Domain/Whois) so the executive table reads the same
 * across the dashboard and the PDF.
 */
function friendlyCategory(rawCategory: string, domain: string): string {
  const c = (rawCategory ?? '').toLowerCase();
  const d = (domain ?? '').toLowerCase();
  if (d === 'exposure' || c.includes('port') || c.includes('service')) return 'Network';
  if (d === 'dependency' || c.includes('dependency')) return 'Software Supply Chain';
  if (d === 'ioc' || c.includes('ioc') || c.includes('threat')) return 'Threat Intelligence';
  if (d === 'sast' || c.includes('code')) return 'Source Code';
  if (c.includes('dns')) return 'DNS';
  if (c.includes('whois') || c.includes('domain')) return 'Domain/WHOIS';
  return 'Web Application';
}

/**
 * Headline security score.  Higher is better; A=900-1000, B=800-899,
 * C=700-799, D=600-699, F<600.  Each severity drains a fixed budget,
 * but the curve flattens out so a single Critical doesn't immediately
 * tank a large multi-asset programme to F.
 */
export function computeScore(counts: Record<SeverityLabel, number>): ScoreSummary {
  const weights: Record<SeverityLabel, number> = {
    Critical: 80,
    High: 30,
    Medium: 10,
    Low: 3,
    Info: 0,
  };
  const drain =
    counts.Critical * weights.Critical +
    counts.High * weights.High +
    counts.Medium * weights.Medium +
    counts.Low * weights.Low;
  // log-shape so the score doesn't fall off a cliff once you have many
  // Lows; an asset surface with 50 Lows still scores >800.
  const damped = drain === 0 ? 0 : Math.round(140 * Math.log10(1 + drain / 30));
  const raw = Math.max(0, 1000 - damped);
  const score = Math.min(1000, raw);
  const grade = scoreToGrade(score);
  let summary: string;
  if (counts.Critical > 0) {
    summary = `${counts.Critical} Critical issue${counts.Critical === 1 ? '' : 's'} dominate the score.`;
  } else if (counts.High > 0) {
    summary = `${counts.High} High-severity issue${counts.High === 1 ? '' : 's'} are the dominant risk drivers.`;
  } else if (counts.Medium > 0) {
    summary = `Medium-severity issues are the main score drag (${counts.Medium}).`;
  } else if (counts.Low > 0) {
    summary = `Only Low-severity hygiene findings remain (${counts.Low}).`;
  } else {
    summary = 'No active findings on the approved attack surface.';
  }
  return { score, grade, weights, summary };
}

function scoreToGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 900) return 'A';
  if (score >= 800) return 'B';
  if (score >= 700) return 'C';
  if (score >= 600) return 'D';
  return 'F';
}

function buildTimeline(reports: Report[], from: Date, to: Date): TimelineBucket[] {
  const days: TimelineBucket[] = [];
  const cursor = new Date(from);
  cursor.setUTCHours(0, 0, 0, 0);
  while (cursor <= to) {
    days.push({
      date: cursor.toISOString().slice(0, 10),
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  const idx = new Map(days.map((d, i) => [d.date, i]));
  for (const r of reports) {
    const key = new Date(r.createdAt).toISOString().slice(0, 10);
    const i = idx.get(key);
    if (i === undefined) continue;
    days[i].critical += r.criticalCount;
    days[i].high += r.highCount;
    days[i].medium += r.mediumCount;
    days[i].low += r.lowCount;
  }
  return days;
}

function sum(values: number[]): number {
  return values.reduce((a, b) => a + b, 0);
}

// (re-export for tests)
export const _internals = {
  bucketAssetsByShape,
  normaliseSeverity,
  computeScore,
  buildTimeline,
};

// Helper used by the report renderer when it needs to colour fingerprint
// confidence chips on a per-tech card without importing the entity enum
// in another file.
export function confidenceLabel(c: FingerprintConfidence): string {
  switch (c) {
    case 'very_high':
      return 'very high';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    default:
      return 'low';
  }
}
