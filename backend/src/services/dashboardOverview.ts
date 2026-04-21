import { MoreThanOrEqual } from 'typeorm';
import { AppDataSource } from '../db/connection';
import { Campaign } from '../db/models/Campaign';
import { CodeFinding } from '../db/models/CodeFinding';
import { DependencyVulnerability } from '../db/models/DependencyVulnerability';
import { DiscoveredService } from '../db/models/DiscoveredService';
import { AssessmentRun } from '../db/models/AssessmentRun';
import { EvidenceLog } from '../db/models/Evidence';
import { IocIndicator } from '../db/models/IocIndicator';
import { MalwareArtifact } from '../db/models/MalwareArtifact';
import { Report } from '../db/models/Report';
import { SecurityFinding } from '../db/models/SecurityFinding';
import { ScenarioTemplate } from '../db/models/ScenarioTemplate';
import { Target } from '../db/models/Target';
import { TechIntelRun } from '../db/models/TechIntelRun';
import { WafValidationRun } from '../db/models/WafValidationRun';
import { redisConnection, scenarioQueue } from '../engine/queue';
import { WAAP_SCENARIOS } from '../engine/scenarios';

export type DashboardWindow = 'daily' | 'weekly' | 'monthly' | 'yearly';

type TimelineBucket = {
  label: string;
  blocked: number;
  allowed: number;
  errors: number;
};

type WindowSummary = {
  key: DashboardWindow;
  label: string;
  from: string;
  to: string;
  requests: number;
  blocked: number;
  allowed: number;
  errors: number;
  blockRate: number;
  runs: number;
  findings: number;
  newAssets: number;
  uniqueTargets: number;
  timeline: TimelineBucket[];
};

const WINDOW_LABELS: Record<DashboardWindow, string> = {
  daily: 'Last 24 hours',
  weekly: 'Last 7 days',
  monthly: 'Last 30 days',
  yearly: 'Last 12 months',
};

const SCANNER_MODULES = [
  { id: 'discoveryScanner', name: 'Discovery Scanner', domain: 'Application Assessment' },
  { id: 'tlsScanner', name: 'TLS Scanner', domain: 'Application Assessment' },
  { id: 'headerAssessment', name: 'Header Assessment', domain: 'Application Assessment' },
  { id: 'serviceExposureScanner', name: 'Service Exposure Scanner', domain: 'Application Assessment' },
  { id: 'webAssessment', name: 'Web Surface Assessment', domain: 'Application Assessment' },
] as const;

function getWindowStart(window: DashboardWindow, now: Date): Date {
  const start = new Date(now);
  switch (window) {
    case 'daily':
      start.setHours(now.getHours() - 23, 0, 0, 0);
      return start;
    case 'weekly':
      start.setDate(now.getDate() - 6);
      start.setHours(0, 0, 0, 0);
      return start;
    case 'monthly':
      start.setDate(now.getDate() - 29);
      start.setHours(0, 0, 0, 0);
      return start;
    case 'yearly':
      start.setMonth(now.getMonth() - 11, 1);
      start.setHours(0, 0, 0, 0);
      return start;
    default:
      return start;
  }
}

function formatBucketLabel(date: Date, window: DashboardWindow): string {
  switch (window) {
    case 'daily':
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    case 'weekly':
    case 'monthly':
      return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    case 'yearly':
      return date.toLocaleDateString([], { month: 'short' });
    default:
      return date.toLocaleString();
  }
}

function getBucketKey(date: Date, window: DashboardWindow): string {
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, '0');
  const day = `${date.getDate()}`.padStart(2, '0');
  const hour = `${date.getHours()}`.padStart(2, '0');

  if (window === 'daily') {
    return `${year}-${month}-${day}T${hour}`;
  }
  if (window === 'yearly') {
    return `${year}-${month}`;
  }
  return `${year}-${month}-${day}`;
}

function createTimeline(window: DashboardWindow, from: Date, to: Date): TimelineBucket[] {
  const buckets: TimelineBucket[] = [];
  const cursor = new Date(from);

  while (cursor <= to) {
    buckets.push({
      label: formatBucketLabel(cursor, window),
      blocked: 0,
      allowed: 0,
      errors: 0,
    });

    if (window === 'daily') {
      cursor.setHours(cursor.getHours() + 1);
    } else if (window === 'yearly') {
      cursor.setMonth(cursor.getMonth() + 1, 1);
    } else {
      cursor.setDate(cursor.getDate() + 1);
    }
  }

  return buckets;
}

function buildWindowSummary(
  window: DashboardWindow,
  now: Date,
  evidence: EvidenceLog[],
  runs: AssessmentRun[],
  findings: SecurityFinding[],
  targets: Target[],
): WindowSummary {
  const from = getWindowStart(window, now);
  const filteredEvidence = evidence.filter((event) => event.timestamp >= from);
  const filteredRuns = runs.filter((run) => run.createdAt >= from);
  const filteredFindings = findings.filter((finding) => finding.createdAt >= from);
  const filteredTargets = targets.filter((target) => target.createdAt >= from);
  const timeline = createTimeline(window, from, now);
  const bucketIndex = new Map<string, number>();

  timeline.forEach((bucket, index) => {
    let keyDate = new Date(from);
    if (window === 'daily') {
      keyDate.setHours(from.getHours() + index);
    } else if (window === 'yearly') {
      keyDate.setMonth(from.getMonth() + index, 1);
    } else {
      keyDate.setDate(from.getDate() + index);
    }
    bucketIndex.set(getBucketKey(keyDate, window), index);
  });

  const isControlled = (event: EvidenceLog): boolean => {
    const verdict = event.verdict ?? '';
    if (
      verdict === 'blocked' ||
      verdict === 'challenged' ||
      verdict === 'edge_mitigated' ||
      verdict === 'origin_rejected'
    ) {
      return true;
    }
    if (!verdict || verdict === 'ambiguous') {
      // Backwards compatibility for evidence rows captured before verdict
      // classification existed.
      return event.responseStatusCode >= 400;
    }
    return false;
  };
  const isAllowed = (event: EvidenceLog): boolean => {
    const verdict = event.verdict ?? '';
    if (verdict === 'allowed') return true;
    if (!verdict || verdict === 'ambiguous') {
      return event.responseStatusCode >= 200 && event.responseStatusCode < 400;
    }
    return false;
  };
  const isError = (event: EvidenceLog): boolean => {
    const verdict = event.verdict ?? '';
    if (verdict === 'network_error') return true;
    if (!verdict) {
      return event.executionStatus === 'network_error' || event.responseStatusCode === -1;
    }
    return false;
  };

  for (const event of filteredEvidence) {
    const key = getBucketKey(event.timestamp, window);
    const targetIndex = bucketIndex.get(key);
    if (targetIndex === undefined) {
      continue;
    }
    if (isError(event)) {
      timeline[targetIndex].errors += 1;
    } else if (isControlled(event)) {
      timeline[targetIndex].blocked += 1;
    } else if (isAllowed(event)) {
      timeline[targetIndex].allowed += 1;
    }
  }

  const requests = filteredEvidence.length;
  const blocked = filteredEvidence.filter(isControlled).length;
  const allowed = filteredEvidence.filter(isAllowed).length;
  const errors = filteredEvidence.filter(isError).length;
  const uniqueTargets = new Set(filteredEvidence.map((event) => event.targetHostname)).size;

  return {
    key: window,
    label: WINDOW_LABELS[window],
    from: from.toISOString(),
    to: now.toISOString(),
    requests,
    blocked,
    allowed,
    errors,
    blockRate: requests > 0 ? Math.round((blocked / requests) * 100) : 0,
    runs: filteredRuns.length,
    findings: filteredFindings.length,
    newAssets: filteredTargets.length,
    uniqueTargets,
    timeline,
  };
}

/**
 * Section / module health classification.
 *
 *   healthy   = wired AND has had real activity in the lookback window
 *   ready     = wired but no activity yet (legitimately idle)
 *   attention = wired AND degraded (errors observed, data missing, etc.)
 *   scaffolded = backend feature is not implemented yet
 */
type SectionState = 'healthy' | 'ready' | 'attention' | 'scaffolded';

function buildStatus(
  name: string,
  route: string,
  status: SectionState,
  detail: string,
  metric: string,
) {
  return { name, route, status, detail, metric };
}

/** Convert ms-since-event into "now / 12m / 3h / 4d" style label. */
function formatAgeFromNow(date: Date | null | undefined, now: Date): string | null {
  if (!date) return null;
  const ms = now.getTime() - new Date(date).getTime();
  if (!Number.isFinite(ms) || ms < 0) return null;
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

/**
 * Decide a SectionState given a count and an optional last-activity time.
 * Centralises the "is this module actually alive?" rule so every section card
 * is graded consistently against the same evidence.
 */
function classifyByActivity(
  count: number,
  lastActivity: Date | null,
  now: Date,
  maxFreshHours = 168,
): SectionState {
  if (count <= 0) return 'ready';
  if (!lastActivity) return 'ready';
  const ageHours = (now.getTime() - new Date(lastActivity).getTime()) / 36e5;
  if (ageHours > maxFreshHours) return 'attention';
  return 'healthy';
}

export async function buildDashboardOverview(selectedWindow: DashboardWindow) {
  const now = new Date();
  const yearlyStart = getWindowStart('yearly', now);

  const targetRepo = AppDataSource.getRepository(Target);
  const campaignRepo = AppDataSource.getRepository(Campaign);
  const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
  const runRepo = AppDataSource.getRepository(AssessmentRun);
  const findingRepo = AppDataSource.getRepository(SecurityFinding);
  const discRepo = AppDataSource.getRepository(DiscoveredService);
  const templateRepo = AppDataSource.getRepository(ScenarioTemplate);
  const reportRepo = AppDataSource.getRepository(Report);
  const techIntelRunRepo = AppDataSource.getRepository(TechIntelRun);
  const wafRunRepo = AppDataSource.getRepository(WafValidationRun);
  const codeFindingRepo = AppDataSource.getRepository(CodeFinding);
  const dependencyRepo = AppDataSource.getRepository(DependencyVulnerability);
  const iocRepo = AppDataSource.getRepository(IocIndicator);
  const malwareRepo = AppDataSource.getRepository(MalwareArtifact);

  // Helper: latest "createdAt" timestamp for a repo (or null when empty).
  // Uses a query builder so that TypeORM's `findOne({ where: ... })`
  // requirement does not block us. The alias must match the entity
  // ("e") because we only need the column scalar.
  const latestCreatedAt = async (
    repo: { createQueryBuilder: (alias: string) => { select: (s: string, a: string) => { orderBy: (s: string, d: 'DESC') => { limit: (n: number) => { getRawOne: () => Promise<{ ts: Date | string | null } | undefined> } } } } },
    column = 'createdAt',
  ): Promise<Date | null> => {
    try {
      const row = await repo
        .createQueryBuilder('e')
        .select(`e.${column}`, 'ts')
        .orderBy(`e.${column}`, 'DESC')
        .limit(1)
        .getRawOne();
      const v = row?.ts;
      return v ? new Date(v as Date | string) : null;
    } catch {
      return null;
    }
  };

  const [
    approvedAssets,
    campaignsTotal,
    evidenceEvents,
    runsTotal,
    findingsTotal,
    exposureSignals,
    scenarioTemplates,
    reportsTotal,
    techIntelRunsTotal,
    wafRunsTotal,
    codeFindingsTotal,
    dependencyVulnsTotal,
    iocIndicatorsTotal,
    malwareArtifactsTotal,
    evidenceRows,
    runRows,
    findingRows,
    targetRows,
    queueCounts,
    redisPing,
    latestDiscovery,
    latestReport,
    latestTechIntelRun,
    latestWafRun,
    latestCodeFinding,
    latestDependency,
    latestIoc,
    latestMalware,
    latestEvidence,
    latestTarget,
    latestRun,
  ] = await Promise.all([
    targetRepo.count({ where: { approvalStatus: 'approved' } }),
    campaignRepo.count(),
    evidenceRepo.count(),
    runRepo.count(),
    findingRepo.count(),
    discRepo.count(),
    templateRepo.count(),
    reportRepo.count(),
    techIntelRunRepo.count(),
    wafRunRepo.count(),
    codeFindingRepo.count(),
    dependencyRepo.count(),
    iocRepo.count(),
    malwareRepo.count(),
    evidenceRepo.find({
      where: { timestamp: MoreThanOrEqual(yearlyStart) },
      order: { timestamp: 'DESC' },
      take: 5000,
    }),
    runRepo.find({
      where: { createdAt: MoreThanOrEqual(yearlyStart) },
      order: { createdAt: 'DESC' },
      take: 1000,
    }),
    findingRepo.find({
      where: { createdAt: MoreThanOrEqual(yearlyStart) },
      order: { createdAt: 'DESC' },
      take: 2000,
    }),
    targetRepo.find({
      where: { createdAt: MoreThanOrEqual(yearlyStart) },
      order: { createdAt: 'DESC' },
      take: 1000,
    }),
    scenarioQueue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed'),
    redisConnection.ping().then(() => 'PONG').catch(() => 'ERR'),
    latestCreatedAt(discRepo as never, 'lastSeen'),
    latestCreatedAt(reportRepo as never),
    latestCreatedAt(techIntelRunRepo as never),
    latestCreatedAt(wafRunRepo as never),
    latestCreatedAt(codeFindingRepo as never),
    latestCreatedAt(dependencyRepo as never),
    latestCreatedAt(iocRepo as never),
    latestCreatedAt(malwareRepo as never),
    latestCreatedAt(evidenceRepo as never, 'timestamp'),
    latestCreatedAt(targetRepo as never),
    latestCreatedAt(runRepo as never),
  ]);

  const windows = {
    daily: buildWindowSummary('daily', now, evidenceRows, runRows, findingRows, targetRows),
    weekly: buildWindowSummary('weekly', now, evidenceRows, runRows, findingRows, targetRows),
    monthly: buildWindowSummary('monthly', now, evidenceRows, runRows, findingRows, targetRows),
    yearly: buildWindowSummary('yearly', now, evidenceRows, runRows, findingRows, targetRows),
  } satisfies Record<DashboardWindow, WindowSummary>;

  const selected = windows[selectedWindow];
  const scenarioCounts = evidenceRows
    .filter((event) => event.timestamp >= new Date(selected.from))
    .reduce<Record<string, number>>((acc, event) => {
      acc[event.scenarioId] = (acc[event.scenarioId] ?? 0) + 1;
      return acc;
    }, {});

  // Evidence-grade activity counts in the SELECTED window. Used so each
  // section card communicates "here's what this module did in the period
  // you're looking at" rather than just a lifetime total.
  const evidenceInWindow = evidenceRows.filter(
    (event) => event.timestamp >= new Date(selected.from),
  ).length;
  const runsInWindow = runRows.filter(
    (run) => run.createdAt >= new Date(selected.from),
  ).length;

  const sectionStatus = [
    buildStatus(
      'Dashboard',
      '/',
      'healthy',
      'Executive overview endpoint is operational and emitting live aggregates.',
      'Live',
    ),
    buildStatus(
      'Targets',
      '/targets',
      classifyByActivity(approvedAssets, latestTarget, now),
      approvedAssets > 0
        ? `${approvedAssets} approved assets registered. Last asset created ${formatAgeFromNow(latestTarget, now) ?? 'unknown'}.`
        : 'No approved assets yet — register a target to enable execution.',
      `${approvedAssets} approved`,
    ),
    buildStatus(
      'Discovery',
      '/discovery',
      classifyByActivity(exposureSignals, latestDiscovery, now),
      exposureSignals > 0
        ? `${exposureSignals} discovered service signals captured. Last discovery ${formatAgeFromNow(latestDiscovery, now) ?? 'unknown'}.`
        : 'Discovery pipeline wired. Run a Discovery sweep on an approved asset to populate the inventory.',
      `${exposureSignals} services`,
    ),
    buildStatus(
      'Scenario Catalog',
      '/scenario-catalog',
      scenarioTemplates > 0 ? 'healthy' : 'ready',
      scenarioTemplates > 0
        ? `${scenarioTemplates} policy-bound templates loaded.`
        : 'Catalog is empty — seed a template to enable orchestrated execution.',
      `${scenarioTemplates} templates`,
    ),
    buildStatus(
      'Campaigns',
      '/campaigns',
      classifyByActivity(runsInWindow + campaignsTotal, latestRun, now),
      `${runsInWindow} campaign runs in ${selected.label.toLowerCase()} (${campaignsTotal} lifetime). Last run ${formatAgeFromNow(latestRun, now) ?? 'never'}.`,
      `${runsInWindow} / ${selected.label.toLowerCase()}`,
    ),
    buildStatus(
      'Runs',
      '/runs',
      classifyByActivity(runsTotal, latestRun, now),
      `${runsTotal} assessment runs persisted. Last run ${formatAgeFromNow(latestRun, now) ?? 'never'}.`,
      `${runsTotal} total`,
    ),
    buildStatus(
      'WAAP Validation',
      '/waap-validation',
      classifyByActivity(wafRunsTotal, latestWafRun, now),
      wafRunsTotal > 0
        ? `${wafRunsTotal} WAAP validation runs recorded. Last run ${formatAgeFromNow(latestWafRun, now) ?? 'unknown'}.`
        : 'WAAP validation engine wired. Launch a hardening-validation profile to populate observed verdicts.',
      `${wafRunsTotal} runs`,
    ),
    buildStatus(
      'Tech Intelligence',
      '/tech-intelligence',
      classifyByActivity(techIntelRunsTotal, latestTechIntelRun, now),
      techIntelRunsTotal > 0
        ? `${techIntelRunsTotal} fingerprint runs executed. Last run ${formatAgeFromNow(latestTechIntelRun, now) ?? 'unknown'}.`
        : 'Tech Intelligence wired. Run a fingerprint profile to populate technology + advisory correlations.',
      `${techIntelRunsTotal} runs`,
    ),
    buildStatus(
      'Application Assessment',
      '/scanner',
      classifyByActivity(findingsTotal, latestRun, now),
      `${findingsTotal} security findings persisted across ${SCANNER_MODULES.length} modules.`,
      `${findingsTotal} findings`,
    ),
    buildStatus(
      'Evidence & Logs',
      '/evidence',
      classifyByActivity(evidenceEvents, latestEvidence, now),
      `${evidenceInWindow} events in ${selected.label.toLowerCase()} (${evidenceEvents} total). Last event ${formatAgeFromNow(latestEvidence, now) ?? 'never'}.`,
      `${evidenceEvents} events`,
    ),
    buildStatus(
      'Code Security',
      '/code-security',
      classifyByActivity(codeFindingsTotal, latestCodeFinding, now),
      codeFindingsTotal > 0
        ? `${codeFindingsTotal} code-level findings indexed. Last update ${formatAgeFromNow(latestCodeFinding, now) ?? 'unknown'}.`
        : 'Code Security wired. SAST adapter integration is staged for a future phase.',
      `${codeFindingsTotal} findings`,
    ),
    buildStatus(
      'CVE Intelligence',
      '/dependency-risk',
      classifyByActivity(dependencyVulnsTotal, latestDependency, now, 8),
      dependencyVulnsTotal > 0
        ? `${dependencyVulnsTotal} CVEs indexed from public feeds. Last refresh ${formatAgeFromNow(latestDependency, now) ?? 'unknown'}.`
        : 'CVE feed wired (mycve.com, OSV.dev). Trigger a refresh to populate the index.',
      `${dependencyVulnsTotal} CVEs`,
    ),
    buildStatus(
      'IOC & Threat Context',
      '/ioc-threat',
      classifyByActivity(iocIndicatorsTotal, latestIoc, now, 8),
      iocIndicatorsTotal > 0
        ? `${iocIndicatorsTotal} indicators indexed (GH Advisories, OpenPhish, ThreatFox). Last refresh ${formatAgeFromNow(latestIoc, now) ?? 'unknown'}.`
        : 'IOC feed wired. Trigger a refresh to populate indicators.',
      `${iocIndicatorsTotal} indicators`,
    ),
    buildStatus(
      'Malware & File Risk',
      '/malware-file-risk',
      classifyByActivity(malwareArtifactsTotal, latestMalware, now),
      malwareArtifactsTotal > 0
        ? `${malwareArtifactsTotal} artifacts under analysis. Last upload ${formatAgeFromNow(latestMalware, now) ?? 'unknown'}.`
        : 'Malware analysis wired. Upload an artifact to begin a controlled review.',
      `${malwareArtifactsTotal} artifacts`,
    ),
    buildStatus(
      'Reports',
      '/reports',
      classifyByActivity(reportsTotal, latestReport, now),
      reportsTotal > 0
        ? `${reportsTotal} reports persisted (HTML + PDF). Last generated ${formatAgeFromNow(latestReport, now) ?? 'unknown'}.`
        : 'Reports pipeline wired. Reports are produced automatically by Scanner / Tech Intelligence runs.',
      `${reportsTotal} reports`,
    ),
    buildStatus(
      'Integrations',
      '/integrations',
      'ready',
      'External adapter shell is wired. SIEM / SOAR connector implementations are staged for a future phase.',
      'Wired',
    ),
    buildStatus(
      'Settings',
      '/settings',
      'ready',
      'Operator preferences, theme, and policy navigation are wired and available.',
      'Wired',
    ),
  ];

  const moduleStatus: Array<{
    name: string;
    domain: string;
    status: SectionState;
    detail: string;
    metric: string;
  }> = [
    {
      name: 'Redis Queue',
      domain: 'Platform',
      status: redisPing === 'PONG' ? 'healthy' : 'attention',
      detail:
        redisPing === 'PONG'
          ? 'Redis connectivity and queue transport responded normally.'
          : 'Redis ping failed — worker dispatch and refresh jobs may be degraded.',
      metric: `${queueCounts.waiting ?? 0} waiting / ${queueCounts.active ?? 0} active`,
    },
    {
      name: 'Scenario Worker',
      domain: 'Platform',
      status: (queueCounts.failed ?? 0) > 0 ? 'attention' : 'healthy',
      detail: `${WAAP_SCENARIOS.length} bounded WAAP scenarios are registered for worker execution.`,
      metric: `${queueCounts.failed ?? 0} failed jobs · ${queueCounts.completed ?? 0} completed`,
    },
    {
      name: 'Asset Registry',
      domain: 'Platform',
      status: approvedAssets > 0 ? 'healthy' : 'ready',
      detail: 'Approved asset registry is used as the executable trust boundary.',
      metric: `${approvedAssets} approved assets`,
    },
    {
      name: 'Evidence Telemetry',
      domain: 'Platform',
      status: classifyByActivity(evidenceEvents, latestEvidence, now),
      detail: `Campaign and validation outputs persist into operator-visible evidence logs. Last event ${formatAgeFromNow(latestEvidence, now) ?? 'never'}.`,
      metric: `${evidenceEvents} events`,
    },
    {
      name: 'Discovery Inventory',
      domain: 'Platform',
      status: classifyByActivity(exposureSignals, latestDiscovery, now),
      detail: `Discovery signals are normalized into the approved asset inventory. Last discovery ${formatAgeFromNow(latestDiscovery, now) ?? 'never'}.`,
      metric: `${exposureSignals} services`,
    },
    {
      name: 'Tech Intelligence Engine',
      domain: 'Platform',
      status: classifyByActivity(techIntelRunsTotal, latestTechIntelRun, now),
      detail: `Profile-driven fingerprint engine. Last run ${formatAgeFromNow(latestTechIntelRun, now) ?? 'never'}.`,
      metric: `${techIntelRunsTotal} runs`,
    },
    {
      name: 'WAAP Validation Engine',
      domain: 'Platform',
      status: classifyByActivity(wafRunsTotal, latestWafRun, now),
      detail: `Hardening-validation engine for approved targets. Last run ${formatAgeFromNow(latestWafRun, now) ?? 'never'}.`,
      metric: `${wafRunsTotal} runs`,
    },
    {
      name: 'CVE Feed Ingestor',
      domain: 'Threat Intelligence',
      status: classifyByActivity(dependencyVulnsTotal, latestDependency, now, 8),
      detail: `Public CVE feed ingestion (mycve.com, OSV.dev). Last refresh ${formatAgeFromNow(latestDependency, now) ?? 'never'}.`,
      metric: `${dependencyVulnsTotal} CVEs`,
    },
    {
      name: 'IOC Feed Ingestor',
      domain: 'Threat Intelligence',
      status: classifyByActivity(iocIndicatorsTotal, latestIoc, now, 8),
      detail: `Indicator ingestion (GH Advisories, OpenPhish, ThreatFox). Last refresh ${formatAgeFromNow(latestIoc, now) ?? 'never'}.`,
      metric: `${iocIndicatorsTotal} indicators`,
    },
    {
      name: 'Reports Pipeline',
      domain: 'Platform',
      status: classifyByActivity(reportsTotal, latestReport, now),
      detail: `HTML + PDF report generation pipeline. Last report ${formatAgeFromNow(latestReport, now) ?? 'never'}.`,
      metric: `${reportsTotal} reports`,
    },
    ...SCANNER_MODULES.map((module) => ({
      name: module.name,
      domain: module.domain,
      status: classifyByActivity(findingsTotal, latestRun, now) as SectionState,
      detail:
        'Module is registered in the scanner orchestration pipeline and contributes evidence-driven findings.',
      metric: `${findingsTotal} findings`,
    })),
    ...WAAP_SCENARIOS.map((scenario) => ({
      name: scenario.name,
      domain: 'Campaign Scenario',
      status: ((scenarioCounts[scenario.id] ?? 0) > 0 ? 'healthy' : 'ready') as SectionState,
      detail: `${scenario.category} scenario is available for bounded validation traffic.`,
      metric: `${scenarioCounts[scenario.id] ?? 0} hits in ${selected.key}`,
    })),
  ];

  return {
    generatedAt: now.toISOString(),
    selectedWindow,
    windows,
    platformSummary: {
      approvedAssets,
      findingsTotal,
      campaignsTotal,
      evidenceEvents,
      runsTotal,
      exposureSignals,
      scenarioTemplates,
      waapScenarioCount: WAAP_SCENARIOS.length,
      assessmentModuleCount: SCANNER_MODULES.length,
      queueCounts,
    },
    traffic: selected,
    sectionStatus,
    moduleStatus,
  };
}
