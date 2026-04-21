import { createHash } from 'crypto';
import { In } from 'typeorm';
import { AppDataSource } from '../db/connection';
import { AssessmentRun } from '../db/models/AssessmentRun';
import { EvidenceLog } from '../db/models/Evidence';
import { getCampaignScenarioById, type CampaignScenarioDefinition } from '../engine/scenarios';
import type { VerdictEvaluation, Verdict } from '../engine/verdict';
import type { ExpectationEvaluation, ExpectationOutcome } from '../engine/expectation';
import { findApprovedAssetByNormalizedKey } from './assetRegistry';

export const VERDICT_KEYS: Verdict[] = [
  'blocked',
  'challenged',
  'edge_mitigated',
  'origin_rejected',
  'allowed',
  'network_error',
  'ambiguous',
];

export const EXPECTATION_KEYS: ExpectationOutcome[] = [
  'matched',
  'partially_matched',
  'mismatched',
  'ambiguous',
];

export type CampaignActivityEvent = {
  id: string;
  timestamp: Date;
  executionStatus: string;
  responseStatusCode: number;
  latencyMs: number;
  attemptedUrl: string | null;
  requestLabel: string | null;
  deliveryChannel: string | null;
  method: string;
  path: string;
  requestHeaders: Record<string, string> | null;
  requestBodyPreview: string | null;
  payloadHash: string | null;
  responseHeaders: Record<string, string> | null;
  responseBodyPreview: string | null;
  errorMessage: string | null;
  workerJobId: string | null;
  attemptNumber: number;
  verdict: string;
  verdictConfidence: number;
  verdictReason: string | null;
  verdictSignals: Array<{ source: string; name: string; detail?: string }> | null;
  expectationOutcome: string;
  expectationDetails: Record<string, unknown> | null;
};

export type CampaignActivityRun = {
  runId: string;
  externalRunId: string;
  label: string;
  status: string;
  targetHostname: string;
  scenarioId: string;
  scenarioName: string;
  scenarioCategory: string;
  requestedJobs: number;
  completedJobs: number;
  blockedJobs: number;
  allowedJobs: number;
  errorJobs: number;
  verdictCounts: Record<Verdict, number>;
  expectationCounts: Record<ExpectationOutcome, number>;
  queuedJobIds: string[];
  startedAt: Date | null;
  completedAt: Date | null;
  updatedAt: Date;
  events: CampaignActivityEvent[];
};

function emptyVerdictCounts(): Record<Verdict, number> {
  return VERDICT_KEYS.reduce(
    (acc, key) => {
      acc[key] = 0;
      return acc;
    },
    {} as Record<Verdict, number>,
  );
}

function emptyExpectationCounts(): Record<ExpectationOutcome, number> {
  return EXPECTATION_KEYS.reduce(
    (acc, key) => {
      acc[key] = 0;
      return acc;
    },
    {} as Record<ExpectationOutcome, number>,
  );
}

function aggregateVerdictCounts(events: EvidenceLog[]): Record<Verdict, number> {
  const counts = emptyVerdictCounts();
  for (const event of events) {
    const key = (event.verdict ?? 'ambiguous') as Verdict;
    if (key in counts) {
      counts[key] += 1;
    } else {
      counts.ambiguous += 1;
    }
  }
  return counts;
}

function aggregateExpectationCounts(events: EvidenceLog[]): Record<ExpectationOutcome, number> {
  const counts = emptyExpectationCounts();
  for (const event of events) {
    const key = (event.expectationOutcome ?? 'ambiguous') as ExpectationOutcome;
    if (key in counts) {
      counts[key] += 1;
    } else {
      counts.ambiguous += 1;
    }
  }
  return counts;
}

const PREVIEW_LIMIT = 1200;

function truncateText(value: string, maxLength = PREVIEW_LIMIT): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength)}…`;
}

export function serializePreview(value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === 'string') {
    return truncateText(value);
  }
  try {
    return truncateText(JSON.stringify(value, null, 2));
  } catch {
    return truncateText(String(value));
  }
}

export function computePayloadHash(value: unknown): string | null {
  const preview = serializePreview(value);
  if (!preview) {
    return null;
  }
  return createHash('sha256').update(preview).digest('hex');
}

function normalizeStringMap(input: Record<string, unknown> | undefined): Record<string, string> | null {
  if (!input) {
    return null;
  }
  const normalizedEntries = Object.entries(input)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => [key, String(value)] as const);

  return normalizedEntries.length > 0 ? Object.fromEntries(normalizedEntries) : null;
}

function getScenarioDefinition(scenarioId: string): CampaignScenarioDefinition | undefined {
  return getCampaignScenarioById(scenarioId);
}

function parseNumericSummary(summary: Record<string, unknown> | null, key: string, fallback = 0): number {
  const value = summary?.[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function parseStringSummary(summary: Record<string, unknown> | null, key: string, fallback = ''): string {
  const value = summary?.[key];
  return typeof value === 'string' ? value : fallback;
}

function parseStringArraySummary(summary: Record<string, unknown> | null, key: string): string[] {
  const value = summary?.[key];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

export async function createCampaignRunRecord(input: {
  externalRunId: string;
  targetHostname: string;
  scenarioId: string;
  requestedJobs: number;
  queuedJobIds: string[];
}): Promise<AssessmentRun> {
  const runRepo = AppDataSource.getRepository(AssessmentRun);
  const asset = await findApprovedAssetByNormalizedKey(input.targetHostname);
  const scenario = getScenarioDefinition(input.scenarioId);

  const summary = {
    targetHostname: input.targetHostname,
    scenarioId: input.scenarioId,
    scenarioName: scenario?.name ?? input.scenarioId,
    scenarioCategory: scenario?.category ?? 'Uncategorized',
    scenarioSeverity: scenario?.severity ?? 'medium',
    scenarioAttackSurface: scenario?.attackSurface ?? 'web',
    requestedJobs: input.requestedJobs,
    requestCount: scenario?.requests.length ?? 0,
    completedJobs: 0,
    blockedJobs: 0,
    allowedJobs: 0,
    errorJobs: 0,
    queuedJobIds: input.queuedJobIds,
  };

  const run = runRepo.create({
    externalRunId: input.externalRunId,
    campaignId: null,
    assetId: asset?.id ?? null,
    label: `${summary.scenarioName} · ${input.targetHostname}`,
    status: 'queued',
    summary,
    startedAt: new Date(),
    completedAt: null,
  });

  return runRepo.save(run);
}

export async function refreshCampaignRunSummary(externalRunId: string): Promise<void> {
  const runRepo = AppDataSource.getRepository(AssessmentRun);
  const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
  const run = await runRepo.findOne({ where: { externalRunId } });

  if (!run) {
    return;
  }

  const evidence = await evidenceRepo.find({
    where: { campaignRunId: externalRunId },
    order: { timestamp: 'ASC' },
  });

  const summary = (run.summary ?? {}) as Record<string, unknown>;
  const requestedJobs = parseNumericSummary(summary, 'requestedJobs', evidence.length);
  const completedJobs = evidence.length;
  const verdictCounts = aggregateVerdictCounts(evidence);
  const expectationCounts = aggregateExpectationCounts(evidence);

  // Verdict-derived aggregations (no longer status-only). "blockedJobs" now
  // means controlled-by-edge-or-origin (not simply HTTP >= 400). Allowed
  // strictly means clean pass-through.
  const blockedJobs =
    verdictCounts.blocked +
    verdictCounts.challenged +
    verdictCounts.edge_mitigated +
    verdictCounts.origin_rejected;
  const allowedJobs = verdictCounts.allowed;
  const errorJobs = verdictCounts.network_error;
  const latestEvent = evidence[evidence.length - 1];

  run.status =
    completedJobs === 0
      ? 'queued'
      : completedJobs < requestedJobs
        ? 'running'
        : errorJobs > 0
          ? 'partial'
          : 'completed';

  run.summary = {
    ...summary,
    completedJobs,
    blockedJobs,
    allowedJobs,
    errorJobs,
    verdictCounts,
    expectationCounts,
    latestStatusCode: latestEvent?.responseStatusCode ?? null,
    latestVerdict: latestEvent?.verdict ?? null,
    latestExpectationOutcome: latestEvent?.expectationOutcome ?? null,
    latestEventAt: latestEvent?.timestamp?.toISOString?.() ?? null,
    observedStatuses: [...new Set(evidence.map((event) => event.responseStatusCode))],
  };

  run.completedAt = completedJobs >= requestedJobs && latestEvent ? latestEvent.timestamp : null;
  await runRepo.save(run);
}

export async function listRecentCampaignActivity(limit = 8): Promise<CampaignActivityRun[]> {
  const runRepo = AppDataSource.getRepository(AssessmentRun);
  const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
  const runs = await runRepo.find({
    where: {
      externalRunId: In(
        (
          await runRepo
            .createQueryBuilder('run')
            .select('run.externalRunId', 'externalRunId')
            .where('run.externalRunId IS NOT NULL')
            .orderBy('run.createdAt', 'DESC')
            .take(limit)
            .getRawMany()
        )
          .map((row) => row.externalRunId as string)
          .filter(Boolean),
      ),
    },
    order: { createdAt: 'DESC' },
  });

  if (runs.length === 0) {
    return [];
  }

  const externalRunIds = runs
    .map((run) => run.externalRunId)
    .filter((value): value is string => typeof value === 'string' && value.length > 0);

  const evidence = await evidenceRepo.find({
    where: { campaignRunId: In(externalRunIds) },
    order: { timestamp: 'DESC' },
  });

  const eventsByRunId = new Map<string, CampaignActivityEvent[]>();
  const evidenceByRunId = new Map<string, EvidenceLog[]>();
  for (const event of evidence) {
    const list = eventsByRunId.get(event.campaignRunId) ?? [];
    list.push({
      id: event.id,
      timestamp: event.timestamp,
      executionStatus: event.executionStatus,
      responseStatusCode: event.responseStatusCode,
      latencyMs: event.latencyMs,
      attemptedUrl: event.attemptedUrl,
      requestLabel: event.requestLabel,
      deliveryChannel: event.deliveryChannel,
      method: event.method,
      path: event.path,
      requestHeaders: event.requestHeaders,
      requestBodyPreview: event.requestBodyPreview,
      payloadHash: event.payloadHash,
      responseHeaders: event.responseHeaders,
      responseBodyPreview: event.responseBodyPreview,
      errorMessage: event.errorMessage,
      workerJobId: event.workerJobId,
      attemptNumber: event.attemptNumber,
      verdict: event.verdict ?? 'ambiguous',
      verdictConfidence: event.verdictConfidence ?? 0,
      verdictReason: event.verdictReason,
      verdictSignals: event.verdictSignals,
      expectationOutcome: event.expectationOutcome ?? 'ambiguous',
      expectationDetails: event.expectationDetails,
    });
    eventsByRunId.set(event.campaignRunId, list);

    const evidenceList = evidenceByRunId.get(event.campaignRunId) ?? [];
    evidenceList.push(event);
    evidenceByRunId.set(event.campaignRunId, evidenceList);
  }

  return runs.map((run) => {
    const summary = (run.summary ?? {}) as Record<string, unknown>;
    const externalRunId = run.externalRunId ?? run.id;
    const runEvidence = evidenceByRunId.get(externalRunId) ?? [];
    const verdictCounts =
      runEvidence.length > 0
        ? aggregateVerdictCounts(runEvidence)
        : (summary['verdictCounts'] as Record<Verdict, number> | undefined) ?? emptyVerdictCounts();
    const expectationCounts =
      runEvidence.length > 0
        ? aggregateExpectationCounts(runEvidence)
        : (summary['expectationCounts'] as Record<ExpectationOutcome, number> | undefined) ??
          emptyExpectationCounts();

    return {
      runId: run.id,
      externalRunId,
      label: run.label,
      status: run.status,
      targetHostname: parseStringSummary(summary, 'targetHostname', run.asset?.hostname ?? 'Unknown target'),
      scenarioId: parseStringSummary(summary, 'scenarioId', 'unknown'),
      scenarioName: parseStringSummary(summary, 'scenarioName', run.label),
      scenarioCategory: parseStringSummary(summary, 'scenarioCategory', 'Uncategorized'),
      requestedJobs: parseNumericSummary(summary, 'requestedJobs', 0),
      completedJobs: parseNumericSummary(summary, 'completedJobs', 0),
      blockedJobs: parseNumericSummary(summary, 'blockedJobs', 0),
      allowedJobs: parseNumericSummary(summary, 'allowedJobs', 0),
      errorJobs: parseNumericSummary(summary, 'errorJobs', 0),
      verdictCounts,
      expectationCounts,
      queuedJobIds: parseStringArraySummary(summary, 'queuedJobIds'),
      startedAt: run.startedAt,
      completedAt: run.completedAt,
      updatedAt: run.updatedAt,
      events: eventsByRunId.get(externalRunId) ?? [],
    };
  });
}

export function buildExecutionLogEntry(input: {
  campaignRunId: string;
  scenarioId: string;
  targetHostname: string;
  method: string;
  path: string;
  requestLabel?: string | null;
  deliveryChannel?: string | null;
  attemptNumber: number;
  workerJobId: string | null;
  attemptedUrl: string;
  requestHeaders?: Record<string, unknown>;
  requestBody?: unknown;
  executionStatus: string;
  responseStatusCode: number;
  latencyMs: number;
  responseHeaders?: Record<string, unknown>;
  responseBodyPreview?: string | null;
  errorMessage?: string | null;
  verdict?: VerdictEvaluation | null;
  expectation?: ExpectationEvaluation | null;
}): EvidenceLog {
  const evidenceRepo = AppDataSource.getRepository(EvidenceLog);

  return evidenceRepo.create({
    campaignRunId: input.campaignRunId,
    scenarioId: input.scenarioId,
    targetHostname: input.targetHostname,
    method: input.method,
    path: input.path,
    requestLabel: input.requestLabel ?? null,
    deliveryChannel: input.deliveryChannel ?? null,
    attemptNumber: input.attemptNumber,
    workerJobId: input.workerJobId,
    attemptedUrl: input.attemptedUrl,
    requestHeaders: normalizeStringMap(input.requestHeaders),
    requestBodyPreview: serializePreview(input.requestBody),
    payloadHash: computePayloadHash(input.requestBody),
    executionStatus: input.executionStatus,
    responseStatusCode: input.responseStatusCode,
    latencyMs: input.latencyMs,
    responseHeaders: normalizeStringMap(input.responseHeaders),
    responseBodyPreview: input.responseBodyPreview ? truncateText(input.responseBodyPreview) : null,
    errorMessage: input.errorMessage ?? null,
    verdict: input.verdict?.verdict ?? 'ambiguous',
    verdictConfidence: input.verdict?.confidence ?? 0,
    verdictSignals: input.verdict?.signals ?? null,
    verdictReason: input.verdict?.reason ?? null,
    expectationOutcome: input.expectation?.outcome ?? 'ambiguous',
    expectationDetails: input.expectation
      ? {
          matchedVerdict: input.expectation.matchedVerdict,
          matchedSignals: input.expectation.matchedSignals,
          matchedStatus: input.expectation.matchedStatus,
          reasons: input.expectation.reasons,
          expected: input.expectation.expected,
        }
      : null,
  });
}
