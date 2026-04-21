/**
 * UASF Tech Intelligence — Orchestration Service
 *
 * Public facade for the Tech Intelligence module.  Responsible for:
 *
 *   - enforcing approved-target gating
 *   - resolving the operator-supplied target key to a probable hostname
 *   - executing the fingerprint engine + correlator (transactionally)
 *   - executing the WAF hardening validator + persisting events
 *   - paginated listing + detailed retrieval for the dashboard
 *
 * The service does not depend on Fastify; the API layer wraps it.
 */

import { AppDataSource } from '../../db/connection';
import { TechIntelRun, type TechIntelRunStatus } from '../../db/models/TechIntelRun';
import { DetectedTechnology } from '../../db/models/DetectedTechnology';
import { VulnerabilityCorrelation } from '../../db/models/VulnerabilityCorrelation';
import { FingerprintObservation } from '../../db/models/FingerprintObservation';
import { WafValidationRun } from '../../db/models/WafValidationRun';
import { WafValidationEvent } from '../../db/models/WafValidationEvent';
import { resolveProtectedHostname } from '../../db/targetResolution';
import { assertExecutableApprovedAsset } from '../../policy/executableAsset';
import { runFingerprintEngine } from './fingerprintEngine';
import type { FusedCandidate } from './signalFusion';
import { correlateVulnerabilities } from './vulnerabilityCorrelator';
import { refreshOsvAdvisoriesForCandidates } from './osvAdvisoryLookup';
import { runHardeningValidation } from './hardeningValidator';
import { findProfileById, TECH_INTEL_PROFILES } from './profiles';
import { findHardeningProfile, HARDENING_PROFILES } from './hardeningProfiles';
import { DETECTION_METHODS_CATALOG } from './detectionMethodsCatalog';

export interface RunFingerprintInput {
  targetKey: string;
  profileId: string;
  operatorId?: string | null;
}

export interface RunFingerprintOutput {
  runId: string;
  status: TechIntelRunStatus;
  resolvedHostname: string;
  technologyCount: number;
  correlationCount: number;
  highOrCriticalCount: number;
  durationMs: number;
  errors: string[];
}

export interface RunHardeningInput {
  targetKey: string;
  profileId: string;
  operatorId?: string | null;
}

export interface RunHardeningOutput {
  runId: string;
  status: TechIntelRunStatus;
  resolvedHostname: string;
  totalEvents: number;
  matchedEvents: number;
  partiallyMatchedEvents: number;
  mismatchedEvents: number;
  ambiguousEvents: number;
  durationMs: number;
}

// ---------------------------------------------------------------
// Overview aggregation
// ---------------------------------------------------------------

export interface TechIntelOverviewStats {
  fingerprintRunCount: number;
  /** Distinct (productKey + version) pairs seen across all fingerprint runs. */
  distinctTechnologyCount: number;
  /** Distinct productKeys (regardless of version) seen across all runs. */
  distinctProductCount: number;
  totalCorrelationCount: number;
  /** Distinct advisory ids that ever correlated. */
  distinctAdvisoryCount: number;
  /** Distinct advisory ids whose severity is High or Critical. */
  highOrCriticalAdvisoryCount: number;
  wafRunCount: number;
  wafTotalEvents: number;
  wafMatchedEvents: number;
  wafPartiallyMatchedEvents: number;
  wafMismatchedEvents: number;
  wafAmbiguousEvents: number;
  /** Most recent fingerprint run timestamp (ISO) or null. */
  lastFingerprintRunAt: string | null;
  /** Most recent WAF validation run timestamp (ISO) or null. */
  lastWafRunAt: string | null;
}

/**
 * Computes overview metrics directly from the underlying tables instead of
 * summing per-run aggregate columns.  Sum-of-per-run-counts overstates
 * "Detected technologies" when the same product appears in multiple runs
 * and creates the misleading appearance that the metric simply mirrors
 * the run count.  We deduplicate by (productKey, version) for technologies
 * and by advisoryId for correlations.
 */
export async function getTechIntelOverviewStats(): Promise<TechIntelOverviewStats> {
  const runRepo = AppDataSource.getRepository(TechIntelRun);
  const techRepo = AppDataSource.getRepository(DetectedTechnology);
  const corrRepo = AppDataSource.getRepository(VulnerabilityCorrelation);
  const wafRepo = AppDataSource.getRepository(WafValidationRun);

  const [
    fingerprintRunCount,
    distinctTechnologyRow,
    distinctProductRow,
    totalCorrelationCount,
    distinctAdvisoryRow,
    highCriticalRow,
    wafRunCount,
    wafAggRow,
    lastFingerprintRun,
    lastWafRun,
  ] = await Promise.all([
    runRepo.count(),
    techRepo
      .createQueryBuilder('t')
      .select('COUNT(DISTINCT (t."productKey" || COALESCE(t.version, \'\')))', 'n')
      .getRawOne<{ n: string }>(),
    techRepo
      .createQueryBuilder('t')
      .select('COUNT(DISTINCT t."productKey")', 'n')
      .getRawOne<{ n: string }>(),
    corrRepo.count(),
    corrRepo
      .createQueryBuilder('c')
      .select('COUNT(DISTINCT c."advisoryId")', 'n')
      .getRawOne<{ n: string }>(),
    corrRepo
      .createQueryBuilder('c')
      .select('COUNT(DISTINCT c."advisoryId")', 'n')
      .where('LOWER(c."severityLabel") IN (:...labels)', { labels: ['high', 'critical'] })
      .getRawOne<{ n: string }>(),
    wafRepo.count(),
    wafRepo
      .createQueryBuilder('w')
      .select('COALESCE(SUM(w."totalEvents"), 0)', 'total')
      .addSelect('COALESCE(SUM(w."matchedEvents"), 0)', 'matched')
      .addSelect('COALESCE(SUM(w."partiallyMatchedEvents"), 0)', 'partial')
      .addSelect('COALESCE(SUM(w."mismatchedEvents"), 0)', 'mismatched')
      .addSelect('COALESCE(SUM(w."ambiguousEvents"), 0)', 'ambiguous')
      .getRawOne<{ total: string; matched: string; partial: string; mismatched: string; ambiguous: string }>(),
    runRepo.findOne({ where: {}, order: { createdAt: 'DESC' } }),
    wafRepo.findOne({ where: {}, order: { createdAt: 'DESC' } }),
  ]);

  const num = (s: string | undefined | null): number => {
    const n = Number(s);
    return Number.isFinite(n) ? n : 0;
  };

  return {
    fingerprintRunCount,
    distinctTechnologyCount: num(distinctTechnologyRow?.n),
    distinctProductCount: num(distinctProductRow?.n),
    totalCorrelationCount,
    distinctAdvisoryCount: num(distinctAdvisoryRow?.n),
    highOrCriticalAdvisoryCount: num(highCriticalRow?.n),
    wafRunCount,
    wafTotalEvents: num(wafAggRow?.total),
    wafMatchedEvents: num(wafAggRow?.matched),
    wafPartiallyMatchedEvents: num(wafAggRow?.partial),
    wafMismatchedEvents: num(wafAggRow?.mismatched),
    wafAmbiguousEvents: num(wafAggRow?.ambiguous),
    lastFingerprintRunAt: lastFingerprintRun ? lastFingerprintRun.createdAt.toISOString() : null,
    lastWafRunAt: lastWafRun ? lastWafRun.createdAt.toISOString() : null,
  };
}

// ---------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------

export function listProfiles() {
  return {
    fingerprint: TECH_INTEL_PROFILES.map((profile) => ({
      id: profile.id,
      name: profile.name,
      description: profile.description,
      probes: profile.probes,
      enableNmap: profile.enableNmap,
      adapters: profile.adapters,
    })),
    hardening: HARDENING_PROFILES.map((profile) => ({
      id: profile.id,
      name: profile.name,
      description: profile.description,
      probeCount: profile.probes.length,
      categories: Array.from(new Set(profile.probes.map((p) => p.category))),
    })),
  };
}

// ---------------------------------------------------------------
// Detection methods catalog
// ---------------------------------------------------------------

export function listDetectionMethodsCatalog() {
  return { methods: DETECTION_METHODS_CATALOG };
}

// ---------------------------------------------------------------
// Fingerprint runs
// ---------------------------------------------------------------

export async function runTechIntelFingerprint(input: RunFingerprintInput): Promise<RunFingerprintOutput> {
  const profile = findProfileById(input.profileId);
  if (!profile) throw new Error(`Unknown fingerprint profile: ${input.profileId}`);

  await assertExecutableApprovedAsset(input.targetKey);
  const resolvedHostname = (await resolveProtectedHostname(input.targetKey)).trim();

  const runRepo = AppDataSource.getRepository(TechIntelRun);
  const techRepo = AppDataSource.getRepository(DetectedTechnology);
  const corrRepo = AppDataSource.getRepository(VulnerabilityCorrelation);
  const obsRepo = AppDataSource.getRepository(FingerprintObservation);

  const run = runRepo.create({
    targetKey: input.targetKey,
    resolvedHostname,
    profileId: profile.id,
    status: 'running',
    operatorId: input.operatorId ?? null,
  });
  await runRepo.save(run);

  const startedAt = Date.now();
  let status: TechIntelRunStatus = 'completed';
  let errorMessage: string | null = null;
  let fusedCandidates: FusedCandidate[] = [];
  let engineResult: Awaited<ReturnType<typeof runFingerprintEngine>> | null = null;
  let executionTrace: TechIntelRun['executionTrace'] = {
    declaredProbes: [...profile.probes],
    executedProbes: [],
    httpProbed: false,
    tlsProbed: false,
    nmapProbed: false,
    probeErrors: [],
  };

  try {
    engineResult = await runFingerprintEngine(resolvedHostname, profile);
    fusedCandidates = engineResult.fusedCandidates;
    executionTrace = {
      declaredProbes: [...profile.probes],
      executedProbes: engineResult.rawSummary.executedProbes,
      httpProbed: engineResult.rawSummary.httpProbed,
      tlsProbed: engineResult.rawSummary.tlsProbed,
      nmapProbed: engineResult.rawSummary.nmapProbed,
      probeErrors: engineResult.rawSummary.errors,
    };
    if (engineResult.rawSummary.errors.length > 0 && fusedCandidates.length === 0) {
      status = 'failed';
      errorMessage = engineResult.rawSummary.errors.join(' | ');
    } else if (engineResult.rawSummary.errors.length > 0) {
      status = 'partial';
      errorMessage = engineResult.rawSummary.errors.join(' | ');
    }
  } catch (err) {
    status = 'failed';
    errorMessage = (err as Error).message;
    executionTrace = {
      declaredProbes: [...profile.probes],
      executedProbes: [],
      httpProbed: false,
      tlsProbed: false,
      nmapProbed: false,
      probeErrors: [errorMessage ?? 'engine failed'],
    };
  }

  // -------------------------------------------------------------------
  // Persist observations first (ledger of raw signals).  Each observation
  // gets its own row; ids are echoed back onto the owning DetectedTechnology
  // for fast evidence-trace rendering in the UI.
  // -------------------------------------------------------------------
  const allObservations = engineResult?.observations ?? [];
  const observationRows = allObservations.map((obs) =>
    obsRepo.create({
      runId: run.id,
      family: obs.family,
      methodId: obs.methodId,
      methodLabel: obs.methodLabel,
      signalKey: obs.signalKey,
      signalValue: obs.signalValue,
      evidenceSnippet: obs.evidenceSnippet,
      productKey: obs.productKey,
      versionLiteral: obs.versionLiteral,
      weight: obs.weight,
      vendorMatch: obs.vendorMatch,
      metadata: obs.metadata ?? null,
    }),
  );
  const persistedObservations = await obsRepo.save(observationRows);

  // Index observations by productKey so each DetectedTechnology row can
  // back-reference the ids of the signals that contributed to it.
  const obsIdsByProduct = new Map<string, string[]>();
  for (let i = 0; i < allObservations.length; i += 1) {
    const pk = allObservations[i].productKey;
    if (!pk) continue;
    const id = persistedObservations[i]?.id;
    if (!id) continue;
    const list = obsIdsByProduct.get(pk) ?? [];
    list.push(id);
    obsIdsByProduct.set(pk, list);
  }

  // Persist detected technologies first; we need their ids for correlations.
  const persistedTechs = await techRepo.save(
    fusedCandidates.map((cand) =>
      techRepo.create({
        runId: run.id,
        productKey: cand.productKey,
        productName: cand.productName,
        vendor: cand.vendor,
        category: cand.category,
        version: cand.version,
        versionFamily: cand.versionFamily,
        versionCertainty: cand.versionCertainty,
        confidence: cand.confidence,
        confidenceScore: cand.confidenceScore,
        signalFamilies: cand.signalFamilies,
        detectionMethodIds: cand.detectionMethodIds,
        observationIds: obsIdsByProduct.get(cand.productKey) ?? null,
        evidence: cand.contributingObservations.map((o) => ({
          source: legacySourceFromFamily(o.family),
          detail: o.evidenceSnippet,
          matchedRule: o.methodId,
        })),
      }),
    ),
  );

  // Re-package fused candidates into the legacy shape the correlator
  // still expects.  The evidence array is rebuilt from the observation
  // ledger so advisory-correlation logic has the same view.
  const correlatorInput = fusedCandidates.map((cand) => ({
    productKey: cand.productKey,
    productName: cand.productName,
    vendor: cand.vendor,
    category: cand.category,
    version: cand.version,
    versionFamily: cand.versionFamily,
    versionCertainty: cand.versionCertainty,
    confidence: cand.confidence,
    evidence: cand.contributingObservations.map((o) => ({
      source: legacySourceFromFamily(o.family) as
        | 'header'
        | 'cookie'
        | 'body_marker'
        | 'tls'
        | 'banner'
        | 'meta_tag'
        | 'asset'
        | 'script'
        | 'rule',
      detail: o.evidenceSnippet,
      matchedRule: o.methodId,
    })),
  }));

  // Refresh OSV advisories for the detected technologies first, so the
  // correlator has structured, version-range-aware proof to work with.
  // OSV failures are non-fatal — the correlator simply falls back to
  // whatever the periodic mycve.com refresh has already cached.
  await refreshOsvAdvisoriesForCandidates(correlatorInput).catch(() => undefined);

  // Correlate against the (now freshly updated) advisory cache.
  const correlations = await correlateVulnerabilities(correlatorInput);
  const techByProduct = new Map(persistedTechs.map((t) => [t.productKey, t.id]));
  const correlationRows = correlations
    .map((c) => {
      const detectedTechnologyId = techByProduct.get(c.detectedProductKey);
      if (!detectedTechnologyId) return null;
      return corrRepo.create({
        runId: run.id,
        detectedTechnologyId,
        productKey: c.detectedProductKey,
        detectedVersion: c.detectedVersion,
        advisoryId: c.advisoryId,
        cveId: c.cveId,
        severityLabel: c.severityLabel,
        severityScore: c.severityScore,
        summary: c.summary,
        affectedRanges: c.affectedRanges,
        fixedVersions: c.fixedVersions,
        source: c.source,
        sourceUrl: c.sourceUrl,
        strength: c.strength,
        certaintyLabel: c.certaintyLabel,
        matchType: c.matchType,
        triageState: c.triageState,
      });
    })
    .filter((row): row is VulnerabilityCorrelation => row !== null);
  await corrRepo.save(correlationRows);

  const highOrCriticalCount = correlationRows.filter((c) =>
    ['critical', 'high'].includes(c.severityLabel.toLowerCase()),
  ).length;

  run.status = status;
  run.errorMessage = errorMessage;
  run.technologyCount = persistedTechs.length;
  run.correlationCount = correlationRows.length;
  run.highOrCriticalCount = highOrCriticalCount;
  run.durationMs = Date.now() - startedAt;
  run.executionTrace = executionTrace;
  await runRepo.save(run);

  return {
    runId: run.id,
    status: run.status,
    resolvedHostname,
    technologyCount: run.technologyCount,
    correlationCount: run.correlationCount,
    highOrCriticalCount: run.highOrCriticalCount,
    durationMs: run.durationMs,
    errors: errorMessage ? errorMessage.split(' | ') : [],
  };
}

// ---------------------------------------------------------------
// Hardening runs
// ---------------------------------------------------------------

export async function runTechIntelHardening(input: RunHardeningInput): Promise<RunHardeningOutput> {
  const profile = findHardeningProfile(input.profileId);
  if (!profile) throw new Error(`Unknown hardening profile: ${input.profileId}`);

  await assertExecutableApprovedAsset(input.targetKey);
  const resolvedHostname = (await resolveProtectedHostname(input.targetKey)).trim();

  const runRepo = AppDataSource.getRepository(WafValidationRun);
  const evtRepo = AppDataSource.getRepository(WafValidationEvent);

  const run = runRepo.create({
    targetKey: input.targetKey,
    resolvedHostname,
    profileId: profile.id,
    status: 'running',
    operatorId: input.operatorId ?? null,
  });
  await runRepo.save(run);

  let status: TechIntelRunStatus = 'completed';
  let errorMessage: string | null = null;
  const startedAt = Date.now();

  let result: Awaited<ReturnType<typeof runHardeningValidation>> | null = null;
  try {
    result = await runHardeningValidation(resolvedHostname, profile.id);
  } catch (err) {
    status = 'failed';
    errorMessage = (err as Error).message;
  }

  const events = result?.events ?? [];

  await evtRepo.save(
    events.map((event) =>
      evtRepo.create({
        runId: run.id,
        probeId: event.probeId,
        probeLabel: event.probeLabel,
        category: event.category,
        method: event.method,
        path: event.path,
        responseStatus: event.responseStatus,
        responseDurationMs: event.responseDurationMs,
        observedVerdict: event.observedVerdict,
        observedConfidence: event.observedConfidence,
        verdictSignals: event.verdictSignals,
        expectedVerdicts: event.expectedVerdicts,
        expectationOutcome: event.expectationOutcome,
        expectationReasons: event.expectationReasons,
        bodyPreview: event.bodyPreview,
        responseHeaders: event.responseHeaders,
        errorMessage: event.errorMessage,
      }),
    ),
  );

  const counts = events.reduce(
    (acc, evt) => {
      acc[evt.expectationOutcome] += 1;
      return acc;
    },
    { matched: 0, partially_matched: 0, mismatched: 0, ambiguous: 0 } as Record<string, number>,
  );

  if (status === 'completed' && (counts.mismatched > 0 || counts.ambiguous === events.length) && events.length > 0) {
    status = 'partial';
  }

  run.status = status;
  run.errorMessage = errorMessage;
  run.totalEvents = events.length;
  run.matchedEvents = counts.matched;
  run.partiallyMatchedEvents = counts.partially_matched;
  run.mismatchedEvents = counts.mismatched;
  run.ambiguousEvents = counts.ambiguous;
  run.durationMs = Date.now() - startedAt;
  await runRepo.save(run);

  return {
    runId: run.id,
    status: run.status,
    resolvedHostname,
    totalEvents: run.totalEvents,
    matchedEvents: run.matchedEvents,
    partiallyMatchedEvents: run.partiallyMatchedEvents,
    mismatchedEvents: run.mismatchedEvents,
    ambiguousEvents: run.ambiguousEvents,
    durationMs: run.durationMs,
  };
}

// ---------------------------------------------------------------
// Listing & detail
// ---------------------------------------------------------------

export interface TechIntelRunListItem {
  id: string;
  targetKey: string;
  resolvedHostname: string;
  profileId: string;
  status: string;
  technologyCount: number;
  correlationCount: number;
  highOrCriticalCount: number;
  durationMs: number;
  createdAt: Date;
}

export async function listTechIntelRuns(limit = 50): Promise<TechIntelRunListItem[]> {
  const repo = AppDataSource.getRepository(TechIntelRun);
  const rows = await repo.find({ order: { createdAt: 'DESC' }, take: limit });
  return rows.map((row) => ({
    id: row.id,
    targetKey: row.targetKey,
    resolvedHostname: row.resolvedHostname,
    profileId: row.profileId,
    status: row.status,
    technologyCount: row.technologyCount,
    correlationCount: row.correlationCount,
    highOrCriticalCount: row.highOrCriticalCount,
    durationMs: row.durationMs,
    createdAt: row.createdAt,
  }));
}

export async function getTechIntelRunDetail(runId: string) {
  const runRepo = AppDataSource.getRepository(TechIntelRun);
  const techRepo = AppDataSource.getRepository(DetectedTechnology);
  const corrRepo = AppDataSource.getRepository(VulnerabilityCorrelation);
  const obsRepo = AppDataSource.getRepository(FingerprintObservation);
  const run = await runRepo.findOne({ where: { id: runId } });
  if (!run) return null;
  const [technologies, correlations, observations] = await Promise.all([
    techRepo.find({ where: { runId }, order: { category: 'ASC', productName: 'ASC' } }),
    corrRepo.find({ where: { runId }, order: { severityScore: 'DESC' } }),
    obsRepo.find({ where: { runId }, order: { family: 'ASC', methodId: 'ASC', capturedAt: 'ASC' } }),
  ]);
  const methodsExercised = [...new Set(observations.map((o) => o.methodId))].sort();
  return { run, technologies, correlations, observations, methodsExercised };
}

export async function listWafValidationRuns(limit = 50) {
  const repo = AppDataSource.getRepository(WafValidationRun);
  const rows = await repo.find({ order: { createdAt: 'DESC' }, take: limit });
  return rows.map((row) => ({
    id: row.id,
    targetKey: row.targetKey,
    resolvedHostname: row.resolvedHostname,
    profileId: row.profileId,
    status: row.status,
    totalEvents: row.totalEvents,
    matchedEvents: row.matchedEvents,
    partiallyMatchedEvents: row.partiallyMatchedEvents,
    mismatchedEvents: row.mismatchedEvents,
    ambiguousEvents: row.ambiguousEvents,
    durationMs: row.durationMs,
    createdAt: row.createdAt,
  }));
}

export async function getWafValidationRunDetail(runId: string) {
  const runRepo = AppDataSource.getRepository(WafValidationRun);
  const evtRepo = AppDataSource.getRepository(WafValidationEvent);
  const run = await runRepo.findOne({ where: { id: runId } });
  if (!run) return null;
  const events = await evtRepo.find({ where: { runId }, order: { createdAt: 'ASC' } });
  return { run, events };
}

export async function updateCorrelationTriage(
  correlationId: string,
  triageState: VulnerabilityCorrelation['triageState'],
  operatorNote: string | null,
): Promise<VulnerabilityCorrelation | null> {
  const repo = AppDataSource.getRepository(VulnerabilityCorrelation);
  const row = await repo.findOne({ where: { id: correlationId } });
  if (!row) return null;
  row.triageState = triageState;
  row.operatorNote = operatorNote;
  return repo.save(row);
}

// ---------------------------------------------------------------
// Observation ledger (evidence trace)
// ---------------------------------------------------------------

export async function listRunObservations(runId: string): Promise<FingerprintObservation[]> {
  const repo = AppDataSource.getRepository(FingerprintObservation);
  return repo.find({
    where: { runId },
    order: { family: 'ASC', methodId: 'ASC', capturedAt: 'ASC' },
  });
}

/**
 * Returns the distinct detection-method ids that fired during a run.
 * Used to render the "Methods Exercised" panel without re-fetching the
 * full observation ledger.
 */
export async function listRunMethodsExercised(runId: string): Promise<string[]> {
  const repo = AppDataSource.getRepository(FingerprintObservation);
  const rows = await repo
    .createQueryBuilder('o')
    .select('DISTINCT o."methodId"', 'methodId')
    .where('o."runId" = :runId', { runId })
    .getRawMany<{ methodId: string }>();
  return rows.map((r) => r.methodId).sort();
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/**
 * Map a {@link FingerprintSignalFamily} back onto the legacy evidence
 * `source` tag so existing UI code (and the PDF/HTML report renderer)
 * continue to work without a migration.
 */
function legacySourceFromFamily(
  family:
    | 'passive_http'
    | 'tls'
    | 'markup'
    | 'url_route'
    | 'dom_structural'
    | 'behavior'
    | 'service',
): 'header' | 'cookie' | 'body_marker' | 'tls' | 'banner' | 'meta_tag' | 'asset' | 'script' | 'rule' {
  switch (family) {
    case 'tls':
      return 'tls';
    case 'service':
      return 'banner';
    case 'markup':
      return 'body_marker';
    case 'passive_http':
      return 'header';
    case 'url_route':
    case 'dom_structural':
    case 'behavior':
    default:
      return 'rule';
  }
}
