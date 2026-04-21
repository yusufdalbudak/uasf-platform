import { FastifyInstance } from 'fastify';
import { scenarioQueue, redisConnection } from '../engine/queue';
import { AppDataSource } from '../db/connection';
import { EvidenceLog } from '../db/models/Evidence';
import { Target } from '../db/models/Target';
import { ScenarioTemplate } from '../db/models/ScenarioTemplate';
import { Campaign } from '../db/models/Campaign';
import { AssessmentRun } from '../db/models/AssessmentRun';
import { SecurityFinding } from '../db/models/SecurityFinding';
import { DiscoveredService } from '../db/models/DiscoveredService';
import { Report } from '../db/models/Report';
import { DependencyVulnerability } from '../db/models/DependencyVulnerability';
import { IocIndicator } from '../db/models/IocIndicator';
import { MalwareArtifact } from '../db/models/MalwareArtifact';
import { CodeFinding } from '../db/models/CodeFinding';
import {
  persistAssessmentReport,
  renderReportHtml,
  renderReportPdf,
} from '../services/reportService';
import { runDiscoveryPipeline } from '../services/discoveryService';
import { refreshDependencyFeed } from '../services/dependencyFeedService';
import { refreshIocFeed } from '../services/iocFeedService';
import { analyzeArtifact } from '../services/malwareAnalysisService';
import { ingestSarifDocument } from '../services/codeSecurityService';
import {
  isVirusTotalConfigured,
  virustotalLookup,
  VtLookupError,
} from '../services/virustotalService';
import {
  multiLookup,
  multiLookupStatus,
} from '../services/multiLookupService';
import {
  WAAP_SCENARIOS,
  getCampaignScenarioById,
  getCampaignScenarioJobCount,
  listCampaignScenarios,
} from '../engine/scenarios';
import { runVulnerabilityScan } from '../engine/scanner';
import { createScanErrorResult, parseScanRequestBody } from '../engine/validators';
import { PolicyForbiddenTargetError } from '../safety/guard';
import {
  assertExecutableApprovedAsset,
  AssetNotApprovedError,
  AssetNotRegisteredError,
} from '../policy/executableAsset';
import { env } from '../config/env';
import { getMergedAllowlistKeys } from '../policy/policy';
import { registerApprovedWebTarget } from '../services/registerTarget';
import { normalizeOperatorTargetInput } from '../../../shared/scanContract';
import {
  createCampaignRunRecord,
  listRecentCampaignActivity,
} from '../services/campaignTelemetry';
import { buildDashboardOverview, type DashboardWindow } from '../services/dashboardOverview';

function policyErrorReply(reply: import('fastify').FastifyReply, e: unknown, target = '') {
  if (e instanceof PolicyForbiddenTargetError) {
    return reply.code(403).send({
      error:
        'This target is not on the approved allowlist for this environment. Update ALLOWED_TARGETS or use an authorized hostname or label.',
      code: 'POLICY_FORBIDDEN_TARGET',
      targetKey: e.targetKey,
      result: createScanErrorResult(target),
    });
  }
  if (e instanceof AssetNotRegisteredError) {
    return reply.code(403).send({
      error:
        'This target is not registered in the approved asset registry. Add it under Targets or disable REQUIRE_REGISTERED_ASSET for legacy demos.',
      code: 'ASSET_NOT_REGISTERED',
      targetKey: e.targetKey,
      result: createScanErrorResult(target),
    });
  }
  if (e instanceof AssetNotApprovedError) {
    return reply.code(403).send({
      error: `Asset exists but is not approved for execution (status: ${e.approvalStatus}).`,
      code: 'ASSET_NOT_APPROVED',
      targetKey: e.targetKey,
      approvalStatus: e.approvalStatus,
      result: createScanErrorResult(target),
    });
  }
  return null;
}

export async function setupRoutes(server: FastifyInstance) {
  server.post('/api/scan/run', async (request, reply) => {
    const parsed = parseScanRequestBody(request.body);
    const target = parsed.ok ? parsed.value.target : '';

    if (parsed.ok === false) {
      const errorMessage = parsed.error;
      return reply.code(400).send({
        error: errorMessage,
        code: 'INVALID_SCAN_REQUEST',
        result: createScanErrorResult(target),
      });
    }

    try {
      const result = await runVulnerabilityScan(parsed.value.target);
      // Best-effort persistence: never let a report write failure swallow a
      // valid assessment result. The renderer always works off the live
      // result; the persisted Report unlocks downstream HTML/PDF downloads.
      let reportId: string | undefined;
      try {
        const persisted = await persistAssessmentReport({
          reportType: 'assessment',
          result,
        });
        reportId = persisted.id;
      } catch (persistError) {
        request.log.warn({ err: persistError, target }, 'Assessment report persistence failed');
      }
      return { ...result, reportId };
    } catch (e: unknown) {
      const pe = policyErrorReply(reply, e, target);
      if (pe) return pe;
      request.log.error({ err: e, target }, 'Scan execution failed');
      const err = e as Error;
      return reply.code(500).send({
        error: `Scan failed: ${err.message}`,
        code: 'SCAN_EXECUTION_FAILED',
        result: createScanErrorResult(target),
      });
    }
  });

  server.get('/api/health', async () => ({
    status: 'ok',
    service: env.serviceName,
    version: env.serviceVersion,
    policy: {
      requireRegisteredAsset: env.requireRegisteredAsset,
    },
  }));

  server.get('/api/ready', async (_request, reply) => {
    try {
      await AppDataSource.query('SELECT 1');
      await redisConnection.ping();
      return {
        status: 'ready',
        checks: { database: true, redis: true },
      };
    } catch (e: unknown) {
      const err = e as Error;
      return reply.code(503).send({
        status: 'not_ready',
        error: err.message,
      });
    }
  });

  server.post('/api/campaigns/run', async (request, reply) => {
    try {
      const body = request.body as { targetHostname?: string; scenarioType?: string };
      const targetHostname = normalizeOperatorTargetInput(body?.targetHostname ?? '');
      const scenarioType = body?.scenarioType;

      if (!targetHostname) {
        return reply.code(400).send({ error: 'Target hostname or label is required' });
      }
      await assertExecutableApprovedAsset(targetHostname);

      const campaignRunId = `run_${Date.now()}`;
      const scenario = getCampaignScenarioById(scenarioType ?? '') || WAAP_SCENARIOS[0];
      const jobs: (string | number | undefined)[] = [];

      for (const requestTemplate of scenario.requests) {
        const repeatCount = requestTemplate.repeatCount ?? 1;
        for (let index = 0; index < repeatCount; index += 1) {
          const job = await scenarioQueue.add('execute-scenario', {
            campaignRunId,
            scenarioId: scenario.id,
            templateRequestId: requestTemplate.id,
            targetHostname,
            requestLabel:
              repeatCount > 1 ? `${requestTemplate.label} (${index + 1}/${repeatCount})` : requestTemplate.label,
            deliveryChannel: requestTemplate.deliveryChannel,
            method: requestTemplate.method,
            path: requestTemplate.path,
            headers: {
              ...(requestTemplate.headers || {}),
            },
            body: requestTemplate.body,
            bodyMode: requestTemplate.bodyMode,
            expected: requestTemplate.expected,
          });
          jobs.push(job.id);
        }
      }

      await createCampaignRunRecord({
        externalRunId: campaignRunId,
        targetHostname,
        scenarioId: scenario.id,
        requestedJobs: getCampaignScenarioJobCount(scenario),
        queuedJobIds: jobs.map((jobId) => String(jobId)),
      });

      return {
        status: 'queued',
        jobsQueued: jobs.length,
        campaignRunId,
        scenario: {
          id: scenario.id,
          name: scenario.name,
          category: scenario.category,
        },
      };
    } catch (e: unknown) {
      const pe = policyErrorReply(reply, e);
      if (pe) return pe;
      const err = e as Error;
      return reply.code(500).send({ error: err.message });
    }
  });

  server.get('/api/campaign-scenarios', async () => ({
    scenarios: listCampaignScenarios(),
  }));

  server.get('/api/campaigns/activity', async (request) => {
    const query = request.query as { take?: string | number | undefined };
    const takeRaw = typeof query.take === 'number' ? query.take : parseInt(String(query.take ?? '8'), 10);
    const take = Number.isFinite(takeRaw) && takeRaw > 0 ? Math.min(takeRaw, 20) : 8;

    return {
      runs: await listRecentCampaignActivity(take),
    };
  });

  server.get('/api/policy/allowed-target-keys', async () => ({
    keys: await getMergedAllowlistKeys(),
  }));

  server.post('/api/targets', async (request, reply) => {
    const body = request.body as {
      hostname?: string;
      displayName?: string | null;
      environment?: string | null;
      apptranaAlias?: string | null;
    };
    if (!body?.hostname || typeof body.hostname !== 'string') {
      return reply.code(400).send({ error: 'hostname is required' });
    }
    try {
      const r = await registerApprovedWebTarget({
        hostnameInput: body.hostname,
        displayName: body.displayName ?? null,
        environment: body.environment ?? null,
        apptranaAlias: body.apptranaAlias ?? null,
      });
      return {
        ok: true,
        target: r.target,
        targetCreated: r.targetCreated,
        allowlistCreated: r.allowlistCreated,
      };
    } catch (e: unknown) {
      const err = e as Error;
      return reply.code(400).send({ error: err.message });
    }
  });

  server.get('/api/dashboard/summary', async () => {
    const targetRepo = AppDataSource.getRepository(Target);
    const findingRepo = AppDataSource.getRepository(SecurityFinding);
    const campaignRepo = AppDataSource.getRepository(Campaign);
    const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
    const runRepo = AppDataSource.getRepository(AssessmentRun);
    const discRepo = AppDataSource.getRepository(DiscoveredService);

    const [approvedAssets, findingsTotal, campaignsTotal, evidenceEvents, runsTotal, exposureRows] =
      await Promise.all([
        targetRepo.count({ where: { approvalStatus: 'approved' } }),
        findingRepo.count(),
        campaignRepo.count(),
        evidenceRepo.count(),
        runRepo.count(),
        discRepo.count(),
      ]);

    const raw = await findingRepo
      .createQueryBuilder('f')
      .select('f.severity', 'severity')
      .addSelect('COUNT(*)', 'count')
      .groupBy('f.severity')
      .getRawMany();

    const findingsBySeverity: Record<string, number> = {};
    for (const row of raw) {
      findingsBySeverity[row.severity] = parseInt(String(row.count), 10);
    }

    return {
      approvedAssets,
      findingsTotal,
      campaignsTotal,
      evidenceEvents,
      runsTotal,
      exposureSignals: exposureRows,
      findingsBySeverity,
    };
  });

  server.get('/api/dashboard/overview', async (request, reply) => {
    const query = request.query as { window?: string | undefined };
    const candidate = String(query.window ?? 'daily').toLowerCase();
    const window = ['daily', 'weekly', 'monthly', 'yearly'].includes(candidate)
      ? (candidate as DashboardWindow)
      : null;

    if (!window) {
      return reply.code(400).send({
        error: 'window must be one of: daily, weekly, monthly, yearly',
      });
    }

    return buildDashboardOverview(window);
  });

  server.get('/api/assets', async () => {
    const targetRepo = AppDataSource.getRepository(Target);
    const assets = await targetRepo.find({
      relations: ['aliases', 'discoveredServices'],
      order: { hostname: 'ASC' },
    });
    return { assets };
  });

  server.get('/api/targets', async () => {
    const targetRepo = AppDataSource.getRepository(Target);
    const targets = await targetRepo.find({
      relations: ['aliases', 'discoveredServices'],
      order: { hostname: 'ASC' },
    });
    return { targets };
  });

  server.get('/api/scenario-templates', async () => {
    const repo = AppDataSource.getRepository(ScenarioTemplate);
    const templates = await repo.find({ order: { category: 'ASC', name: 'ASC' } });
    return { templates };
  });

  server.get('/api/campaigns', async () => {
    const repo = AppDataSource.getRepository(Campaign);
    const campaigns = await repo.find({
      order: { updatedAt: 'DESC' },
    });
    return { campaigns };
  });

  server.get('/api/runs', async () => {
    const repo = AppDataSource.getRepository(AssessmentRun);
    const runs = await repo.find({
      relations: ['campaign', 'asset'],
      order: { createdAt: 'DESC' },
      take: 100,
    });

    // Most run records originate from WAAP scenarios that live in code
    // (WAAP_SCENARIOS) rather than from a DB Campaign row, so `campaign`
    // is null. Surface the scenario identity from `summary` so the UI can
    // render a meaningful "campaign / scenario" column.
    return {
      runs: runs.map((run) => {
        const summary = (run.summary ?? {}) as Record<string, unknown>;
        const scenarioName =
          typeof summary.scenarioName === 'string' && summary.scenarioName.length > 0
            ? summary.scenarioName
            : null;
        const scenarioId =
          typeof summary.scenarioId === 'string' && summary.scenarioId.length > 0
            ? summary.scenarioId
            : null;
        const scenarioCategory =
          typeof summary.scenarioCategory === 'string' && summary.scenarioCategory.length > 0
            ? summary.scenarioCategory
            : null;
        const targetHostname =
          typeof summary.targetHostname === 'string' && summary.targetHostname.length > 0
            ? summary.targetHostname
            : null;

        return {
          id: run.id,
          externalRunId: run.externalRunId,
          label: run.label,
          status: run.status,
          startedAt: run.startedAt,
          completedAt: run.completedAt,
          createdAt: run.createdAt,
          updatedAt: run.updatedAt,
          campaign: run.campaign ? { id: run.campaign.id, name: run.campaign.name } : null,
          asset: run.asset
            ? { id: run.asset.id, hostname: run.asset.hostname, displayName: run.asset.displayName }
            : null,
          scenario: scenarioId
            ? {
                id: scenarioId,
                name: scenarioName ?? scenarioId,
                category: scenarioCategory,
              }
            : null,
          targetHostname,
          summary: run.summary,
        };
      }),
    };
  });

  server.get('/api/findings', async () => {
    const repo = AppDataSource.getRepository(SecurityFinding);
    const findings = await repo.find({
      relations: ['asset'],
      order: { createdAt: 'DESC' },
      take: 100,
    });
    return { findings };
  });

  server.get('/api/evidence', async () => {
    const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
    return evidenceRepo.find({
      order: { timestamp: 'DESC' },
      take: 200,
    });
  });

  // ----------------------------------------------------------------
  // Reports — list, fetch, render to HTML or PDF, delete.
  // ----------------------------------------------------------------

  server.get('/api/reports', async (request) => {
    const query = request.query as {
      reportType?: string;
      target?: string;
      take?: string | number | undefined;
    };
    const takeRaw =
      typeof query.take === 'number' ? query.take : parseInt(String(query.take ?? '50'), 10);
    const take = Number.isFinite(takeRaw) && takeRaw > 0 ? Math.min(takeRaw, 200) : 50;

    const repo = AppDataSource.getRepository(Report);
    const qb = repo.createQueryBuilder('r').orderBy('r.createdAt', 'DESC').take(take);
    if (query.reportType) qb.andWhere('r.reportType = :rt', { rt: String(query.reportType) });
    if (query.target) qb.andWhere('r.targetHostname = :t', { t: String(query.target) });
    const reports = await qb.getMany();

    return {
      reports: reports.map((report) => ({
        id: report.id,
        reportType: report.reportType,
        targetHostname: report.targetHostname,
        title: report.title,
        durationMs: report.durationMs,
        totalFindings: report.totalFindings,
        criticalCount: report.criticalCount,
        highCount: report.highCount,
        mediumCount: report.mediumCount,
        lowCount: report.lowCount,
        infoCount: report.infoCount,
        modulesRun: report.modulesRun,
        modulesSucceeded: report.modulesSucceeded,
        modulesFailed: report.modulesFailed,
        createdAt: report.createdAt,
      })),
    };
  });

  server.get('/api/reports/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const repo = AppDataSource.getRepository(Report);
    const report = await repo.findOne({ where: { id } });
    if (!report) {
      return reply.code(404).send({ error: 'Report not found', code: 'REPORT_NOT_FOUND' });
    }
    return { report };
  });

  server.get('/api/reports/:id/html', async (request, reply) => {
    const { id } = request.params as { id: string };
    const query = request.query as { download?: string };
    const repo = AppDataSource.getRepository(Report);
    const report = await repo.findOne({ where: { id } });
    if (!report) {
      return reply.code(404).send({ error: 'Report not found', code: 'REPORT_NOT_FOUND' });
    }

    const html = renderReportHtml(report);
    reply.header('Content-Type', 'text/html; charset=utf-8');
    // Inline by default → the new tab actually renders the HTML.
    // attachment only when ?download=1 (explicit download button).
    const disposition = query.download === '1' ? 'attachment' : 'inline';
    reply.header(
      'Content-Disposition',
      `${disposition}; filename="${buildDownloadFilename(report, 'html')}"`,
    );
    return reply.send(html);
  });

  server.get('/api/reports/:id/pdf', async (request, reply) => {
    const { id } = request.params as { id: string };
    const query = request.query as { download?: string };
    const repo = AppDataSource.getRepository(Report);
    const report = await repo.findOne({ where: { id } });
    if (!report) {
      return reply.code(404).send({ error: 'Report not found', code: 'REPORT_NOT_FOUND' });
    }

    try {
      const pdf = await renderReportPdf(report);
      reply.header('Content-Type', 'application/pdf');
      // Inline by default so the browser uses its built-in PDF viewer.
      // Forcing 'attachment' here was the root cause of the spinning
      // "Loading report…" placeholder — Chrome cancelled the navigation
      // and triggered a download instead, leaving the popup orphaned.
      const disposition = query.download === '1' ? 'attachment' : 'inline';
      reply.header(
        'Content-Disposition',
        `${disposition}; filename="${buildDownloadFilename(report, 'pdf')}"`,
      );
      return reply.send(pdf);
    } catch (error: unknown) {
      request.log.error({ err: error, reportId: id }, 'PDF render failed');
      return reply.code(500).send({ error: 'Failed to render PDF', code: 'REPORT_PDF_FAILED' });
    }
  });

  server.delete('/api/reports/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const repo = AppDataSource.getRepository(Report);
    const found = await repo.findOne({ where: { id } });
    if (!found) {
      return reply.code(404).send({ error: 'Report not found', code: 'REPORT_NOT_FOUND' });
    }
    await repo.remove(found);
    return { ok: true };
  });

  // ----------------------------------------------------------------
  // Discovery — recon-only assessment that persists DiscoveredService rows.
  // ----------------------------------------------------------------

  server.post('/api/discovery/run', async (request, reply) => {
    const body = request.body as { target?: string; targetHostname?: string };
    const target = (body?.target ?? body?.targetHostname ?? '').toString();
    if (!target.trim()) {
      return reply.code(400).send({
        error: 'Target hostname or label is required.',
        code: 'INVALID_DISCOVERY_REQUEST',
        result: createScanErrorResult(''),
      });
    }
    try {
      const { result, servicesPersisted } = await runDiscoveryPipeline(target);
      let reportId: string | undefined;
      try {
        const persisted = await persistAssessmentReport({
          reportType: 'discovery',
          result,
        });
        reportId = persisted.id;
      } catch (persistError) {
        request.log.warn({ err: persistError, target }, 'Discovery report persistence failed');
      }
      return { result, servicesPersisted, reportId };
    } catch (e: unknown) {
      const pe = policyErrorReply(reply, e, target);
      if (pe) return pe;
      request.log.error({ err: e, target }, 'Discovery execution failed');
      const err = e as Error;
      return reply.code(500).send({
        error: `Discovery failed: ${err.message}`,
        code: 'DISCOVERY_EXECUTION_FAILED',
        result: createScanErrorResult(target),
      });
    }
  });

  server.get('/api/discovery/services', async () => {
    const repo = AppDataSource.getRepository(DiscoveredService);
    const services = await repo.find({
      relations: ['asset'],
      order: { lastSeen: 'DESC' },
      take: 500,
    });
    return {
      services: services.map((service) => ({
        id: service.id,
        port: service.port,
        protocol: service.protocol,
        bannerSummary: service.bannerSummary,
        evidenceSource: service.evidenceSource,
        firstSeen: service.firstSeen,
        lastSeen: service.lastSeen,
        target: service.asset
          ? {
              id: service.asset.id,
              hostname: service.asset.hostname,
              displayName: service.asset.displayName,
              environment: service.asset.environment,
            }
          : null,
      })),
    };
  });

  server.get('/api/discovery/reports', async () => {
    const repo = AppDataSource.getRepository(Report);
    const reports = await repo.find({
      where: { reportType: 'discovery' },
      order: { createdAt: 'DESC' },
      take: 50,
    });
    return {
      reports: reports.map((report) => ({
        id: report.id,
        targetHostname: report.targetHostname,
        title: report.title,
        durationMs: report.durationMs,
        totalFindings: report.totalFindings,
        modulesRun: report.modulesRun,
        modulesSucceeded: report.modulesSucceeded,
        modulesFailed: report.modulesFailed,
        createdAt: report.createdAt,
      })),
    };
  });

  // ----------------------------------------------------------------
  // Findings — domain-scoped views for the cross-domain modules.
  // ----------------------------------------------------------------

  server.get('/api/findings/by-domain/:domain', async (request, reply) => {
    const { domain } = request.params as { domain: string };
    const validDomains = ['platform', 'dast', 'sast', 'dependency', 'ioc', 'malware', 'exposure'];
    if (!validDomains.includes(domain)) {
      return reply.code(400).send({
        error: `domain must be one of: ${validDomains.join(', ')}`,
        code: 'INVALID_FINDING_DOMAIN',
      });
    }
    const repo = AppDataSource.getRepository(SecurityFinding);
    const findings = await repo.find({
      where: { findingDomain: domain },
      relations: ['asset'],
      order: { createdAt: 'DESC' },
      take: 200,
    });
    return { domain, findings };
  });

  // ----------------------------------------------------------------
  // IOC observations — derived from the verdict signals captured during
  // campaign runs. Surfacing them here gives operators a real, evidence-
  // backed indicator feed without requiring a separate threat-intel pipe.
  // ----------------------------------------------------------------

  server.get('/api/ioc/observations', async () => {
    const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
    const recent = await evidenceRepo.find({
      order: { timestamp: 'DESC' },
      take: 200,
    });

    type Observation = {
      indicator: string;
      type: string;
      detail: string | null;
      occurrences: number;
      firstSeen: string;
      lastSeen: string;
      verdicts: Record<string, number>;
    };

    const map = new Map<string, Observation>();

    for (const event of recent) {
      const signals = Array.isArray(event.verdictSignals) ? event.verdictSignals : [];
      for (const signal of signals) {
        if (!signal || typeof signal.name !== 'string') continue;
        const key = `${signal.source ?? 'unknown'}::${signal.name}`;
        const existing = map.get(key);
        if (existing) {
          existing.occurrences += 1;
          existing.lastSeen = new Date(event.timestamp).toISOString();
          existing.verdicts[event.verdict ?? 'ambiguous'] =
            (existing.verdicts[event.verdict ?? 'ambiguous'] ?? 0) + 1;
        } else {
          map.set(key, {
            indicator: signal.name,
            type: signal.source ?? 'unknown',
            detail: signal.detail ?? null,
            occurrences: 1,
            firstSeen: new Date(event.timestamp).toISOString(),
            lastSeen: new Date(event.timestamp).toISOString(),
            verdicts: { [event.verdict ?? 'ambiguous']: 1 },
          });
        }
      }
    }

    const observations = Array.from(map.values()).sort(
      (a, b) => b.occurrences - a.occurrences,
    );
    return { observations };
  });

  // ----------------------------------------------------------------
  // Integrations — surface the real status of platform back-ends so the
  // operator console reflects ground truth rather than hard-coded text.
  // ----------------------------------------------------------------

  server.get('/api/integrations/status', async () => {
    const checks: Array<{
      id: string;
      name: string;
      kind: string;
      status: 'ok' | 'degraded' | 'down';
      detail?: string | null;
    }> = [];

    try {
      await AppDataSource.query('SELECT 1');
      checks.push({ id: 'postgres', name: 'PostgreSQL', kind: 'datastore', status: 'ok' });
    } catch (error) {
      checks.push({
        id: 'postgres',
        name: 'PostgreSQL',
        kind: 'datastore',
        status: 'down',
        detail: (error as Error).message,
      });
    }

    try {
      const pong = await redisConnection.ping();
      checks.push({
        id: 'redis',
        name: 'Redis (BullMQ backplane)',
        kind: 'queue-backend',
        status: pong === 'PONG' ? 'ok' : 'degraded',
        detail: pong,
      });
    } catch (error) {
      checks.push({
        id: 'redis',
        name: 'Redis (BullMQ backplane)',
        kind: 'queue-backend',
        status: 'down',
        detail: (error as Error).message,
      });
    }

    try {
      const counts = await scenarioQueue.getJobCounts(
        'waiting',
        'active',
        'completed',
        'failed',
        'delayed',
      );
      checks.push({
        id: 'bullmq-scenarios',
        name: 'BullMQ scenario queue',
        kind: 'job-queue',
        status: 'ok',
        detail: `waiting:${counts.waiting} active:${counts.active} completed:${counts.completed} failed:${counts.failed}`,
      });
    } catch (error) {
      checks.push({
        id: 'bullmq-scenarios',
        name: 'BullMQ scenario queue',
        kind: 'job-queue',
        status: 'down',
        detail: (error as Error).message,
      });
    }

    return {
      service: env.serviceName,
      version: env.serviceVersion,
      checks,
    };
  });

  // ----------------------------------------------------------------
  // Settings — read-only environment + policy snapshot for the operator.
  // Secrets are never returned; URLs are shape-only.
  // ----------------------------------------------------------------

  server.get('/api/settings', async () => {
    return {
      service: env.serviceName,
      version: env.serviceVersion,
      policy: {
        requireRegisteredAsset: env.requireRegisteredAsset,
        allowlistKeys: await getMergedAllowlistKeys(),
      },
      runtime: {
        databaseSynchronize: env.databaseSynchronize,
        nodeVersion: process.version,
        platform: process.platform,
        uptimeSeconds: Math.round(process.uptime()),
      },
    };
  });

  // ----------------------------------------------------------------
  // CVE intelligence — newest publicly-disclosed CVEs sourced from the
  // mycve.com community CVE tracker (https://mycve.com/).
  // The cache is refreshed by a background scheduler (every 2 hours);
  // these routes only read or trigger an immediate refresh.
  // ----------------------------------------------------------------

  server.get('/api/dependency/vulnerabilities', async (request) => {
    const query = request.query as {
      ecosystem?: string;
      severity?: string;
      package?: string;
      take?: string | number;
    };
    const takeRaw =
      typeof query.take === 'number' ? query.take : parseInt(String(query.take ?? '100'), 10);
    const take = Number.isFinite(takeRaw) && takeRaw > 0 ? Math.min(takeRaw, 500) : 100;

    const repo = AppDataSource.getRepository(DependencyVulnerability);
    const qb = repo
      .createQueryBuilder('v')
      .orderBy(
        // Severity sorted newest+most-severe first.
        `CASE v.severityLabel WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END`,
        'ASC',
      )
      .addOrderBy('v.modifiedAt', 'DESC')
      .take(take);

    if (query.ecosystem) qb.andWhere('LOWER(v.ecosystem) = LOWER(:ecosystem)', { ecosystem: query.ecosystem });
    if (query.severity) qb.andWhere('LOWER(v.severityLabel) = LOWER(:sev)', { sev: query.severity });
    if (query.package) qb.andWhere('v.packageName ILIKE :pkg', { pkg: `%${query.package}%` });

    const [items, total] = await qb.getManyAndCount();
    return {
      total,
      items,
    };
  });

  server.get('/api/dependency/summary', async () => {
    const repo = AppDataSource.getRepository(DependencyVulnerability);
    const total = await repo.count();
    const bySeverity = await repo
      .createQueryBuilder('v')
      .select('v.severityLabel', 'severity')
      .addSelect('COUNT(*)', 'count')
      .groupBy('v.severityLabel')
      .getRawMany();
    const ecosystems = await repo
      .createQueryBuilder('v')
      .select('v.ecosystem', 'ecosystem')
      .addSelect('COUNT(*)', 'count')
      .groupBy('v.ecosystem')
      .getRawMany();
    const latest = await repo.find({ order: { modifiedAt: 'DESC' }, take: 1 });
    return {
      total,
      bySeverity: Object.fromEntries(bySeverity.map((row) => [row.severity, parseInt(row.count, 10)])),
      byEcosystem: Object.fromEntries(ecosystems.map((row) => [row.ecosystem, parseInt(row.count, 10)])),
      lastIngestAt: latest[0]?.updatedAt ?? null,
      source: {
        name: 'mycve.com — Personal CVE Tracker',
        url: 'https://mycve.com/',
      },
    };
  });

  server.post('/api/dependency/refresh', async () => {
    const summary = await refreshDependencyFeed();
    return summary;
  });

  // ----------------------------------------------------------------
  // IOC & threat-context — multi-source public threat intelligence.
  //   - GitHub Advisory Database (https://github.com/advisories) — GHSA/CVE
  //     identifiers for known software vulnerabilities.
  //   - OpenPhish Community Feed (https://openphish.com/feed.txt) — active
  //     phishing URLs ingested anonymously; the OpenPhish OPDB client at
  //     https://github.com/openphish/pyopdb wraps a licensed product, so we
  //     intentionally consume the free community feed instead.
  //   - abuse.ch ThreatFox (https://threatfox.abuse.ch/export/csv/recent/) —
  //     malware-attributed IOCs (URLs, domains, ip:port, hashes) from the
  //     anonymous CSV export; the JSON API now requires an auth key.
  // All three feeds are refreshed every 2h by the background scheduler.
  // ----------------------------------------------------------------

  server.get('/api/ioc/indicators', async (request) => {
    const query = request.query as {
      type?: string;
      source?: string;
      search?: string;
      take?: string | number;
    };
    const takeRaw =
      typeof query.take === 'number' ? query.take : parseInt(String(query.take ?? '100'), 10);
    const take = Number.isFinite(takeRaw) && takeRaw > 0 ? Math.min(takeRaw, 500) : 100;

    const repo = AppDataSource.getRepository(IocIndicator);
    const qb = repo.createQueryBuilder('i').orderBy('i.lastSeen', 'DESC').take(take);
    if (query.type) qb.andWhere('LOWER(i.indicatorType) = LOWER(:t)', { t: query.type });
    if (query.source) qb.andWhere('LOWER(i.source) = LOWER(:s)', { s: query.source });
    if (query.search) qb.andWhere('i.indicator ILIKE :q', { q: `%${query.search}%` });

    const [items, total] = await qb.getManyAndCount();
    return { total, items };
  });

  server.get('/api/ioc/summary', async () => {
    const repo = AppDataSource.getRepository(IocIndicator);
    const total = await repo.count();
    const byType = await repo
      .createQueryBuilder('i')
      .select('i.indicatorType', 'type')
      .addSelect('COUNT(*)', 'count')
      .groupBy('i.indicatorType')
      .getRawMany();
    const bySource = await repo
      .createQueryBuilder('i')
      .select('i.source', 'source')
      .addSelect('COUNT(*)', 'count')
      .groupBy('i.source')
      .getRawMany();
    const latest = await repo.find({ order: { lastSeen: 'DESC' }, take: 1 });
    return {
      total,
      byType: Object.fromEntries(byType.map((row) => [row.type, parseInt(row.count, 10)])),
      bySource: Object.fromEntries(bySource.map((row) => [row.source, parseInt(row.count, 10)])),
      lastIngestAt: latest[0]?.lastSeen ?? null,
      source: {
        name: 'Multi-source threat intelligence',
        url: 'https://openphish.com/',
      },
      sources: [
        {
          id: 'github_advisories',
          name: 'GitHub Advisory Database',
          url: 'https://github.com/advisories',
          description: 'GHSA + CVE identifiers for known software vulnerabilities.',
        },
        {
          id: 'openphish',
          name: 'OpenPhish Community Feed',
          url: 'https://openphish.com/',
          description:
            'Currently-active phishing URLs published by OpenPhish (free community feed).',
        },
        {
          id: 'threatfox',
          name: 'abuse.ch ThreatFox',
          url: 'https://threatfox.abuse.ch/browse/',
          description:
            'Recent malware-attributed IOCs (URLs, domains, ip:port, hashes) from the ThreatFox public CSV export.',
        },
      ],
    };
  });

  server.post('/api/ioc/refresh', async () => {
    const summary = await refreshIocFeed();
    return summary;
  });

  // ----------------------------------------------------------------
  // Malware & file risk — sandbox-style file analysis. Uploaded files
  // are processed in memory only; nothing is written to disk and no
  // bytes are forwarded to third-party services. Rejected if multipart
  // payload is missing.
  // ----------------------------------------------------------------

  server.post('/api/malware/analyze', async (request, reply) => {
    if (!request.isMultipart()) {
      return reply.code(400).send({
        error: 'Expected multipart/form-data with an "artifact" file field.',
        code: 'MALWARE_BAD_REQUEST',
      });
    }
    try {
      const file = await request.file();
      if (!file) {
        return reply.code(400).send({
          error: 'No file submitted under the "artifact" field.',
          code: 'MALWARE_FILE_MISSING',
        });
      }
      const buffer = await file.toBuffer();
      const result = await analyzeArtifact({
        fileName: file.filename || 'unnamed.bin',
        bytes: buffer,
        submittedBy: typeof request.headers['x-operator'] === 'string'
          ? request.headers['x-operator']
          : null,
      });
      return result;
    } catch (error) {
      request.log.warn({ err: error }, 'Malware analysis failed');
      return reply
        .code(400)
        .send({ error: (error as Error).message, code: 'MALWARE_ANALYSIS_FAILED' });
    }
  });

  server.get('/api/malware/artifacts', async (request) => {
    const query = request.query as { take?: string | number; verdict?: string };
    const takeRaw =
      typeof query.take === 'number' ? query.take : parseInt(String(query.take ?? '50'), 10);
    const take = Number.isFinite(takeRaw) && takeRaw > 0 ? Math.min(takeRaw, 200) : 50;
    const repo = AppDataSource.getRepository(MalwareArtifact);
    const qb = repo.createQueryBuilder('a').orderBy('a.createdAt', 'DESC').take(take);
    if (query.verdict) qb.andWhere('LOWER(a.verdict) = LOWER(:v)', { v: query.verdict });
    return { items: await qb.getMany() };
  });

  server.get('/api/malware/summary', async () => {
    const repo = AppDataSource.getRepository(MalwareArtifact);
    const total = await repo.count();
    const byVerdict = await repo
      .createQueryBuilder('a')
      .select('a.verdict', 'verdict')
      .addSelect('COUNT(*)', 'count')
      .groupBy('a.verdict')
      .getRawMany();
    return {
      total,
      byVerdict: Object.fromEntries(byVerdict.map((row) => [row.verdict, parseInt(row.count, 10)])),
    };
  });

  // ----------------------------------------------------------------
  // VirusTotal proxy — server-side reputation lookups.
  //
  // The VirusTotal API key MUST stay on the backend; embedding it in any
  // browser-shippable artifact would expose it to every page visitor. The
  // service layer adds a 10-min TTL cache so repeated clicks don't spend
  // free-tier quota (4/min, 500/day, 15.5K/month).
  // ----------------------------------------------------------------

  server.get('/api/virustotal/status', async () => {
    return {
      configured: isVirusTotalConfigured(),
      provider: 'VirusTotal Public API v3',
      docs: 'https://docs.virustotal.com/reference/overview',
    };
  });

  server.post('/api/virustotal/lookup', async (request, reply) => {
    const body = (request.body ?? {}) as { kind?: unknown; value?: unknown };
    const kind = typeof body.kind === 'string' ? body.kind.trim() : '';
    const value = typeof body.value === 'string' ? body.value.trim() : '';
    if (!kind || !value) {
      return reply.code(400).send({
        error: 'kind and value are required strings',
        code: 'VT_LOOKUP_BAD_REQUEST',
      });
    }
    try {
      const result = await virustotalLookup(kind, value);
      return result;
    } catch (e) {
      if (e instanceof VtLookupError) {
        return reply.code(e.statusCode).send({ error: e.message, code: `VT_${e.code.toUpperCase()}` });
      }
      request.log.error({ err: e }, 'virustotal lookup failed');
      return reply.code(500).send({
        error: 'VirusTotal lookup failed unexpectedly.',
        code: 'VT_INTERNAL',
      });
    }
  });

  // ----------------------------------------------------------------
  // Multi-source reputation lookup — fans a single indicator out to:
  //   1. Local IOC database (no key required; covers GitHub Advisories,
  //      OpenPhish, abuse.ch ThreatFox feeds we ingest).
  //   2. VirusTotal Public v3 (uses VIRUSTOTAL_API_KEY).
  //   3. abuse.ch ThreatFox / URLhaus / MalwareBazaar (use ABUSE_CH_AUTH_KEY).
  //
  // Each provider's outcome is normalized to one row with verdict + status,
  // so the UI can render a stable grid where unconfigured / unsupported
  // providers explain themselves rather than vanishing.
  // ----------------------------------------------------------------

  server.get('/api/lookup/status', async () => {
    return multiLookupStatus();
  });

  server.post('/api/lookup/multi', async (request, reply) => {
    const body = (request.body ?? {}) as { kind?: unknown; value?: unknown };
    const value = typeof body.value === 'string' ? body.value.trim() : '';
    const kind = typeof body.kind === 'string' ? body.kind.trim() : '';
    if (!value) {
      return reply.code(400).send({
        error: 'value is required and must be a non-empty string',
        code: 'LOOKUP_BAD_REQUEST',
      });
    }
    try {
      return await multiLookup(kind || null, value);
    } catch (e) {
      const message = (e as Error).message ?? 'multi-source lookup failed';
      const code =
        message.includes('detected') || message.includes('declared')
          ? 'LOOKUP_INVALID_INPUT'
          : 'LOOKUP_INTERNAL';
      const status = code === 'LOOKUP_INVALID_INPUT' ? 400 : 500;
      if (status === 500) request.log.error({ err: e }, 'multi lookup failed');
      return reply.code(status).send({ error: message, code });
    }
  });

  // ----------------------------------------------------------------
  // Code Security (SAST) — SARIF ingestion + listing.
  // ----------------------------------------------------------------

  server.post('/api/code-security/sarif', async (request, reply) => {
    const body = request.body as {
      repository?: string;
      ref?: string | null;
      sarif?: unknown;
    };
    if (!body || typeof body.repository !== 'string' || body.repository.trim() === '') {
      return reply.code(400).send({
        error: 'repository is required',
        code: 'CODE_SARIF_BAD_REQUEST',
      });
    }
    if (!body.sarif || typeof body.sarif !== 'object') {
      return reply.code(400).send({
        error: 'sarif must be a SARIF v2 JSON document',
        code: 'CODE_SARIF_BAD_REQUEST',
      });
    }
    try {
      const summary = await ingestSarifDocument({
        repository: body.repository,
        ref: body.ref ?? null,
        document: body.sarif as Parameters<typeof ingestSarifDocument>[0]['document'],
      });
      return summary;
    } catch (error) {
      request.log.warn({ err: error }, 'SARIF ingest failed');
      return reply.code(400).send({
        error: (error as Error).message,
        code: 'CODE_SARIF_INGEST_FAILED',
      });
    }
  });

  server.get('/api/code-security/findings', async (request) => {
    const query = request.query as {
      repository?: string;
      severity?: string;
      take?: string | number;
    };
    const takeRaw =
      typeof query.take === 'number' ? query.take : parseInt(String(query.take ?? '100'), 10);
    const take = Number.isFinite(takeRaw) && takeRaw > 0 ? Math.min(takeRaw, 500) : 100;
    const repo = AppDataSource.getRepository(CodeFinding);
    const qb = repo.createQueryBuilder('f').orderBy('f.createdAt', 'DESC').take(take);
    if (query.repository) qb.andWhere('f.repository = :r', { r: query.repository });
    if (query.severity) qb.andWhere('LOWER(f.severity) = LOWER(:sev)', { sev: query.severity });
    const [items, total] = await qb.getManyAndCount();
    return { items, total };
  });

  server.get('/api/code-security/summary', async () => {
    const repo = AppDataSource.getRepository(CodeFinding);
    const total = await repo.count();
    const bySeverity = await repo
      .createQueryBuilder('f')
      .select('f.severity', 'severity')
      .addSelect('COUNT(*)', 'count')
      .groupBy('f.severity')
      .getRawMany();
    const byRepository = await repo
      .createQueryBuilder('f')
      .select('f.repository', 'repository')
      .addSelect('COUNT(*)', 'count')
      .groupBy('f.repository')
      .getRawMany();
    return {
      total,
      bySeverity: Object.fromEntries(bySeverity.map((row) => [row.severity, parseInt(row.count, 10)])),
      byRepository: Object.fromEntries(
        byRepository.map((row) => [row.repository, parseInt(row.count, 10)]),
      ),
    };
  });
}

function buildDownloadFilename(report: Report, ext: 'html' | 'pdf'): string {
  const safeTarget = report.targetHostname.replace(/[^a-z0-9.-]/gi, '_');
  const stamp = new Date(report.createdAt).toISOString().replace(/[:.]/g, '-');
  return `uasf_${report.reportType}_${safeTarget}_${stamp}.${ext}`;
}
