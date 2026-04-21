import { Worker, Job } from 'bullmq';
import { redisConnection, SCENARIO_QUEUE_NAME } from './queue';
import { assertExecutableApprovedAsset } from '../policy/executableAsset';
import { AppDataSource } from '../db/connection';
import { EvidenceLog } from '../db/models/Evidence';
import { resolveProtectedHostname } from '../db/targetResolution';
import { env } from '../config/env';
import { buildExecutionLogEntry, refreshCampaignRunSummary } from '../services/campaignTelemetry';
import {
  type CampaignRequestBodyMode,
  getCampaignScenarioById,
} from './scenarios';
import { classifyResponseVerdict, type VerdictEvaluation } from './verdict';
import { evaluateExpectation, type ExpectationEvaluation, type ExpectationSpec } from './expectation';

export interface CampaignJobData {
  campaignRunId: string;
  scenarioId: string;
  targetHostname: string;
  requestLabel?: string;
  deliveryChannel?: string;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  bodyMode?: CampaignRequestBodyMode;
  /** Optional inline expectation; falls back to scenario template lookup. */
  expected?: ExpectationSpec;
  /** Originating request id from scenario template (used to look up expectations). */
  templateRequestId?: string;
}

function buildRequestBody(body: unknown, bodyMode: CampaignRequestBodyMode | undefined): BodyInit | undefined {
  if (body === undefined || body === null) {
    return undefined;
  }
  if (bodyMode === 'raw') {
    return typeof body === 'string' ? body : String(body);
  }
  return JSON.stringify(body);
}

function resolveExpectation(data: CampaignJobData): ExpectationSpec | undefined {
  if (data.expected) {
    return data.expected;
  }
  if (!data.scenarioId || !data.templateRequestId) {
    return undefined;
  }
  const scenario = getCampaignScenarioById(data.scenarioId);
  if (!scenario) return undefined;
  const template = scenario.requests.find((req) => req.id === data.templateRequestId);
  return template?.expected;
}

export let scenarioWorker: Worker;

export function initWorker() {
  scenarioWorker = new Worker(
    SCENARIO_QUEUE_NAME,
    async (job: Job<CampaignJobData>) => {
      const data = job.data;

      await assertExecutableApprovedAsset(data.targetHostname);

      const startTime = Date.now();
      let statusCode = 0;
      let responseHeaders: Record<string, string> = {};
      let responseBodyPreview: string | null = null;
      let errorMessage: string | null = null;

      const protectedHost = await resolveProtectedHostname(data.targetHostname);
      const url = `https://${protectedHost}${data.path}`;
      const requestHeaders = {
        'User-Agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        Connection: 'keep-alive',
        ...data.headers,
      };

      try {
        const response = await fetch(url, {
          method: data.method,
          headers: requestHeaders,
          body: buildRequestBody(data.body, data.bodyMode),
          signal: AbortSignal.timeout(8000),
        });

        statusCode = response.status;
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });
        responseBodyPreview = await response.text();
      } catch (error: unknown) {
        statusCode = -1;
        errorMessage = error instanceof Error ? error.message : String(error);
        responseHeaders['x-error'] = errorMessage;
      }

      const latencyMs = Date.now() - startTime;

      // Classify the verdict based on real signals, not just status codes.
      const verdict: VerdictEvaluation = classifyResponseVerdict({
        status: statusCode,
        headers: responseHeaders,
        bodyPreview: responseBodyPreview,
        errorMessage,
        finalUrl: url,
      });

      // Evaluate expected vs observed for this scenario request.
      const expectationSpec = resolveExpectation(data);
      const expectation: ExpectationEvaluation = evaluateExpectation(expectationSpec, verdict, statusCode);

      const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
      const logEntry = buildExecutionLogEntry({
        campaignRunId: data.campaignRunId,
        scenarioId: data.scenarioId,
        targetHostname: data.targetHostname,
        method: data.method,
        path: data.path,
        requestLabel: data.requestLabel ?? null,
        deliveryChannel: data.deliveryChannel ?? null,
        attemptNumber: job.attemptsMade + 1,
        workerJobId: job.id ? String(job.id) : null,
        attemptedUrl: url,
        requestHeaders,
        requestBody: data.body,
        executionStatus: verdict.verdict,
        responseStatusCode: statusCode,
        latencyMs,
        responseHeaders,
        responseBodyPreview,
        errorMessage,
        verdict,
        expectation,
      });

      await evidenceRepo.save(logEntry);
      await refreshCampaignRunSummary(data.campaignRunId);

      return {
        statusCode,
        latencyMs,
        verdict: verdict.verdict,
        expectationOutcome: expectation.outcome,
      };
    },
    {
      connection: redisConnection,
      concurrency: env.safetyMaxConcurrency,
    },
  );

  scenarioWorker.on('completed', (job, result) => {
    console.log(
      `[uasf-worker] job=${job.id} verdict=${result?.verdict ?? 'unknown'} expectation=${
        result?.expectationOutcome ?? 'unknown'
      } status=${result?.statusCode ?? 'n/a'}`,
    );
  });

  scenarioWorker.on('failed', (job, err) => {
    console.error(`[uasf-worker] job=${job?.id} failed: ${err.message}`);
  });
}
