/**
 * UASF Tech Intelligence — HTTP API
 *
 * Public surface for the Tech Intelligence module.  All routes:
 *
 *   - require an authenticated request (the global authPlugin enforces
 *     this), and additionally restrict run-launch routes to operator
 *     and admin roles.
 *   - validate the input body / params with `zod`.
 *   - translate policy errors (forbidden / unregistered / unapproved)
 *     into the same response envelope the rest of the platform uses,
 *     so the frontend handles them uniformly.
 *
 * Lifecycle endpoints:
 *
 *   POST /api/tech-intel/runs                  — fingerprint run
 *   GET  /api/tech-intel/runs                  — list recent fingerprint runs
 *   GET  /api/tech-intel/runs/:id              — detailed run (techs + correlations)
 *   GET  /api/tech-intel/runs/:id/report.html  — HTML report
 *   GET  /api/tech-intel/runs/:id/report.pdf   — PDF report
 *
 *   POST /api/tech-intel/waf/runs              — hardening validation run
 *   GET  /api/tech-intel/waf/runs              — list recent waf runs
 *   GET  /api/tech-intel/waf/runs/:id          — detailed waf run (events)
 *
 *   GET  /api/tech-intel/profiles              — both profile catalogs
 *   PATCH /api/tech-intel/correlations/:id     — operator triage
 */

import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { PolicyForbiddenTargetError } from '../safety/guard';
import {
  AssetNotApprovedError,
  AssetNotRegisteredError,
} from '../policy/executableAsset';
import { normalizeOperatorTargetInput } from '../../../shared/scanContract';
import {
  getTechIntelOverviewStats,
  getTechIntelRunDetail,
  getWafValidationRunDetail,
  listDetectionMethodsCatalog,
  listProfiles,
  listRunMethodsExercised,
  listRunObservations,
  listTechIntelRuns,
  listWafValidationRuns,
  runTechIntelFingerprint,
  runTechIntelHardening,
  updateCorrelationTriage,
} from '../services/techIntel/techIntelService';
import { renderTechIntelHtml, renderTechIntelPdf } from '../services/techIntel/techIntelReport';

const RUN_FINGERPRINT_BODY = z.object({
  targetKey: z.string().min(1, 'targetKey is required'),
  profileId: z.string().min(1, 'profileId is required'),
});

const RUN_HARDENING_BODY = z.object({
  targetKey: z.string().min(1, 'targetKey is required'),
  profileId: z.string().min(1, 'profileId is required'),
});

const TRIAGE_BODY = z.object({
  triageState: z.enum(['open', 'confirmed', 'false_positive', 'mitigated', 'risk_accepted']),
  operatorNote: z.string().max(1024).nullable().optional(),
});

const STRICT_LIMIT = {
  config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
};

// ---------------------------------------------------------------
// Setup
// ---------------------------------------------------------------

export async function setupTechIntelRoutes(server: FastifyInstance): Promise<void> {
  const operatorOnly = { preHandler: [server.requireRole(['admin', 'operator'])] };

  server.get('/api/tech-intel/profiles', async () => listProfiles());

  server.get('/api/tech-intel/overview', async () => getTechIntelOverviewStats());

  // ------------------------------------------------------------------
  // Detection-method catalog & observation ledger
  //
  // The catalog is static, evidence-free metadata and can be served to
  // any authenticated user.  Observations are bound to a specific run
  // and are returned whole so the Evidence Trace tab can render them.
  // ------------------------------------------------------------------

  server.get('/api/tech-intel/methods', async () => listDetectionMethodsCatalog());

  server.get('/api/tech-intel/runs/:id/observations', async (request, reply) => {
    const { id } = request.params as { id: string };
    const run = await getTechIntelRunDetail(id);
    if (!run) return reply.code(404).send({ error: 'Run not found' });
    const observations = await listRunObservations(id);
    return { runId: id, observations };
  });

  server.get('/api/tech-intel/runs/:id/methods', async (request, reply) => {
    const { id } = request.params as { id: string };
    const run = await getTechIntelRunDetail(id);
    if (!run) return reply.code(404).send({ error: 'Run not found' });
    const methodIds = await listRunMethodsExercised(id);
    return { runId: id, methodIds };
  });

  server.get('/api/tech-intel/runs', async () => {
    const items = await listTechIntelRuns(50);
    return { items };
  });

  server.get('/api/tech-intel/runs/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const detail = await getTechIntelRunDetail(id);
    if (!detail) return reply.code(404).send({ error: 'Run not found' });
    return detail;
  });

  server.get('/api/tech-intel/runs/:id/report.html', async (request, reply) => {
    const { id } = request.params as { id: string };
    const query = request.query as { download?: string };
    const detail = await getTechIntelRunDetail(id);
    if (!detail) return reply.code(404).send({ error: 'Run not found' });
    reply.header('Content-Type', 'text/html; charset=utf-8');
    // Inline by default so the new tab can render the document.  Only
    // force a download when the operator explicitly opts in via
    // ?download=1, otherwise the browser triggers a "save dialog"
    // instead of rendering and the preview tab is left empty.
    const slug = detail.run.targetKey.replace(/[^a-z0-9.-]+/gi, '_');
    const disposition = query.download === '1' ? 'attachment' : 'inline';
    reply.header('Content-Disposition', `${disposition}; filename="uasf-tech-intel-${slug}.html"`);
    return renderTechIntelHtml(detail);
  });

  server.get('/api/tech-intel/runs/:id/report.pdf', async (request, reply) => {
    const { id } = request.params as { id: string };
    const query = request.query as { download?: string };
    const detail = await getTechIntelRunDetail(id);
    if (!detail) return reply.code(404).send({ error: 'Run not found' });
    try {
      const pdf = await renderTechIntelPdf(detail);
      const slug = detail.run.targetKey.replace(/[^a-z0-9.-]+/gi, '_');
      const disposition = query.download === '1' ? 'attachment' : 'inline';
      reply
        .header('Content-Type', 'application/pdf')
        .header('Content-Disposition', `${disposition}; filename="uasf-tech-intel-${slug}.pdf"`);
      return reply.send(pdf);
    } catch (err: unknown) {
      // Fail loudly with a clean JSON envelope instead of letting a
      // partial PDF buffer trickle through to the browser, which is
      // exactly the "corrupted PDF" failure mode operators see.
      request.log.error({ err, runId: id }, 'Tech Intel PDF render failed');
      return reply.code(500).send({
        error: 'Failed to render PDF report.',
        code: 'TECH_INTEL_PDF_FAILED',
      });
    }
  });

  server.post(
    '/api/tech-intel/runs',
    { ...STRICT_LIMIT, ...operatorOnly },
    async (request, reply) => {
      const parsed = RUN_FINGERPRINT_BODY.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? 'Invalid request' });
      }
      const targetKey = normalizeOperatorTargetInput(parsed.data.targetKey);
      try {
        const result = await runTechIntelFingerprint({
          targetKey,
          profileId: parsed.data.profileId,
          operatorId: request.user?.id ?? null,
        });
        return result;
      } catch (err) {
        const handled = handlePolicyError(reply, err);
        if (handled) return handled;
        request.log.error({ err, targetKey }, 'Tech intel fingerprint run failed');
        return reply.code(500).send({ error: (err as Error).message });
      }
    },
  );

  server.get('/api/tech-intel/waf/runs', async () => {
    const items = await listWafValidationRuns(50);
    return { items };
  });

  server.get('/api/tech-intel/waf/runs/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const detail = await getWafValidationRunDetail(id);
    if (!detail) return reply.code(404).send({ error: 'Run not found' });
    return detail;
  });

  server.post(
    '/api/tech-intel/waf/runs',
    { ...STRICT_LIMIT, ...operatorOnly },
    async (request, reply) => {
      const parsed = RUN_HARDENING_BODY.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? 'Invalid request' });
      }
      const targetKey = normalizeOperatorTargetInput(parsed.data.targetKey);
      try {
        const result = await runTechIntelHardening({
          targetKey,
          profileId: parsed.data.profileId,
          operatorId: request.user?.id ?? null,
        });
        return result;
      } catch (err) {
        const handled = handlePolicyError(reply, err);
        if (handled) return handled;
        request.log.error({ err, targetKey }, 'Tech intel hardening run failed');
        return reply.code(500).send({ error: (err as Error).message });
      }
    },
  );

  server.patch(
    '/api/tech-intel/correlations/:id',
    operatorOnly,
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const parsed = TRIAGE_BODY.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: parsed.error.issues[0]?.message ?? 'Invalid request' });
      }
      const updated = await updateCorrelationTriage(
        id,
        parsed.data.triageState,
        parsed.data.operatorNote ?? null,
      );
      if (!updated) return reply.code(404).send({ error: 'Correlation not found' });
      return updated;
    },
  );
}

function handlePolicyError(reply: FastifyReply, err: unknown): unknown | null {
  if (err instanceof PolicyForbiddenTargetError) {
    return reply.code(403).send({
      error:
        'This target is not on the approved allowlist for this environment.  Update ALLOWED_TARGETS or use an authorized hostname or label.',
      code: 'POLICY_FORBIDDEN_TARGET',
      targetKey: err.targetKey,
    });
  }
  if (err instanceof AssetNotRegisteredError) {
    return reply.code(403).send({
      error:
        'This target is not registered in the approved asset registry.  Add it under Targets first.',
      code: 'ASSET_NOT_REGISTERED',
      targetKey: err.targetKey,
    });
  }
  if (err instanceof AssetNotApprovedError) {
    return reply.code(403).send({
      error: `Asset exists but is not approved for execution (status: ${err.approvalStatus}).`,
      code: 'ASSET_NOT_APPROVED',
      targetKey: err.targetKey,
      approvalStatus: err.approvalStatus,
    });
  }
  return null;
}
