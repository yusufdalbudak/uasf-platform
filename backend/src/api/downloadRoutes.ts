/**
 * UASF Downloads — short-lived signed URL issuance.
 *
 * Single endpoint that mints a download token bound to (path, user, expiry)
 * for any path on the server-side allowlist (see
 * `auth/downloadTokenService`).  Used by the UI to open report HTML/PDF in
 * a new browser tab without raw `AUTH_REQUIRED` failures.
 */

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  DownloadTokenError,
  isAllowedDownloadPath,
  issueDownloadToken,
} from '../auth/downloadTokenService';

const SIGN_BODY = z.object({
  path: z.string().min(1).max(512),
  ttlSec: z.number().int().min(30).max(30 * 60).optional(),
});

export async function setupDownloadRoutes(server: FastifyInstance): Promise<void> {
  server.post(
    '/api/downloads/sign',
    { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } },
    async (request, reply) => {
      if (!request.user) {
        return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
      }
      const parsed = SIGN_BODY.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: parsed.error.issues[0]?.message ?? 'Invalid request',
          code: 'BAD_REQUEST',
        });
      }
      // Defence in depth: also reject obviously malformed paths client-side
      // before we even attempt to sign.
      if (!parsed.data.path.startsWith('/api/')) {
        return reply.code(400).send({
          error: 'Path must start with /api/.',
          code: 'BAD_DOWNLOAD_PATH',
        });
      }
      if (!isAllowedDownloadPath(parsed.data.path)) {
        return reply.code(403).send({
          error: 'This path is not eligible for signed download URLs.',
          code: 'DOWNLOAD_PATH_NOT_ALLOWED',
        });
      }
      try {
        const { token, expiresAt } = issueDownloadToken({
          path: parsed.data.path,
          userId: request.user.id,
          ttlSec: parsed.data.ttlSec,
        });
        return reply.send({
          url: `${parsed.data.path}?dlt=${encodeURIComponent(token)}`,
          expiresAt,
        });
      } catch (e) {
        if (e instanceof DownloadTokenError) {
          return reply.code(400).send({ error: e.message, code: e.code });
        }
        request.log.error({ err: e }, 'Failed to issue download token');
        return reply.code(500).send({ error: 'Internal error', code: 'INTERNAL_ERROR' });
      }
    },
  );
}
