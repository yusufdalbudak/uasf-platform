import type { FastifyInstance, FastifyReply } from 'fastify';
import { env } from '../config/env';
import {
  AuthError,
  changePassword,
  completeEmailVerification,
  completePasswordReset,
  deleteAccount,
  issueEmailVerification,
  login,
  logout,
  refreshIssue,
  requestPasswordReset,
  signup,
  type AuthIssuance,
} from '../auth/authService';
import {
  REFRESH_COOKIE_NAME,
  sessionContextFrom,
} from '../auth/authPlugin';
import {
  listActiveSessions,
  revokeSession,
} from '../auth/sessionService';
import { findUserById, toPublicUser } from '../auth/userService';
import { recordAuditEvent } from '../auth/auditService';
import { AppDataSource } from '../db/connection';
import { User } from '../db/models/User';

/**
 * /api/auth/* HTTP layer.
 *
 * Thin wrappers over `authService`. The job here is to:
 *   - validate / coerce the request body,
 *   - manage cookie issuance (refresh token only — never the access token),
 *   - format error responses with stable error codes,
 *   - never leak stack traces or provider internals to clients.
 */

function refreshCookieOpts(): Parameters<FastifyReply['setCookie']>[2] {
  // Cross-origin split deployments (e.g. Vercel-hosted frontend + backend on
  // a separate host) require `SameSite=None; Secure` on the refresh cookie
  // so the browser will actually send it on cross-origin fetches. Same-origin
  // deployments (reverse proxy / Vercel rewrite) keep the safer `lax`.
  // `COOKIE_SAMESITE=none|lax|strict` overrides the auto choice when needed.
  const override = (process.env.COOKIE_SAMESITE || '').trim().toLowerCase();
  const sameSite: 'none' | 'lax' | 'strict' =
    override === 'none' || override === 'lax' || override === 'strict'
      ? override
      : env.cookieSecure
        ? 'none'
        : 'lax';
  return {
    httpOnly: true,
    secure: env.cookieSecure || sameSite === 'none',
    sameSite,
    // Scope the cookie to the auth subtree so it's never sent to other API
    // routes; the access token (in the Authorization header) is what
    // protected endpoints rely on.
    path: '/api/auth',
    maxAge: env.refreshTokenTtlSec,
  };
}

function sendIssuance(
  reply: FastifyReply,
  issuance: AuthIssuance,
  status = 200,
): FastifyReply {
  reply.setCookie(REFRESH_COOKIE_NAME, issuance.refreshToken, refreshCookieOpts());
  return reply.code(status).send({
    user: issuance.user,
    accessToken: issuance.accessToken,
    accessTokenExpiresAt: issuance.accessTokenExpiresAt,
    sessionId: issuance.sessionId,
    refreshTokenExpiresAt: issuance.refreshTokenExpiresAt,
  });
}

function authErrorReply(reply: FastifyReply, e: unknown): FastifyReply {
  if (e instanceof AuthError) {
    return reply.code(e.statusCode).send({
      error: e.message,
      code: `AUTH_${e.code.toUpperCase()}`,
    });
  }
  return reply.code(500).send({
    error: 'Authentication request failed.',
    code: 'AUTH_INTERNAL',
  });
}

/**
 * Per-route rate-limit policies. Auth flows are the most attractive target
 * for abuse (credential stuffing, enumeration, password-reset spam) so each
 * gets a tight, deliberate limit on top of the global ceiling.
 */
const STRICT_LIMIT = { rateLimit: { max: 10, timeWindow: '1 minute' } } as const;
const RESET_LIMIT = { rateLimit: { max: 5, timeWindow: '15 minutes' } } as const;

export async function setupAuthRoutes(server: FastifyInstance): Promise<void> {
  // ----- signup -----
  server.post('/api/auth/signup', { config: STRICT_LIMIT }, async (request, reply) => {
    const body = (request.body ?? {}) as {
      email?: unknown;
      password?: unknown;
      displayName?: unknown;
      gdprConsent?: unknown;
    };
    try {
      const issuance = await signup(
        {
          email: typeof body.email === 'string' ? body.email : '',
          password: typeof body.password === 'string' ? body.password : '',
          displayName: typeof body.displayName === 'string' ? body.displayName : null,
          gdprConsent: body.gdprConsent === true,
        },
        sessionContextFrom(request),
      );
      return sendIssuance(reply, issuance, 201);
    } catch (e) {
      if (e instanceof AuthError && e.code === 'pending_verification') {
        return reply.code(202).send({
          message: e.message,
          code: 'AUTH_PENDING_VERIFICATION',
        });
      }
      return authErrorReply(reply, e);
    }
  });

  // ----- login -----
  server.post('/api/auth/login', { config: STRICT_LIMIT }, async (request, reply) => {
    const body = (request.body ?? {}) as { email?: unknown; password?: unknown };
    try {
      const issuance = await login(
        {
          email: typeof body.email === 'string' ? body.email : '',
          password: typeof body.password === 'string' ? body.password : '',
        },
        sessionContextFrom(request),
      );
      return sendIssuance(reply, issuance);
    } catch (e) {
      return authErrorReply(reply, e);
    }
  });

  // ----- refresh -----
  server.post('/api/auth/refresh', async (request, reply) => {
    try {
      const presented = request.presentedRefreshToken ?? null;
      if (!presented) {
        return reply.code(401).send({
          error: 'Refresh token missing.',
          code: 'AUTH_TOKEN_INVALID',
        });
      }
      const issuance = await refreshIssue(presented, sessionContextFrom(request));
      return sendIssuance(reply, issuance);
    } catch (e) {
      // Always clear the bad cookie on failure so the browser doesn't
      // keep retrying with a known-broken value.
      reply.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
      return authErrorReply(reply, e);
    }
  });

  // ----- logout -----
  server.post('/api/auth/logout', async (request, reply) => {
    const presented = request.presentedRefreshToken ?? null;
    await logout(
      presented,
      request.user ? { id: request.user.id, email: request.user.email } : null,
      sessionContextFrom(request),
    );
    reply.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
    return reply.code(200).send({ ok: true });
  });

  // ----- current user -----
  server.get('/api/auth/me', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    }
    const user = await findUserById(request.user.id);
    if (!user) {
      return reply.code(404).send({ error: 'User not found.', code: 'AUTH_USER_NOT_FOUND' });
    }
    return reply.send({ user: toPublicUser(user) });
  });

  // ----- update profile (displayName only — minimum viable surface) -----
  server.patch('/api/auth/me', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    }
    const body = (request.body ?? {}) as { displayName?: unknown };
    const repo = AppDataSource.getRepository(User);
    const user = await repo.findOne({ where: { id: request.user.id } });
    if (!user) {
      return reply.code(404).send({ error: 'User not found.', code: 'AUTH_USER_NOT_FOUND' });
    }
    if (typeof body.displayName === 'string') {
      const trimmed = body.displayName.trim();
      user.displayName = trimmed.length > 0 ? trimmed.slice(0, 128) : null;
    }
    await repo.save(user);
    return reply.send({ user: toPublicUser(user) });
  });

  // ----- change password -----
  server.post('/api/auth/change-password', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    }
    const body = (request.body ?? {}) as { currentPassword?: unknown; newPassword?: unknown };
    try {
      await changePassword(
        request.user.id,
        typeof body.currentPassword === 'string' ? body.currentPassword : '',
        typeof body.newPassword === 'string' ? body.newPassword : '',
        sessionContextFrom(request),
      );
      reply.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
      return reply.send({ ok: true });
    } catch (e) {
      return authErrorReply(reply, e);
    }
  });

  // ----- forgot / reset password -----
  server.post('/api/auth/forgot-password', { config: RESET_LIMIT }, async (request, reply) => {
    const body = (request.body ?? {}) as { email?: unknown };
    const result = await requestPasswordReset(
      typeof body.email === 'string' ? body.email : '',
      sessionContextFrom(request),
    );
    // Always 200 to avoid email enumeration.
    return reply.send({
      ok: true,
      // Surface the token in dev so operators can complete the flow without
      // SMTP. Production responses NEVER include it.
      ...(result.devToken ? { devToken: result.devToken } : {}),
    });
  });

  server.post('/api/auth/reset-password', { config: RESET_LIMIT }, async (request, reply) => {
    const body = (request.body ?? {}) as { token?: unknown; newPassword?: unknown };
    try {
      await completePasswordReset(
        typeof body.token === 'string' ? body.token : '',
        typeof body.newPassword === 'string' ? body.newPassword : '',
        sessionContextFrom(request),
      );
      return reply.send({ ok: true });
    } catch (e) {
      return authErrorReply(reply, e);
    }
  });

  // ----- email verification -----
  server.post('/api/auth/verify-email', async (request, reply) => {
    const body = (request.body ?? {}) as { token?: unknown };
    try {
      const user = await completeEmailVerification(
        typeof body.token === 'string' ? body.token : '',
        sessionContextFrom(request),
      );
      return reply.send({ user });
    } catch (e) {
      return authErrorReply(reply, e);
    }
  });

  server.post('/api/auth/resend-verification', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    }
    const result = await issueEmailVerification(request.user.id);
    return reply.send({
      ok: true,
      ...(result.devToken ? { devToken: result.devToken } : {}),
    });
  });

  // ----- active sessions -----
  server.get('/api/auth/sessions', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    }
    const sessions = await listActiveSessions(request.user.id);
    return reply.send({
      sessions: sessions.map((s) => ({
        id: s.id,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        createdAt: s.createdAt.toISOString(),
        lastUsedAt: s.lastUsedAt ? s.lastUsedAt.toISOString() : null,
        expiresAt: s.expiresAt.toISOString(),
        current: s.id === request.user!.sessionId,
      })),
    });
  });

  server.delete('/api/auth/sessions/:id', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    }
    const params = request.params as { id?: string };
    const id = params?.id;
    if (!id) return reply.code(400).send({ error: 'Session id required.', code: 'AUTH_BAD_REQUEST' });
    const sessions = await listActiveSessions(request.user.id);
    const owned = sessions.find((s) => s.id === id);
    if (!owned) {
      // Don't leak whether the session id exists for someone else.
      return reply.code(404).send({ error: 'Session not found.', code: 'AUTH_NOT_FOUND' });
    }
    await revokeSession(id, 'manual');
    await recordAuditEvent({
      action: 'session_revoked',
      userId: request.user.id,
      email: request.user.email,
      ipAddress: sessionContextFrom(request).ipAddress,
      userAgent: sessionContextFrom(request).userAgent,
      metadata: { sessionId: id, byUser: true },
    });
    return reply.send({ ok: true });
  });

  // ----- account deletion (GDPR right to erasure) -----
  server.post('/api/auth/delete-account', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
    }
    const body = (request.body ?? {}) as { password?: unknown };
    try {
      await deleteAccount(
        request.user.id,
        typeof body.password === 'string' ? body.password : '',
        sessionContextFrom(request),
      );
      reply.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
      return reply.send({ ok: true });
    } catch (e) {
      return authErrorReply(reply, e);
    }
  });

  // ----- admin: list users / change role -----
  server.get('/api/auth/users', { preHandler: server.requireRole(['admin']) }, async (_request, reply) => {
    const repo = AppDataSource.getRepository(User);
    const users = await repo.find({ order: { createdAt: 'ASC' } });
    return reply.send({ users: users.map(toPublicUser) });
  });

  server.patch(
    '/api/auth/users/:id/role',
    { preHandler: server.requireRole(['admin']) },
    async (request, reply) => {
      const params = request.params as { id?: string };
      const body = (request.body ?? {}) as { role?: unknown };
      if (!params.id) return reply.code(400).send({ error: 'User id required.', code: 'AUTH_BAD_REQUEST' });
      if (
        body.role !== 'admin' &&
        body.role !== 'operator' &&
        body.role !== 'viewer'
      ) {
        return reply.code(400).send({ error: 'Invalid role.', code: 'AUTH_BAD_REQUEST' });
      }
      if (params.id === request.user!.id && body.role !== 'admin') {
        return reply.code(400).send({
          error: 'Admins cannot demote themselves.',
          code: 'AUTH_BAD_REQUEST',
        });
      }
      const repo = AppDataSource.getRepository(User);
      const user = await repo.findOne({ where: { id: params.id } });
      if (!user) return reply.code(404).send({ error: 'User not found.', code: 'AUTH_NOT_FOUND' });
      const previousRole = user.role;
      user.role = body.role;
      await repo.save(user);
      await recordAuditEvent({
        action: 'role_changed',
        userId: user.id,
        email: user.email,
        ipAddress: sessionContextFrom(request).ipAddress,
        userAgent: sessionContextFrom(request).userAgent,
        metadata: { previousRole, newRole: user.role, changedBy: request.user!.id },
      });
      return reply.send({ user: toPublicUser(user) });
    },
  );
}
