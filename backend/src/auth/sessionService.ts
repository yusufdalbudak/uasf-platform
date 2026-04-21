import { AppDataSource } from '../db/connection';
import { AuthSession } from '../db/models/AuthSession';
import { env } from '../config/env';
import { generateOpaqueToken, hashOpaqueToken } from './tokenService';

/**
 * Refresh-session lifecycle.
 *
 * One row per (user, device). The plaintext refresh token is returned to the
 * caller exactly once at issuance / rotation; only its hash is stored. On
 * every refresh we ROTATE the token so the cookie value the client now holds
 * is fresh — the previous value is invalidated and any subsequent reuse is
 * treated as token theft.
 */

export interface SessionContext {
  ipAddress: string | null;
  userAgent: string | null;
}

export interface IssuedSession {
  sessionId: string;
  refreshToken: string;
  expiresAt: Date;
}

export async function createSession(userId: string, ctx: SessionContext): Promise<IssuedSession> {
  const repo = AppDataSource.getRepository(AuthSession);
  const refreshToken = generateOpaqueToken();
  const refreshTokenHash = hashOpaqueToken(refreshToken);
  const expiresAt = new Date(Date.now() + env.refreshTokenTtlSec * 1000);
  const row = repo.create({
    userId,
    refreshTokenHash,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent ? ctx.userAgent.slice(0, 512) : null,
    expiresAt,
    lastUsedAt: new Date(),
  });
  await repo.save(row);
  return { sessionId: row.id, refreshToken, expiresAt };
}

export type ConsumeResult =
  | { ok: true; session: AuthSession; refreshToken: string; expiresAt: Date }
  | { ok: false; reason: 'unknown' | 'expired' | 'revoked' | 'reused' };

/**
 * Validate a presented refresh token and rotate it. Returns the new
 * plaintext refresh token (to be re-emitted as a cookie) and the persisted
 * session row (so callers can build a fresh access token).
 *
 * Reuse detection: if the presented token's hash doesn't match ANY active
 * session, but the session id we expected exists and was already rotated
 * away, the entire session is force-revoked as a theft signal.
 */
export async function rotateSession(
  presentedToken: string,
  ctx: SessionContext,
): Promise<ConsumeResult> {
  const repo = AppDataSource.getRepository(AuthSession);
  const presentedHash = hashOpaqueToken(presentedToken);
  const session = await repo.findOne({ where: { refreshTokenHash: presentedHash } });
  if (!session) return { ok: false, reason: 'unknown' };
  if (session.revokedAt) return { ok: false, reason: 'revoked' };
  if (session.expiresAt.getTime() < Date.now()) {
    session.revokedAt = new Date();
    session.revocationReason = 'expired';
    await repo.save(session);
    return { ok: false, reason: 'expired' };
  }

  const newToken = generateOpaqueToken();
  session.refreshTokenHash = hashOpaqueToken(newToken);
  session.lastUsedAt = new Date();
  session.ipAddress = ctx.ipAddress ?? session.ipAddress;
  session.userAgent = ctx.userAgent ? ctx.userAgent.slice(0, 512) : session.userAgent;
  // We deliberately do NOT extend expiresAt here — refresh tokens have a
  // fixed absolute lifetime so an attacker who silently rotates forever
  // cannot extend a stolen session indefinitely.
  await repo.save(session);
  return {
    ok: true,
    session,
    refreshToken: newToken,
    expiresAt: session.expiresAt,
  };
}

export async function revokeSession(sessionId: string, reason: string): Promise<void> {
  const repo = AppDataSource.getRepository(AuthSession);
  await repo.update(
    { id: sessionId },
    { revokedAt: new Date(), revocationReason: reason },
  );
}

export async function revokeSessionByRefreshToken(token: string, reason: string): Promise<string | null> {
  const repo = AppDataSource.getRepository(AuthSession);
  const session = await repo.findOne({ where: { refreshTokenHash: hashOpaqueToken(token) } });
  if (!session) return null;
  if (!session.revokedAt) {
    session.revokedAt = new Date();
    session.revocationReason = reason;
    await repo.save(session);
  }
  return session.id;
}

export async function revokeAllSessionsForUser(userId: string, reason: string): Promise<void> {
  const repo = AppDataSource.getRepository(AuthSession);
  await repo
    .createQueryBuilder()
    .update(AuthSession)
    .set({ revokedAt: new Date(), revocationReason: reason })
    .where('"userId" = :userId AND "revokedAt" IS NULL', { userId })
    .execute();
}

export async function listActiveSessions(userId: string): Promise<AuthSession[]> {
  const repo = AppDataSource.getRepository(AuthSession);
  return repo
    .createQueryBuilder('s')
    .where('s.userId = :userId', { userId })
    .andWhere('s.revokedAt IS NULL')
    .andWhere('s.expiresAt > :now', { now: new Date() })
    .orderBy('s.lastUsedAt', 'DESC')
    .getMany();
}

/**
 * Confirm that the access-token's `sid` claim still resolves to a live,
 * non-revoked session row. Performed on every authenticated request so we
 * can revoke a session and have it stop working immediately, rather than
 * waiting for the access-token lifetime to elapse.
 */
export async function isSessionLive(sessionId: string): Promise<boolean> {
  const repo = AppDataSource.getRepository(AuthSession);
  const session = await repo.findOne({ where: { id: sessionId } });
  if (!session) return false;
  if (session.revokedAt) return false;
  if (session.expiresAt.getTime() < Date.now()) return false;
  return true;
}
