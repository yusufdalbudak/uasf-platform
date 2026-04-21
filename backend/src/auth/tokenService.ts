import { createHash, randomBytes } from 'crypto';
import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';
import { env } from '../config/env';
import type { UserRole } from '../db/models/User';

/**
 * Token primitives used by the auth layer.
 *
 * Two distinct token types live here:
 *
 *   1. ACCESS TOKENS — short-lived JWTs (15 min default) signed with HS256.
 *      Carry the user identity, role, and a `tokenVersion` claim so a
 *      password change or role change instantly invalidates older tokens.
 *      Sent in the `Authorization: Bearer ...` header by the frontend.
 *
 *   2. REFRESH TOKENS — opaque, high-entropy random strings (256 bits).
 *      Stored as an httpOnly + Secure + SameSite=Lax cookie on the client;
 *      ONLY the SHA-256 hash (with a server-side pepper) is persisted in
 *      the `auth_sessions` table. Rotated on every refresh; reuse of an
 *      already-rotated token is treated as theft.
 */

export interface AccessTokenClaims {
  sub: string; // user id
  email: string;
  role: UserRole;
  tv: number; // tokenVersion — bumped on password / role change
  sid: string; // refresh-session id, lets us tie tokens back to a device
}

const ACCESS_ISSUER = 'uasf-platform';
const ACCESS_AUDIENCE = 'uasf-frontend';

let cachedSecret: Uint8Array | null = null;
function accessSecret(): Uint8Array {
  if (!cachedSecret) cachedSecret = new TextEncoder().encode(env.jwtAccessSecret);
  return cachedSecret;
}

export async function signAccessToken(claims: AccessTokenClaims): Promise<string> {
  return new SignJWT({ email: claims.email, role: claims.role, tv: claims.tv, sid: claims.sid })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(claims.sub)
    .setIssuer(ACCESS_ISSUER)
    .setAudience(ACCESS_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${env.accessTokenTtlSec}s`)
    .sign(accessSecret());
}

export type AccessVerifyError =
  | 'invalid'
  | 'expired'
  | 'malformed'
  | 'signature'
  | 'unknown';

export interface AccessVerifyResult {
  ok: true;
  claims: AccessTokenClaims;
}
export interface AccessVerifyFailure {
  ok: false;
  reason: AccessVerifyError;
}

export async function verifyAccessToken(
  token: string,
): Promise<AccessVerifyResult | AccessVerifyFailure> {
  try {
    const { payload } = await jwtVerify(token, accessSecret(), {
      issuer: ACCESS_ISSUER,
      audience: ACCESS_AUDIENCE,
    });
    if (
      typeof payload.sub !== 'string' ||
      typeof payload.email !== 'string' ||
      typeof payload.role !== 'string' ||
      typeof payload.tv !== 'number' ||
      typeof payload.sid !== 'string'
    ) {
      return { ok: false, reason: 'malformed' };
    }
    return {
      ok: true,
      claims: {
        sub: payload.sub,
        email: payload.email,
        role: payload.role as UserRole,
        tv: payload.tv,
        sid: payload.sid,
      },
    };
  } catch (e) {
    if (e instanceof joseErrors.JWTExpired) return { ok: false, reason: 'expired' };
    if (e instanceof joseErrors.JWSSignatureVerificationFailed)
      return { ok: false, reason: 'signature' };
    if (e instanceof joseErrors.JWTInvalid || e instanceof joseErrors.JWTClaimValidationFailed)
      return { ok: false, reason: 'invalid' };
    return { ok: false, reason: 'unknown' };
  }
}

// ---------------------------------------------------------------------------
// Opaque token primitives (refresh, password reset, email verification).
// ---------------------------------------------------------------------------

/** 256 bits of entropy as URL-safe base64. */
export function generateOpaqueToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Hash an opaque token for at-rest storage. We fold a server-side pepper
 * into the hash so a leaked DB row alone cannot be replayed without also
 * stealing the pepper from process memory / env.
 */
export function hashOpaqueToken(token: string): string {
  return createHash('sha256').update(`${env.refreshTokenPepper}|${token}`).digest('hex');
}

/**
 * Constant-time-style comparison helper. Both inputs are short (64-char hex)
 * so the standard equality check is acceptable; centralised here so we have
 * one place to harden if the threat model ever changes.
 */
export function timingSafeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i += 1) {
    r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return r === 0;
}
