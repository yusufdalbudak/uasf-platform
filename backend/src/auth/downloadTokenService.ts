/**
 * UASF Download Token Service
 *
 * Some artifacts (rendered reports) are intentionally rendered into the
 * browser tab itself: PDFs render inline with the OS preview, HTML reports
 * open in a new tab so the operator can scroll and print.  Both flows
 * navigate the browser directly to the API URL — at which point the
 * `Authorization: Bearer ...` header that `apiFetchJson` normally adds is
 * NOT present, and the global authPlugin returns a raw `AUTH_REQUIRED`
 * JSON body in the new tab.  That's terrible UX and looks like a security
 * defect to operators.
 *
 * The fix is the standard "signed URL" pattern used by S3, GCS, etc.:
 *
 *   1. The frontend, while still authenticated, calls
 *      `POST /api/downloads/sign` with the absolute API path it wants to
 *      open.
 *
 *   2. The backend validates the path against an allowlist of resource
 *      patterns (so an attacker holding the signing secret still can't
 *      arbitrary-route into anything but the listed read endpoints), and
 *      returns a short-lived HMAC-signed token bound to:
 *         - the exact path
 *         - the issuing user id
 *         - an expiry timestamp
 *
 *   3. The frontend appends `?dlt=<token>` to the URL and opens it.  The
 *      authPlugin recognises this token, verifies the HMAC, validates the
 *      path matches the signed scope, and synthesises an authenticated
 *      request.user from the embedded claims.
 *
 * This keeps:
 *   - cookie auth out of the surface (we already use Bearer-only),
 *   - direct-link previews working (so PDFs render inline),
 *   - no AUTH_REQUIRED tab-fail for the operator.
 *
 * The token is a single JSON document, base64url-encoded, with a separate
 * base64url HMAC-SHA-256 over the canonical claims string.  Format:
 *
 *     <base64url(JSON claims)>.<base64url(HMAC)>
 */

import { createHmac, timingSafeEqual } from 'crypto';
import { env } from '../config/env';

const SIGNING_SECRET = (): Buffer =>
  Buffer.from(env.refreshTokenPepper + ':download', 'utf8');

const DEFAULT_TTL_SEC = 5 * 60; // 5 minutes is plenty to open in a tab.
const MAX_TTL_SEC = 30 * 60;

/**
 * Allowlist of safe download paths, expressed as a regex over the path
 * (no query string).  ONLY paths matching one of these patterns may be
 * signed; everything else is refused at sign time.  Keep this list tight.
 */
const ALLOWED_PATH_PATTERNS: RegExp[] = [
  /^\/api\/reports\/[A-Za-z0-9-]{8,64}\/(html|pdf)$/,
  /^\/api\/tech-intel\/runs\/[A-Za-z0-9-]{8,64}\/report\.(html|pdf)$/,
  /^\/api\/easm\/report\.(html|pdf)$/,
];

export class DownloadTokenError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export interface DownloadTokenClaims {
  /** Path the token authorises, e.g. `/api/reports/<id>/pdf`. */
  p: string;
  /** Issuer user id. */
  u: string;
  /** Issued-at (epoch seconds). */
  iat: number;
  /** Expiry (epoch seconds). */
  exp: number;
}

export function isAllowedDownloadPath(path: string): boolean {
  return ALLOWED_PATH_PATTERNS.some((re) => re.test(path));
}

export function issueDownloadToken(opts: {
  path: string;
  userId: string;
  ttlSec?: number;
}): { token: string; expiresAt: number } {
  if (!isAllowedDownloadPath(opts.path)) {
    throw new DownloadTokenError(
      'DOWNLOAD_PATH_NOT_ALLOWED',
      'Refusing to sign: the requested path is not on the download allowlist.',
    );
  }
  const ttl = Math.min(Math.max(opts.ttlSec ?? DEFAULT_TTL_SEC, 30), MAX_TTL_SEC);
  const now = Math.floor(Date.now() / 1000);
  const claims: DownloadTokenClaims = {
    p: opts.path,
    u: opts.userId,
    iat: now,
    exp: now + ttl,
  };
  const claimsB64 = base64urlEncode(Buffer.from(JSON.stringify(claims), 'utf8'));
  const sig = sign(claimsB64);
  return { token: `${claimsB64}.${sig}`, expiresAt: claims.exp };
}

export function verifyDownloadToken(
  token: string,
  expectedPath: string,
): { ok: true; claims: DownloadTokenClaims } | { ok: false; reason: string } {
  if (!token || typeof token !== 'string') {
    return { ok: false, reason: 'missing token' };
  }
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) {
    return { ok: false, reason: 'malformed token' };
  }
  const claimsB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = sign(claimsB64);
  if (!constantTimeEquals(sig, expected)) {
    return { ok: false, reason: 'bad signature' };
  }
  let claims: DownloadTokenClaims;
  try {
    claims = JSON.parse(base64urlDecode(claimsB64).toString('utf8')) as DownloadTokenClaims;
  } catch {
    return { ok: false, reason: 'bad payload' };
  }
  if (typeof claims.p !== 'string' || typeof claims.u !== 'string' || typeof claims.exp !== 'number') {
    return { ok: false, reason: 'bad claims' };
  }
  if (claims.p !== expectedPath) {
    return { ok: false, reason: 'path mismatch' };
  }
  if (Math.floor(Date.now() / 1000) > claims.exp) {
    return { ok: false, reason: 'expired' };
  }
  return { ok: true, claims };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function sign(payloadB64: string): string {
  return base64urlEncode(createHmac('sha256', SIGNING_SECRET()).update(payloadB64).digest());
}

function base64urlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}
