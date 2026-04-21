import type { FastifyInstance, FastifyRequest, FastifyReply, preHandlerHookHandler } from 'fastify';
import fp from 'fastify-plugin';
import { env } from '../config/env';
import { verifyAccessToken } from './tokenService';
import { findUserById } from './userService';
import { isSessionLive } from './sessionService';
import { verifyDownloadToken } from './downloadTokenService';
import type { UserRole } from '../db/models/User';

/**
 * Authentication / authorization plugin.
 *
 * Wires three pieces:
 *
 *   1. A `preHandler` hook on every request that decodes the
 *      `Authorization: Bearer <token>` header (when present), validates the
 *      JWT signature/expiry/issuer/audience, confirms the underlying session
 *      row is still live, refreshes the user record from the DB, and
 *      attaches a typed `request.user` for downstream handlers.
 *
 *   2. A `request.user` decorator typed via Fastify module augmentation, so
 *      route code reads `request.user?.id` with autocomplete and never has
 *      to deal with the JWT directly.
 *
 *   3. Global enforcement: every route under `/api/*` requires authentication
 *      EXCEPT the public allowlist (auth endpoints themselves, health, ready,
 *      and a small set of operational probes).
 */

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  sessionId: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
    /** Populated by extractRefreshTokenCookie() — used by /auth/refresh + /auth/logout. */
    presentedRefreshToken?: string | null;
  }
  interface FastifyInstance {
    /**
     * Use as a preHandler to require an authenticated user. Replies 401 if
     * no valid token is present.
     */
    requireAuth: preHandlerHookHandler;
    /**
     * Returns a preHandler that requires the authenticated user to hold
     * one of the supplied roles. Use after `requireAuth` (or instead of it
     * — it implicitly enforces auth too).
     */
    requireRole: (roles: UserRole[]) => preHandlerHookHandler;
  }
}

/** Routes (path prefixes) that are accessible without a valid session. */
const PUBLIC_PATH_PREFIXES = [
  '/api/health',
  '/api/ready',
  '/api/auth/signup',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/refresh',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/verify-email',
  '/api/auth/csrf',
];

function isPublicRoute(url: string): boolean {
  // Strip query string before matching.
  const path = url.split('?')[0];
  return PUBLIC_PATH_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`));
}

function extractBearer(req: FastifyRequest): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return m ? m[1] : null;
}

export const REFRESH_COOKIE_NAME = 'uasf_refresh';

function extractRefreshCookie(req: FastifyRequest): string | null {
  // @fastify/cookie populates req.cookies.
  const cookies = (req as FastifyRequest & { cookies?: Record<string, string> }).cookies;
  if (!cookies) return null;
  const v = cookies[REFRESH_COOKIE_NAME];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

async function authPluginImpl(server: FastifyInstance): Promise<void> {
  // Always extract the refresh cookie up front; routes can read it via
  // `request.presentedRefreshToken` without re-parsing.
  server.addHook('preHandler', async (request) => {
    request.presentedRefreshToken = extractRefreshCookie(request);
  });

  // Best-effort identity resolution: populates `request.user` whenever a
  // valid bearer token is present, but never blocks the request here. The
  // hard enforcement happens in the second hook below so the public routes
  // remain accessible.
  server.addHook('preHandler', async (request) => {
    const token = extractBearer(request);
    if (!token) return;
    const verify = await verifyAccessToken(token);
    if (!verify.ok) return;
    const user = await findUserById(verify.claims.sub);
    if (!user || user.status !== 'active') return;
    if (user.tokenVersion !== verify.claims.tv) return; // stale token
    if (!(await isSessionLive(verify.claims.sid))) return;
    request.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      sessionId: verify.claims.sid,
    };
  });

  // Download-token resolution.  When a `?dlt=` query param is present,
  // verify it is a valid HMAC-signed token bound to this exact path and
  // synthesise the request.user from the embedded user id.  This is
  // strictly read-only: the token grants access to exactly one URL for at
  // most a few minutes.
  server.addHook('preHandler', async (request) => {
    if (request.user) return; // bearer already won
    const url = request.url;
    const qIndex = url.indexOf('?');
    if (qIndex < 0) return;
    const path = url.slice(0, qIndex);
    // Cheap parse: look for dlt= without pulling in URLSearchParams cost
    // for every request.
    const tokenMatch = /[?&]dlt=([^&]+)/.exec(url);
    if (!tokenMatch) return;
    const result = verifyDownloadToken(decodeURIComponent(tokenMatch[1]), path);
    if (!result.ok) return;
    const user = await findUserById(result.claims.u);
    if (!user || user.status !== 'active') return;
    request.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      // Synthetic session id: download tokens don't have a refresh-session
      // backing them.  Downstream code that needs a real session id (e.g.
      // logout) should never run on a download-token request — these
      // endpoints are read-only and don't accept side effects.
      sessionId: `dlt:${result.claims.iat}`,
    };
  });

  // Hard enforcement: every non-public path requires `request.user`.
  server.addHook('preHandler', async (request, reply) => {
    if (!env.authRequired) return;
    if (!request.url.startsWith('/api/')) return;
    if (isPublicRoute(request.url)) return;
    if (!request.user) {
      return sendAuthRequired(request, reply);
    }
  });

  server.decorate('requireAuth', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return sendAuthRequired(request, reply);
    }
  });

  server.decorate('requireRole', (roles: UserRole[]) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.user) {
        return sendAuthRequired(request, reply);
      }
      if (!roles.includes(request.user.role)) {
        return reply.code(403).send({
          error: 'You do not have permission to perform this action.',
          code: 'AUTH_FORBIDDEN',
          requiredRoles: roles,
        });
      }
    };
  });
}

// ---------------------------------------------------------------------------
// AUTH_REQUIRED responder
// ---------------------------------------------------------------------------
//
// When a browser tab navigates directly to a protected GET endpoint (typically
// a report HTML/PDF link the operator copy-pasted into a fresh tab), the
// classic `{"error":"AUTH_REQUIRED"}` JSON body is rendered as raw text in the
// tab and looks like a hard backend failure.  We detect "this looks like a
// browser navigation that wants HTML back" and render a small friendly page
// instead.  JSON callers (any /api/* request that doesn't ask for HTML) keep
// the structured error envelope they already understand.
function wantsHtml(request: FastifyRequest): boolean {
  if (request.method !== 'GET') return false;
  const accept = request.headers['accept'];
  if (typeof accept !== 'string') return false;
  // Browsers send `text/html` first; XHR/fetch sends `application/json` or `*/*`.
  // We deliberately do NOT match on `*/*` so JSON clients still get JSON.
  return /text\/html\b/.test(accept);
}

function sendAuthRequired(request: FastifyRequest, reply: FastifyReply) {
  if (wantsHtml(request)) {
    const html = renderAuthRequiredHtml(request.url);
    return reply
      .code(401)
      .header('Content-Type', 'text/html; charset=utf-8')
      .header('Cache-Control', 'no-store')
      .send(html);
  }
  return reply.code(401).send({
    error: 'Authentication required.',
    code: 'AUTH_REQUIRED',
  });
}

function renderAuthRequiredHtml(originalUrl: string): string {
  // Escape the URL we echo back so a malicious caller can't XSS the page.
  const safeUrl = String(originalUrl).replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      case "'":
        return '&#39;';
      default:
        return ch;
    }
  });
  // We deliberately render a small, self-contained page (no external assets,
  // no scripts) so it works in any browser preview pane.  The "Open in app"
  // link sends the user to the SPA root (`/`); the SPA's RouteGuards take
  // them through `/login` and back to whatever they were doing.
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>UASF — Sign in required</title>
    <meta name="robots" content="noindex,nofollow" />
    <meta name="referrer" content="no-referrer" />
    <style>
      :root { color-scheme: light dark; }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #0f1115;
        color: #e5e7eb;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
      }
      .card {
        max-width: 520px;
        width: 100%;
        background: #161922;
        border: 1px solid #2d333b;
        border-radius: 12px;
        padding: 28px 32px;
      }
      h1 {
        font-size: 18px;
        margin: 0 0 12px;
        color: #ffffff;
      }
      p {
        font-size: 14px;
        line-height: 1.5;
        color: #cbd5e1;
        margin: 0 0 12px;
      }
      .path {
        font-family: SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 12px;
        color: #94a3b8;
        background: #0f1115;
        border: 1px solid #2d333b;
        border-radius: 6px;
        padding: 8px 10px;
        margin: 12px 0 16px;
        word-break: break-all;
      }
      a.btn {
        display: inline-block;
        padding: 9px 14px;
        border-radius: 8px;
        background: #6a2bba;
        color: #ffffff;
        text-decoration: none;
        font-weight: 600;
        font-size: 14px;
      }
      a.btn:hover { background: #7c39d2; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Sign in required</h1>
      <p>
        This UASF resource is protected and can only be opened from inside an
        authenticated session.  The link you followed expired or was opened
        outside the console.
      </p>
      <div class="path">${safeUrl}</div>
      <p>
        Open the UASF console, sign in, and re-launch the report from the
        Tech Intelligence dashboard — the console mints a short-lived signed
        URL that lets your browser tab render the report directly.
      </p>
      <p>
        <a class="btn" href="/">Open the UASF console</a>
      </p>
    </div>
  </body>
</html>`;
}

// Wrap with fastify-plugin so the `requireAuth` / `requireRole` decorators
// and the global preHandler hooks live on the *root* server instance instead
// of being trapped inside this plugin's encapsulated child context.
export const authPlugin = fp(authPluginImpl, {
  name: 'uasf-auth-plugin',
  fastify: '4.x || 5.x',
});

/**
 * Builds a SessionContext (ip + user agent) from a Fastify request. Centralised
 * so the auth service receives a consistent shape.
 */
export function sessionContextFrom(req: FastifyRequest): {
  ipAddress: string | null;
  userAgent: string | null;
} {
  const fwd = req.headers['x-forwarded-for'];
  const ip =
    (typeof fwd === 'string' ? fwd.split(',')[0]?.trim() : Array.isArray(fwd) ? fwd[0] : '') ||
    req.ip ||
    null;
  const ua = req.headers['user-agent'];
  return {
    ipAddress: ip ? String(ip).slice(0, 64) : null,
    userAgent: typeof ua === 'string' ? ua.slice(0, 512) : null,
  };
}
