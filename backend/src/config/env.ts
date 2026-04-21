import { config } from 'dotenv';

config();

function parseIntEnv(name: string, fallback: string): number {
  const raw = process.env[name] ?? fallback;
  const n = parseInt(String(raw), 10);
  if (Number.isNaN(n) || n < 0) {
    throw new Error(`Invalid integer for ${name}: ${raw}`);
  }
  return n;
}

function requireNonEmpty(name: string): string {
  const v = process.env[name];
  if (v === undefined || String(v).trim() === '') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return String(v).trim();
}

/**
 * Validated process environment. Import this module before creating DB/Redis clients
 * so configuration fails fast at startup.
 */
export const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseIntEnv('PORT', '3000'),
  host: (process.env.HOST || '0.0.0.0').trim(),
  databaseUrl: requireNonEmpty('DATABASE_URL'),
  redisHost: (process.env.REDIS_HOST || 'localhost').trim(),
  redisPort: parseIntEnv('REDIS_PORT', '6379'),
  /** Comma-separated hostnames and AppTrana-style labels (e.g. host_API) permitted for outbound validation */
  allowedTargets: requireNonEmpty('ALLOWED_TARGETS'),
  safetyMaxConcurrency: parseIntEnv('SAFETY_MAX_CONCURRENCY', '5'),
  safetyMaxRps: parseIntEnv('SAFETY_MAX_RPS', '50'),
  serviceName: (process.env.SERVICE_NAME || 'UASF — Universal Attack Simulation Framework').trim(),
  serviceVersion: (process.env.SERVICE_VERSION || '1.0.0').trim(),
  databaseSynchronize:
    process.env.DB_SYNCHRONIZE === 'true' ||
    (process.env.DB_SYNCHRONIZE === undefined && (process.env.NODE_ENV || 'development') === 'development'),
  /**
   * When true (default), executable workflows require a registry row with approval.
   * Set to false only for legacy demos without a populated asset registry.
   */
  requireRegisteredAsset: process.env.REQUIRE_REGISTERED_ASSET !== 'false',
  /**
   * Optional VirusTotal Public API v3 key. When unset, the /api/virustotal/*
   * routes return HTTP 503 and the frontend falls back to opening
   * virustotal.com in a new tab.
   */
  virustotalApiKey: (process.env.VIRUSTOTAL_API_KEY || '').trim() || null,
  /**
   * Optional abuse.ch unified Auth-Key. ONE key authenticates ThreatFox,
   * URLhaus, and MalwareBazaar. When unset, those providers are skipped by
   * /api/lookup/multi and reported as "not_configured" via /api/lookup/status.
   * Get a free key at https://auth.abuse.ch/.
   */
  abuseChAuthKey: (process.env.ABUSE_CH_AUTH_KEY || '').trim() || null,

  // -----------------------------------------------------------------
  // IAM / authentication configuration.
  // -----------------------------------------------------------------

  /**
   * HMAC secret used to sign short-lived access JWTs. MUST be at least 32
   * bytes of high-entropy data in production. A random value is generated at
   * boot when unset so dev environments still work; production deployments
   * must pin this so tokens survive restarts.
   */
  jwtAccessSecret:
    (process.env.JWT_ACCESS_SECRET || '').trim() ||
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('crypto').randomBytes(48).toString('hex'),

  /**
   * Extra pepper folded into refresh-token hashes so a leaked DB plus a
   * leaked refresh cookie still doesn't let an attacker forge new tokens
   * without also stealing this server-side secret.
   */
  refreshTokenPepper:
    (process.env.REFRESH_TOKEN_PEPPER || '').trim() ||
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('crypto').randomBytes(32).toString('hex'),

  /** Access token TTL in seconds (default 15 minutes). */
  accessTokenTtlSec: parseIntEnv('ACCESS_TOKEN_TTL_SEC', '900'),
  /** Refresh token TTL in seconds (default 14 days). */
  refreshTokenTtlSec: parseIntEnv('REFRESH_TOKEN_TTL_SEC', String(60 * 60 * 24 * 14)),

  /** Password reset token TTL in seconds (default 60 minutes). */
  passwordResetTtlSec: parseIntEnv('PASSWORD_RESET_TTL_SEC', '3600'),
  /** Email verification token TTL in seconds (default 24 hours). */
  emailVerificationTtlSec: parseIntEnv('EMAIL_VERIFICATION_TTL_SEC', '86400'),

  /**
   * When true (default), every protected route requires a valid access token.
   * Setting this to false bypasses authentication entirely; reserved for
   * legacy demos and never recommended in production.
   */
  authRequired: process.env.AUTH_REQUIRED !== 'false',

  /**
   * When true (default), the signup flow creates accounts in
   * `pending_verification` and blocks login until the user clicks the
   * verification link. Disable in trusted-network deployments where SMTP
   * is unavailable.
   */
  requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFICATION === 'true',

  /**
   * Allowed origin(s) for the frontend. Used to restrict CORS so cookies are
   * only ever sent from the legitimate web app(s). Accepts a single origin or
   * a comma-separated list (e.g. production + Vercel preview URL). Defaults
   * to the Vite dev server in development; REQUIRED in production.
   *
   * Example:
   *   FRONTEND_ORIGIN=https://uasf.example.com,https://uasf-preview.vercel.app
   */
  frontendOrigin: (() => {
    const raw = (process.env.FRONTEND_ORIGIN || '').trim();
    if (raw) return raw;
    if ((process.env.NODE_ENV || 'development') === 'production') {
      throw new Error(
        'Missing required environment variable in production: FRONTEND_ORIGIN ' +
          '(set it to the deployed web origin(s), comma-separated; cookies and CORS depend on this).',
      );
    }
    return 'http://localhost:5173';
  })(),

  /**
   * Derived list of allowed origins (lowercase, no trailing slash).
   */
  frontendOrigins: (() => {
    const raw = (process.env.FRONTEND_ORIGIN || '').trim() || 'http://localhost:5173';
    return raw
      .split(',')
      .map((s) => s.trim().replace(/\/$/, ''))
      .filter((s) => s.length > 0);
  })(),

  /**
   * Bootstraps a single admin user when no users exist in the DB. Disable
   * by leaving either value blank.
   */
  bootstrapAdminEmail: (process.env.BOOTSTRAP_ADMIN_EMAIL || '').trim() || null,
  bootstrapAdminPassword: (process.env.BOOTSTRAP_ADMIN_PASSWORD || '').trim() || null,

  /**
   * Privacy-policy version that the signup form presents. Bump this constant
   * when the privacy notice changes; existing users will be re-prompted to
   * re-consent on next login.
   */
  privacyPolicyVersion: (process.env.PRIVACY_POLICY_VERSION || '2026-04-19').trim(),

  /** Lock account for this many seconds after `loginMaxFailedAttempts`. */
  loginLockoutSec: parseIntEnv('LOGIN_LOCKOUT_SEC', '900'),
  loginMaxFailedAttempts: parseIntEnv('LOGIN_MAX_FAILED_ATTEMPTS', '8'),

  /**
   * Marks refresh-token cookies `Secure`. Defaults to true in production;
   * defaults to false in development so plain-HTTP `localhost` works.
   * Override explicitly with COOKIE_SECURE=true|false.
   */
  cookieSecure:
    process.env.COOKIE_SECURE === 'true' ||
    (process.env.COOKIE_SECURE !== 'false' && (process.env.NODE_ENV || 'development') !== 'development'),
} as const;
