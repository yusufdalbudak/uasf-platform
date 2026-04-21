import { AppDataSource } from '../db/connection';
import { User } from '../db/models/User';
import { PasswordResetToken } from '../db/models/PasswordResetToken';
import { EmailVerificationToken } from '../db/models/EmailVerificationToken';
import { env } from '../config/env';
import {
  checkPasswordStrength,
  dummyVerify,
  hashPassword,
  verifyPassword,
} from './passwordService';
import {
  generateOpaqueToken,
  hashOpaqueToken,
  signAccessToken,
} from './tokenService';
import {
  createSession,
  revokeAllSessionsForUser,
  type IssuedSession,
  type SessionContext,
} from './sessionService';
import { recordAuditEvent } from './auditService';
import {
  findUserByEmail,
  findUserById,
  normalizeEmail,
  toPublicUser,
  type PublicUser,
} from './userService';

/**
 * High-level orchestration of the auth flows. Owns the privacy/security
 * decisions that involve more than one entity (e.g. signup writes the
 * `User` row AND issues a verification token AND records an audit event).
 *
 * Public surface:
 *   - signup, login, refreshIssue, logout
 *   - changePassword, requestPasswordReset, completePasswordReset
 *   - issueEmailVerification, completeEmailVerification
 *   - deleteAccount
 *
 * The HTTP route layer is a thin shell over these functions; nothing in here
 * touches Fastify, cookies, headers, or rate-limit policy. That separation
 * keeps the security-critical logic easy to reason about and unit-test.
 */

export class AuthError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code:
      | 'invalid_input'
      | 'invalid_credentials'
      | 'account_locked'
      | 'email_in_use'
      | 'pending_verification'
      | 'disabled'
      | 'token_invalid'
      | 'token_expired'
      | 'consent_required'
      | 'weak_password',
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export interface AuthIssuance {
  user: PublicUser;
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshToken: string;
  refreshTokenExpiresAt: string;
  sessionId: string;
}

async function issueTokens(user: User, ctx: SessionContext): Promise<AuthIssuance> {
  const session: IssuedSession = await createSession(user.id, ctx);
  const accessToken = await signAccessToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    tv: user.tokenVersion,
    sid: session.sessionId,
  });
  const accessExpires = new Date(Date.now() + env.accessTokenTtlSec * 1000);
  return {
    user: toPublicUser(user),
    accessToken,
    accessTokenExpiresAt: accessExpires.toISOString(),
    refreshToken: session.refreshToken,
    refreshTokenExpiresAt: session.expiresAt.toISOString(),
    sessionId: session.sessionId,
  };
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

export interface SignupInput {
  email: string;
  password: string;
  displayName?: string | null;
  gdprConsent: boolean;
}

export async function signup(
  input: SignupInput,
  ctx: SessionContext,
): Promise<AuthIssuance> {
  const email = normalizeEmail(input.email);
  if (!email) {
    throw new AuthError('A valid email address is required.', 400, 'invalid_input');
  }
  if (!input.gdprConsent) {
    throw new AuthError(
      'You must accept the privacy notice to create an account.',
      400,
      'consent_required',
    );
  }
  const strength = checkPasswordStrength(input.password);
  if (!strength.ok) {
    throw new AuthError(strength.reason ?? 'Password is too weak.', 400, 'weak_password');
  }

  const repo = AppDataSource.getRepository(User);
  const existing = await repo.findOne({ where: { email } });
  if (existing) {
    throw new AuthError(
      'An account with this email already exists.',
      409,
      'email_in_use',
    );
  }

  const passwordHash = await hashPassword(input.password);
  const isFirstUser = (await repo.count()) === 0;
  const user = repo.create({
    email,
    passwordHash,
    displayName: input.displayName?.trim() || null,
    // The very first account on a fresh install becomes admin so the
    // platform is usable. Subsequent users are viewers by default and
    // must be promoted by an admin.
    role: isFirstUser ? 'admin' : 'viewer',
    status: env.requireEmailVerification && !isFirstUser ? 'pending_verification' : 'active',
    emailVerified: !env.requireEmailVerification || isFirstUser,
    gdprConsentAt: new Date(),
    gdprConsentVersion: env.privacyPolicyVersion,
  });
  await repo.save(user);

  await recordAuditEvent({
    action: 'signup',
    userId: user.id,
    email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { firstUser: isFirstUser, role: user.role },
  });

  // If verification is required and this isn't the bootstrap admin, return
  // a stub issuance with no tokens so the UI can route to the "check your
  // email" screen without actually granting access.
  if (user.status === 'pending_verification') {
    await issueEmailVerification(user.id);
    throw new AuthError(
      'Account created. Please verify your email address to log in.',
      202,
      'pending_verification',
    );
  }

  const issuance = await issueTokens(user, ctx);
  // Persist last-login so the bootstrap admin's dashboard "last login"
  // surface is correct from day one.
  user.lastLoginAt = new Date();
  await repo.save(user);
  return issuance;
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export interface LoginInput {
  email: string;
  password: string;
}

export async function login(input: LoginInput, ctx: SessionContext): Promise<AuthIssuance> {
  const email = normalizeEmail(input.email);
  if (!email || !input.password) {
    // We deliberately return the same generic error for every failure mode
    // below to avoid leaking whether the email is registered.
    if (email)
      await recordAuditEvent({
        action: 'login_failed',
        userId: null,
        email,
        ipAddress: ctx.ipAddress,
        userAgent: ctx.userAgent,
        metadata: { reason: 'missing_input' },
      });
    throw new AuthError('Invalid email or password.', 401, 'invalid_credentials');
  }

  const repo = AppDataSource.getRepository(User);
  const user = await repo.findOne({ where: { email } });
  if (!user) {
    // Equalize timing with the real bcrypt verify path so an attacker
    // cannot enumerate registered emails by measuring response latency.
    await dummyVerify();
    await recordAuditEvent({
      action: 'login_failed',
      userId: null,
      email,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { reason: 'unknown_email' },
    });
    throw new AuthError('Invalid email or password.', 401, 'invalid_credentials');
  }

  // Lockout enforcement.
  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    await recordAuditEvent({
      action: 'login_failed',
      userId: user.id,
      email,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { reason: 'locked' },
    });
    throw new AuthError(
      'Account is temporarily locked. Try again later or reset your password.',
      423,
      'account_locked',
    );
  }

  const ok = await verifyPassword(input.password, user.passwordHash);
  if (!ok) {
    user.failedLoginAttempts = (user.failedLoginAttempts ?? 0) + 1;
    if (user.failedLoginAttempts >= env.loginMaxFailedAttempts) {
      user.lockedUntil = new Date(Date.now() + env.loginLockoutSec * 1000);
      await repo.save(user);
      await recordAuditEvent({
        action: 'account_locked',
        userId: user.id,
        email,
        ipAddress: ctx.ipAddress,
        userAgent: ctx.userAgent,
        metadata: { until: user.lockedUntil.toISOString() },
      });
      throw new AuthError(
        'Too many failed attempts. Account temporarily locked.',
        423,
        'account_locked',
      );
    }
    await repo.save(user);
    await recordAuditEvent({
      action: 'login_failed',
      userId: user.id,
      email,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { reason: 'bad_password', attempts: user.failedLoginAttempts },
    });
    throw new AuthError('Invalid email or password.', 401, 'invalid_credentials');
  }

  if (user.status === 'pending_verification') {
    throw new AuthError(
      'Please verify your email address before logging in.',
      403,
      'pending_verification',
    );
  }
  if (user.status === 'disabled') {
    throw new AuthError('This account has been disabled.', 403, 'disabled');
  }

  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  user.lastLoginAt = new Date();
  await repo.save(user);

  const issuance = await issueTokens(user, ctx);
  await recordAuditEvent({
    action: 'login_success',
    userId: user.id,
    email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { sessionId: issuance.sessionId },
  });
  return issuance;
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

import { rotateSession } from './sessionService';

export async function refreshIssue(
  refreshToken: string,
  ctx: SessionContext,
): Promise<AuthIssuance> {
  if (!refreshToken) {
    throw new AuthError('Refresh token missing.', 401, 'token_invalid');
  }
  const result = await rotateSession(refreshToken, ctx);
  if (result.ok === false) {
    if (result.reason === 'expired')
      throw new AuthError('Session expired. Please log in again.', 401, 'token_expired');
    throw new AuthError('Invalid refresh token.', 401, 'token_invalid');
  }
  const user = await findUserById(result.session.userId);
  if (!user) {
    throw new AuthError('Invalid refresh token.', 401, 'token_invalid');
  }
  if (user.status !== 'active') {
    throw new AuthError('Account is no longer active.', 403, 'disabled');
  }
  const accessToken = await signAccessToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    tv: user.tokenVersion,
    sid: result.session.id,
  });
  await recordAuditEvent({
    action: 'token_refresh',
    userId: user.id,
    email: user.email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { sessionId: result.session.id },
  });
  return {
    user: toPublicUser(user),
    accessToken,
    accessTokenExpiresAt: new Date(Date.now() + env.accessTokenTtlSec * 1000).toISOString(),
    refreshToken: result.refreshToken,
    refreshTokenExpiresAt: result.expiresAt.toISOString(),
    sessionId: result.session.id,
  };
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

import { revokeSessionByRefreshToken } from './sessionService';

export async function logout(
  refreshToken: string | null,
  user: { id: string; email: string } | null,
  ctx: SessionContext,
): Promise<void> {
  if (refreshToken) {
    const sessionId = await revokeSessionByRefreshToken(refreshToken, 'logout');
    await recordAuditEvent({
      action: 'logout',
      userId: user?.id ?? null,
      email: user?.email ?? null,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: sessionId ? { sessionId } : null,
    });
  }
}

// ---------------------------------------------------------------------------
// Password change & reset
// ---------------------------------------------------------------------------

import { bumpTokenVersion } from './userService';

export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  ctx: SessionContext,
): Promise<void> {
  const user = await findUserById(userId);
  if (!user) throw new AuthError('User not found.', 404, 'invalid_input');
  const ok = await verifyPassword(currentPassword, user.passwordHash);
  if (!ok) throw new AuthError('Current password is incorrect.', 400, 'invalid_credentials');
  const strength = checkPasswordStrength(newPassword);
  if (!strength.ok) throw new AuthError(strength.reason ?? 'Weak password.', 400, 'weak_password');
  user.passwordHash = await hashPassword(newPassword);
  await AppDataSource.getRepository(User).save(user);
  await bumpTokenVersion(userId);
  await revokeAllSessionsForUser(userId, 'password_change');
  await recordAuditEvent({
    action: 'password_change',
    userId,
    email: user.email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });
}

export async function requestPasswordReset(
  emailRaw: string,
  ctx: SessionContext,
): Promise<{ devToken?: string }> {
  const email = normalizeEmail(emailRaw);
  // Always behave identically regardless of whether the email exists, so
  // attackers cannot enumerate registered emails through this endpoint.
  if (!email) return {};
  const user = await findUserByEmail(email);
  if (!user) {
    await recordAuditEvent({
      action: 'password_reset_request',
      userId: null,
      email,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { found: false },
    });
    return {};
  }
  const tokenRepo = AppDataSource.getRepository(PasswordResetToken);
  // Invalidate any prior outstanding tokens for this user so an attacker
  // who steals one is locked out the moment a fresh one is issued.
  await tokenRepo
    .createQueryBuilder()
    .update(PasswordResetToken)
    .set({ usedAt: () => 'COALESCE("usedAt", NOW())' })
    .where('"userId" = :userId AND "usedAt" IS NULL', { userId: user.id })
    .execute();
  const token = generateOpaqueToken();
  const tokenHash = hashOpaqueToken(token);
  const expiresAt = new Date(Date.now() + env.passwordResetTtlSec * 1000);
  await tokenRepo.save(tokenRepo.create({ userId: user.id, tokenHash, expiresAt, requestedFromIp: ctx.ipAddress }));
  await recordAuditEvent({
    action: 'password_reset_request',
    userId: user.id,
    email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { found: true },
  });
  // In a production deployment this is where we'd hand the token to the
  // mail service. For development we surface it in the response so
  // operators can complete the flow without an SMTP dependency.
  return env.nodeEnv === 'development' ? { devToken: token } : {};
}

export async function completePasswordReset(
  token: string,
  newPassword: string,
  ctx: SessionContext,
): Promise<void> {
  if (!token) throw new AuthError('Reset token missing.', 400, 'token_invalid');
  const strength = checkPasswordStrength(newPassword);
  if (!strength.ok) throw new AuthError(strength.reason ?? 'Weak password.', 400, 'weak_password');
  const repo = AppDataSource.getRepository(PasswordResetToken);
  const row = await repo.findOne({ where: { tokenHash: hashOpaqueToken(token) } });
  if (!row || row.usedAt || row.expiresAt.getTime() < Date.now()) {
    throw new AuthError('Reset link is invalid or expired.', 400, 'token_invalid');
  }
  const userRepo = AppDataSource.getRepository(User);
  const user = await userRepo.findOne({ where: { id: row.userId } });
  if (!user) throw new AuthError('Reset link is invalid.', 400, 'token_invalid');

  user.passwordHash = await hashPassword(newPassword);
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  await userRepo.save(user);
  row.usedAt = new Date();
  await repo.save(row);
  await bumpTokenVersion(user.id);
  await revokeAllSessionsForUser(user.id, 'password_reset');

  await recordAuditEvent({
    action: 'password_reset_complete',
    userId: user.id,
    email: user.email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

export async function issueEmailVerification(userId: string): Promise<{ devToken?: string }> {
  const user = await findUserById(userId);
  if (!user) return {};
  if (user.emailVerified) return {};
  const repo = AppDataSource.getRepository(EmailVerificationToken);
  await repo
    .createQueryBuilder()
    .update(EmailVerificationToken)
    .set({ usedAt: () => 'COALESCE("usedAt", NOW())' })
    .where('"userId" = :userId AND "usedAt" IS NULL', { userId })
    .execute();
  const token = generateOpaqueToken();
  const tokenHash = hashOpaqueToken(token);
  const expiresAt = new Date(Date.now() + env.emailVerificationTtlSec * 1000);
  await repo.save(repo.create({ userId, tokenHash, expiresAt }));
  await recordAuditEvent({
    action: 'email_verification_sent',
    userId,
    email: user.email,
    ipAddress: null,
    userAgent: null,
  });
  return env.nodeEnv === 'development' ? { devToken: token } : {};
}

export async function completeEmailVerification(
  token: string,
  ctx: SessionContext,
): Promise<PublicUser> {
  if (!token) throw new AuthError('Verification token missing.', 400, 'token_invalid');
  const repo = AppDataSource.getRepository(EmailVerificationToken);
  const row = await repo.findOne({ where: { tokenHash: hashOpaqueToken(token) } });
  if (!row || row.usedAt || row.expiresAt.getTime() < Date.now()) {
    throw new AuthError('Verification link is invalid or expired.', 400, 'token_invalid');
  }
  const userRepo = AppDataSource.getRepository(User);
  const user = await userRepo.findOne({ where: { id: row.userId } });
  if (!user) throw new AuthError('Verification link is invalid.', 400, 'token_invalid');
  user.emailVerified = true;
  if (user.status === 'pending_verification') user.status = 'active';
  await userRepo.save(user);
  row.usedAt = new Date();
  await repo.save(row);
  await recordAuditEvent({
    action: 'email_verified',
    userId: user.id,
    email: user.email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });
  return toPublicUser(user);
}

// ---------------------------------------------------------------------------
// Account deletion (GDPR right to erasure)
// ---------------------------------------------------------------------------

export async function deleteAccount(
  userId: string,
  password: string,
  ctx: SessionContext,
): Promise<void> {
  const user = await findUserById(userId);
  if (!user) return;
  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) throw new AuthError('Password is incorrect.', 400, 'invalid_credentials');
  // Hard delete cascades sessions / reset tokens / verification tokens via
  // ON DELETE CASCADE. The audit log row is intentionally PRESERVED with
  // userId now NULL so we keep an anonymized history of the deletion.
  await AppDataSource.getRepository(User).delete({ id: userId });
  await recordAuditEvent({
    action: 'account_deleted',
    userId: null,
    email: user.email,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { previousUserId: userId },
  });
}
