import { AppDataSource } from '../db/connection';
import { User } from '../db/models/User';
import { env } from '../config/env';
import { hashPassword, checkPasswordStrength } from './passwordService';
import { normalizeEmail } from './userService';
import { recordAuditEvent } from './auditService';

/**
 * Idempotent bootstrap of the very first admin account.
 *
 * Triggered at startup:
 *   - Does nothing if any user already exists (so we never silently
 *     re-create an admin that someone has already configured).
 *   - Does nothing if BOOTSTRAP_ADMIN_EMAIL or BOOTSTRAP_ADMIN_PASSWORD
 *     are not set.
 *
 * The first user is also marked emailVerified=true so the operator can log in
 * without bouncing through the verification flow on a fresh install.
 */
export async function bootstrapAdminUser(): Promise<void> {
  const email = env.bootstrapAdminEmail ? normalizeEmail(env.bootstrapAdminEmail) : null;
  const password = env.bootstrapAdminPassword;
  if (!email || !password) {
    console.log(
      '[auth] BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD not set — skipping admin bootstrap. ' +
        'Sign up at /signup; the FIRST account becomes admin automatically.',
    );
    return;
  }
  const repo = AppDataSource.getRepository(User);
  const existing = await repo.count();
  if (existing > 0) {
    console.log(`[auth] ${existing} user(s) already exist — skipping admin bootstrap.`);
    return;
  }
  const strength = checkPasswordStrength(password);
  if (!strength.ok) {
    console.warn(
      `[auth] BOOTSTRAP_ADMIN_PASSWORD rejected by password policy: ${strength.reason} — skipping bootstrap.`,
    );
    return;
  }
  const passwordHash = await hashPassword(password);
  const user = repo.create({
    email,
    passwordHash,
    displayName: 'Platform Administrator',
    role: 'admin',
    status: 'active',
    emailVerified: true,
    gdprConsentAt: new Date(),
    gdprConsentVersion: env.privacyPolicyVersion,
  });
  await repo.save(user);
  await recordAuditEvent({
    action: 'signup',
    userId: user.id,
    email: user.email,
    ipAddress: null,
    userAgent: 'system:bootstrap',
    metadata: { source: 'bootstrap_admin', role: 'admin' },
  });
  console.log(`[auth] Bootstrap admin created: ${email}`);
}
