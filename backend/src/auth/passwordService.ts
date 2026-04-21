import bcrypt from 'bcryptjs';

/**
 * Password hashing & strength helpers.
 *
 * Hash algorithm: bcrypt at cost factor 12 (~250 ms on modern hardware).
 * Cost is the work parameter the OWASP password-storage cheat sheet
 * recommends for bcrypt; bumping it is a one-line change here.
 *
 * argon2id would be marginally stronger but requires native compilation,
 * which adds friction in the project's alpine container. bcrypt at cost 12
 * is well above the OWASP minimum and is what most production stacks ship.
 */

const BCRYPT_COST = 12;

/** Bcrypt has a 72-byte input limit; longer values are silently truncated. */
const MAX_PASSWORD_BYTES = 72;
const MIN_PASSWORD_LENGTH = 12;

export interface PasswordStrength {
  ok: boolean;
  reason?: string;
}

/**
 * Validates a candidate password against a baseline policy:
 *   - Minimum 12 characters (NIST SP 800-63B advises length over complexity).
 *   - At least one lowercase, one uppercase, one digit, OR length >= 16.
 *   - Disallow whitespace-only / repeated-character / obviously-trivial values.
 */
export function checkPasswordStrength(password: string): PasswordStrength {
  if (typeof password !== 'string') {
    return { ok: false, reason: 'Password must be a string.' };
  }
  const len = password.length;
  if (len < MIN_PASSWORD_LENGTH) {
    return { ok: false, reason: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
  }
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
    return { ok: false, reason: 'Password is too long (max 72 bytes).' };
  }
  if (/^\s+$/.test(password)) {
    return { ok: false, reason: 'Password cannot be whitespace only.' };
  }
  // Reject ten or more identical consecutive characters ("aaaaaaaaaaaa").
  if (/^(.)\1{9,}$/.test(password)) {
    return { ok: false, reason: 'Password is too repetitive.' };
  }
  // Length-based bypass: very long passphrases are accepted without
  // composition rules per NIST guidance.
  if (len >= 16) return { ok: true };
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  if (!(hasLower && hasUpper && hasDigit)) {
    return {
      ok: false,
      reason:
        'Password must contain at least one lowercase letter, one uppercase letter, and one digit (or be 16+ characters).',
    };
  }
  return { ok: true };
}

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, BCRYPT_COST);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  if (!plain || !hash) return false;
  try {
    return await bcrypt.compare(plain, hash);
  } catch {
    return false;
  }
}

/**
 * Constant-time-equivalent dummy verification. Used in the login path to
 * make response-times for known/unknown emails indistinguishable.
 */
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password-but-still-checked', BCRYPT_COST);

export async function dummyVerify(): Promise<void> {
  await bcrypt.compare('not-a-real-password-but-still-checked', DUMMY_HASH);
}
