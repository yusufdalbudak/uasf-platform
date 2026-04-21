import { AppDataSource } from '../db/connection';
import { User, type UserRole } from '../db/models/User';

/**
 * User-record helpers. Centralises lookup, normalisation, and the
 * password-stripping serializer so no API code accidentally returns the hash.
 */

const EMAIL_REGEX = /^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/i;

export function normalizeEmail(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const v = raw.trim().toLowerCase();
  if (!v || v.length > 320) return null;
  if (!EMAIL_REGEX.test(v)) return null;
  return v;
}

export interface PublicUser {
  id: string;
  email: string;
  displayName: string | null;
  role: UserRole;
  emailVerified: boolean;
  status: string;
  createdAt: string;
  lastLoginAt: string | null;
  gdprConsentVersion: string | null;
  gdprConsentAt: string | null;
}

export function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    role: user.role,
    emailVerified: user.emailVerified,
    status: user.status,
    createdAt: user.createdAt.toISOString(),
    lastLoginAt: user.lastLoginAt ? user.lastLoginAt.toISOString() : null,
    gdprConsentVersion: user.gdprConsentVersion,
    gdprConsentAt: user.gdprConsentAt ? user.gdprConsentAt.toISOString() : null,
  };
}

export async function findUserByEmail(email: string): Promise<User | null> {
  const repo = AppDataSource.getRepository(User);
  return repo.findOne({ where: { email } });
}

export async function findUserById(id: string): Promise<User | null> {
  const repo = AppDataSource.getRepository(User);
  return repo.findOne({ where: { id } });
}

export async function countUsers(): Promise<number> {
  const repo = AppDataSource.getRepository(User);
  return repo.count();
}

/** Bumps tokenVersion so existing access tokens are silently invalidated. */
export async function bumpTokenVersion(userId: string): Promise<void> {
  const repo = AppDataSource.getRepository(User);
  await repo
    .createQueryBuilder()
    .update(User)
    .set({ tokenVersion: () => '"tokenVersion" + 1' })
    .where('id = :id', { id: userId })
    .execute();
}
