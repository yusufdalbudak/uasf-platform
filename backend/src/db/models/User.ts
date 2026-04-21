import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Identity record. Holds the minimum personal data required to authenticate
 * the user; operational data (campaigns, runs, evidence, ...) is intentionally
 * NOT linked here so identity and operational concerns can evolve separately.
 *
 * Compliance posture (GDPR / KVKK):
 *   - Data minimization: only `email`, optional `displayName`, and the
 *     password hash are stored. No phone numbers, addresses, etc.
 *   - Consent capture: `gdprConsentAt` + `gdprConsentVersion` record the
 *     exact terms the user accepted at signup.
 *   - Right to erasure: deleting this row cascades all auth-related rows
 *     (sessions, password reset tokens, email verification tokens) via
 *     foreign-key ON DELETE CASCADE.
 *   - The `passwordHash` is NEVER returned by the API — `userService.toPublic()`
 *     strips it before serialisation.
 */
export type UserRole = 'admin' | 'operator' | 'viewer';
export type UserStatus = 'active' | 'disabled' | 'pending_verification';

@Entity('auth_users')
@Index(['email'], { unique: true })
@Index(['status'])
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Lower-cased, validated. Unique within the system. */
  @Column({ type: 'varchar', length: 320 })
  email: string;

  /** bcrypt hash (cost 12). NEVER serialised. */
  @Column({ type: 'varchar', length: 255 })
  passwordHash: string;

  /** Optional friendly name; falls back to the email local-part. */
  @Column({ type: 'varchar', length: 128, nullable: true })
  displayName: string | null;

  /** RBAC role; default 'viewer'. Only `admin` users can promote others. */
  @Column({ type: 'varchar', length: 16, default: 'viewer' })
  role: UserRole;

  /** Lifecycle status. `pending_verification` blocks login until email confirmed. */
  @Column({ type: 'varchar', length: 32, default: 'active' })
  status: UserStatus;

  /** True once the user has clicked the verification link. */
  @Column({ type: 'boolean', default: false })
  emailVerified: boolean;

  @Column({ type: 'timestamptz', nullable: true })
  lastLoginAt: Date | null;

  /** Counter incremented on every failed login; reset on success. */
  @Column({ type: 'int', default: 0 })
  failedLoginAttempts: number;

  /** When set, login is blocked until this timestamp passes. */
  @Column({ type: 'timestamptz', nullable: true })
  lockedUntil: Date | null;

  /** ISO timestamp the user accepted the privacy notice. */
  @Column({ type: 'timestamptz', nullable: true })
  gdprConsentAt: Date | null;

  /**
   * Privacy-policy version accepted at signup. Bump the constant on the
   * server when terms change so we can re-prompt for consent.
   */
  @Column({ type: 'varchar', length: 16, nullable: true })
  gdprConsentVersion: string | null;

  /**
   * Bumped on password change / role change so existing access tokens carrying
   * an older `tokenVersion` claim are silently invalidated.
   */
  @Column({ type: 'int', default: 0 })
  tokenVersion: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
