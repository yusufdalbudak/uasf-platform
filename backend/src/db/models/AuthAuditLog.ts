import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

/**
 * Append-only audit ledger for security-sensitive events.
 *
 * Every meaningful identity action (signup, login success/failure, logout,
 * password change/reset, role change, account deletion, session revoke)
 * writes one row here. Operators can review the ledger to spot brute-force,
 * suspicious geographies, etc.
 *
 * Privacy posture:
 *   - `userId` is NULL for failed logins where the email did not match a
 *     known account, so we do not leak the existence of an email through
 *     the audit log.
 *   - `email` is denormalised here (rather than via FK) so we retain the
 *     attempt-history even after the user exercises their right to erasure.
 */
export type AuthAuditAction =
  | 'signup'
  | 'login_success'
  | 'login_failed'
  | 'logout'
  | 'token_refresh'
  | 'token_refresh_reuse_detected'
  | 'password_change'
  | 'password_reset_request'
  | 'password_reset_complete'
  | 'email_verification_sent'
  | 'email_verified'
  | 'session_revoked'
  | 'account_deleted'
  | 'account_locked'
  | 'role_changed';

@Entity('auth_audit_log')
@Index(['userId'])
@Index(['action'])
export class AuthAuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Nullable: a failed login for an unknown email yields a row with userId=null. */
  @Column({ type: 'uuid', nullable: true })
  userId: string | null;

  /** Lower-cased email associated with the attempt (kept for forensic value). */
  @Column({ type: 'varchar', length: 320, nullable: true })
  email: string | null;

  @Column({ type: 'varchar', length: 64 })
  action: AuthAuditAction;

  @Column({ type: 'varchar', length: 64, nullable: true })
  ipAddress: string | null;

  @Column({ type: 'varchar', length: 512, nullable: true })
  userAgent: string | null;

  /** Free-form metadata: revoked session id, role transition, etc. */
  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, unknown> | null;

  @CreateDateColumn()
  @Index()
  createdAt: Date;
}
