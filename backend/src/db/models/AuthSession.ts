import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './User';

/**
 * Refresh-token-backed session record. One row per browser/device login.
 *
 * Security model:
 *   - We NEVER store the refresh token plaintext. Only its SHA-256 hash is
 *     persisted; the original is sent to the client as an httpOnly cookie.
 *     If an attacker steals the database they cannot replay sessions.
 *   - On every refresh the token is ROTATED: the old hash is replaced with a
 *     new one and `lastUsedAt` is bumped. If the SAME refresh token is used
 *     twice, that's a token-replay signal and the session is force-revoked.
 *   - `revokedAt` is set on logout / password change / explicit kill from the
 *     UI. Revoked rows are kept for audit history; the hash is invalidated so
 *     the cookie can no longer be used.
 *   - IP and user-agent are recorded so the user can spot rogue sessions on
 *     the "Active sessions" panel.
 */
@Entity('auth_sessions')
@Index(['userId'])
@Index(['refreshTokenHash'], { unique: true })
@Index(['expiresAt'])
export class AuthSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  /** SHA-256 hex of the active refresh token. Rotated on every refresh. */
  @Column({ type: 'varchar', length: 64 })
  refreshTokenHash: string;

  @Column({ type: 'varchar', length: 64, nullable: true })
  ipAddress: string | null;

  @Column({ type: 'varchar', length: 512, nullable: true })
  userAgent: string | null;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  lastUsedAt: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  revokedAt: Date | null;

  /**
   * Optional explanation for why this session was killed (logout, password
   * change, admin revoke, suspected reuse, ...). Useful for security audits.
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  revocationReason: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
