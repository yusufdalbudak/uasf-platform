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
 * One-time-use password reset token.
 *
 * The plaintext token is sent to the user (typically via email); only the
 * SHA-256 hash is stored here so a leaked DB row cannot be used to reset
 * a password. Single-use is enforced by setting `usedAt` at consumption.
 *
 * Tokens are short-lived (default 60 minutes). Expired or used rows are
 * left in place so the audit trail records a complete history; a periodic
 * pruning job can delete rows older than the retention window.
 */
@Entity('auth_password_reset_tokens')
@Index(['userId'])
@Index(['tokenHash'], { unique: true })
@Index(['expiresAt'])
export class PasswordResetToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column({ type: 'varchar', length: 64 })
  tokenHash: string;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  usedAt: Date | null;

  @Column({ type: 'varchar', length: 64, nullable: true })
  requestedFromIp: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
