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
 * One-time-use email verification token.
 *
 * Same security model as PasswordResetToken: only the SHA-256 hash is
 * stored, single-use is enforced via `usedAt`, default lifetime is 24 hours.
 * Verifying an account flips `User.emailVerified` to true and removes the
 * `pending_verification` lifecycle gate.
 */
@Entity('auth_email_verification_tokens')
@Index(['userId'])
@Index(['tokenHash'], { unique: true })
@Index(['expiresAt'])
export class EmailVerificationToken {
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

  @CreateDateColumn()
  createdAt: Date;
}
