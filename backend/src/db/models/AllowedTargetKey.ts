import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

/** Extra allowlist entries beyond ALLOWED_TARGETS (e.g. added from the operator console). */
@Entity('allowed_target_keys')
export class AllowedTargetKey {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  key: string;

  @Column({ type: 'varchar', length: 24, default: 'operator' })
  source: 'compose' | 'operator';

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
