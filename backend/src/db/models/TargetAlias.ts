import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Target } from './Target';

export type TargetAliasKind = 'apptrana_console' | 'custom';

@Entity('target_aliases')
@Index(['label'], { unique: true })
export class TargetAlias {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  targetId: string;

  @ManyToOne(() => Target, (t) => t.aliases, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'targetId' })
  target: Target;

  /** AppTrana-facing label (e.g. juiceshopnew.testapptrana.net_API) */
  @Column({ unique: true })
  label: string;

  @Column({ type: 'varchar', length: 32, default: 'apptrana_console' })
  kind: TargetAliasKind;

  @CreateDateColumn()
  createdAt: Date;
}
