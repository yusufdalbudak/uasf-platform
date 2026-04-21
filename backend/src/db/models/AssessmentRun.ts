import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Campaign } from './Campaign';
import { Target } from './Target';

@Entity('assessment_runs')
@Index(['campaignId', 'startedAt'])
export class AssessmentRun {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 128, nullable: true, unique: true })
  externalRunId: string | null;

  @Column({ type: 'uuid', nullable: true })
  campaignId: string | null;

  @ManyToOne(() => Campaign, (c) => c.runs, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'campaignId' })
  campaign: Campaign | null;

  @Column({ type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Target, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'assetId' })
  asset: Target | null;

  @Column({ type: 'varchar', length: 128 })
  label: string;

  @Column({ type: 'varchar', length: 24, default: 'completed' })
  status: string;

  @Column({ type: 'jsonb', nullable: true })
  summary: Record<string, unknown> | null;

  @Column({ type: 'timestamptz', nullable: true })
  startedAt: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  completedAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
