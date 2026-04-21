import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { AssessmentRun } from './AssessmentRun';

@Entity('campaigns')
export class Campaign {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'jsonb', nullable: true })
  assetScope: string[] | null;

  @Column({ type: 'jsonb', nullable: true })
  templateSlugs: string[] | null;

  @Column({ type: 'varchar', length: 24, default: 'draft' })
  status: string;

  @Column({ type: 'varchar', length: 24, default: 'pending' })
  approvalState: string;

  @Column({ type: 'text', nullable: true })
  operatorNotes: string | null;

  @OneToMany(() => AssessmentRun, (r) => r.campaign)
  runs: AssessmentRun[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
