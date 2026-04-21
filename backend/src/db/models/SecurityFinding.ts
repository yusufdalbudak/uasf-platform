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
import { Target } from './Target';

/** Normalized cross-domain security finding (DAST/SAST/deps/IOC/file risk share this shell). */
@Entity('security_findings')
@Index(['assetId', 'status'])
export class SecurityFinding {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', nullable: true })
  assetId: string | null;

  @ManyToOne(() => Target, (a) => a.findings, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'assetId' })
  asset: Target | null;

  @Column({ type: 'varchar', length: 24 })
  severity: string;

  @Column({ type: 'varchar', length: 24, default: 'medium' })
  confidence: string;

  @Column({ type: 'varchar', length: 64 })
  category: string;

  @Column({ type: 'varchar', length: 512 })
  title: string;

  @Column({ type: 'text', nullable: true })
  technicalSummary: string | null;

  @Column({ type: 'text', nullable: true })
  evidenceSummary: string | null;

  @Column({ type: 'varchar', length: 512, nullable: true })
  endpoint: string | null;

  @Column({ type: 'varchar', length: 32, default: 'open' })
  status: string;

  /** Product area: platform, dast, sast, dependency, ioc, malware, exposure */
  @Column({ name: 'finding_domain', type: 'varchar', length: 32, default: 'platform' })
  findingDomain: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
