import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { TargetAlias } from './TargetAlias';
import { DiscoveredService } from './DiscoveredService';
import { SecurityFinding } from './SecurityFinding';

export type AssetType =
  | 'web'
  | 'api'
  | 'repository'
  | 'container_image'
  | 'file_artifact'
  | 'ioc'
  | 'service_endpoint';

export type ApprovalStatus = 'approved' | 'pending_review' | 'suspended';

export type AssetCriticality = 'low' | 'medium' | 'high' | 'critical';

/**
 * Approved asset registry entry. Executable assessments require a matching row with
 * {@link approvalStatus} `approved` in addition to deployment allowlist policy.
 * AppTrana console labels are not network hosts; use {@link TargetAlias} and optional {@link apptranaAlias}.
 */
@Entity('targets')
export class Target {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Network hostname for web/API assets (never an AppTrana metadata label). */
  @Column({ unique: true })
  hostname: string;

  @Column({ nullable: true })
  displayName: string | null;

  @Column({ type: 'varchar', length: 32, default: 'web' })
  assetType: AssetType;

  @Column({ type: 'varchar', length: 16, default: 'https' })
  protocol: string;

  @Column({ type: 'int', nullable: true })
  port: number | null;

  @Column({ nullable: true })
  environment: string | null;

  @Column({ nullable: true })
  businessOwner: string | null;

  @Column({ nullable: true })
  applicationOwner: string | null;

  @Column({ type: 'jsonb', nullable: true })
  tags: string[] | null;

  @Column({ type: 'varchar', length: 24, default: 'approved' })
  approvalStatus: ApprovalStatus;

  @Column({ type: 'varchar', length: 16, default: 'medium' })
  assetCriticality: AssetCriticality;

  /** Policy key, e.g. default-waap, app-assessment-standard */
  @Column({ nullable: true })
  scanPolicy: string | null;

  /** Primary AppTrana console label for correlation (informational; not a socket target). */
  @Column({ nullable: true })
  apptranaAlias: string | null;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  /** Non-host assets: repo URL, image digest, artifact path, etc. */
  @Column({ type: 'text', nullable: true })
  resourceIdentifier: string | null;

  /** Legacy mirror of approval; kept for backward compatibility with existing rows. */
  @Column({ default: true })
  isApproved: boolean;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, unknown> | null;

  @OneToMany(() => TargetAlias, (a) => a.target, { cascade: true })
  aliases: TargetAlias[];

  @OneToMany(() => DiscoveredService, (d) => d.asset)
  discoveredServices: DiscoveredService[];

  @OneToMany(() => SecurityFinding, (f) => f.asset)
  findings: SecurityFinding[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
