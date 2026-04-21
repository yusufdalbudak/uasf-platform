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

/** Normalized exposure / service visibility evidence tied to an approved asset. */
@Entity('discovered_services')
@Index(['assetId', 'port'])
export class DiscoveredService {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assetId: string;

  @ManyToOne(() => Target, (a) => a.discoveredServices, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'assetId' })
  asset: Target;

  @Column({ type: 'int' })
  port: number;

  @Column({ type: 'varchar', length: 16 })
  protocol: string;

  @Column({ type: 'text', nullable: true })
  bannerSummary: string | null;

  @Column({ type: 'varchar', length: 128, nullable: true })
  evidenceSource: string | null;

  @CreateDateColumn()
  firstSeen: Date;

  @Column({ type: 'timestamptz' })
  lastSeen: Date;
}
