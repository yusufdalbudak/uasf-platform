import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

/** Policy-bound reusable assessment / validation template. */
@Entity('scenario_templates')
export class ScenarioTemplate {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  slug: string;

  @Column()
  name: string;

  @Column({ type: 'varchar', length: 64 })
  category: string;

  @Column({ type: 'jsonb', nullable: true })
  supportedAssetTypes: string[] | null;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'jsonb', nullable: true })
  preconditions: Record<string, unknown> | null;

  @Column({ type: 'jsonb', nullable: true })
  executionProfile: Record<string, unknown> | null;

  @Column({ type: 'jsonb', nullable: true })
  observabilityTags: string[] | null;

  @Column({ type: 'varchar', length: 32, default: 'cvss-style' })
  severityModel: string;

  @CreateDateColumn()
  createdAt: Date;
}
