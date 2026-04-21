import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

/**
 * Static-analysis (SAST) finding from an external scanner, normalized to
 * UASF semantics. Currently sourced from operator-uploaded SARIF documents,
 * but the schema is generic enough for future direct integrations.
 */
@Entity('code_findings')
@Index(['repository', 'severity'])
@Index(['ruleId'])
export class CodeFinding {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Logical repository name supplied by the operator at upload time. */
  @Column({ type: 'varchar', length: 255 })
  repository: string;

  /** Optional branch / commit identifier (free text). */
  @Column({ type: 'varchar', length: 255, nullable: true })
  ref: string | null;

  /** SAST tool that produced the finding, e.g. `semgrep`, `codeql`. */
  @Column({ type: 'varchar', length: 64 })
  tool: string;

  /** Tool-specific rule identifier. */
  @Column({ type: 'varchar', length: 128 })
  ruleId: string;

  @Column({ type: 'varchar', length: 24, default: 'medium' })
  severity: string;

  @Column({ type: 'varchar', length: 512 })
  title: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'varchar', length: 512, nullable: true })
  filePath: string | null;

  @Column({ type: 'int', nullable: true })
  lineStart: number | null;

  @Column({ type: 'int', nullable: true })
  lineEnd: number | null;

  /** open | triaged | resolved | suppressed */
  @Column({ type: 'varchar', length: 16, default: 'open' })
  status: string;

  /** Optional CWE reference (`CWE-79`). */
  @Column({ type: 'varchar', length: 16, nullable: true })
  cwe: string | null;

  @Column({ type: 'text', nullable: true })
  remediation: string | null;

  @Column({ type: 'jsonb', nullable: true })
  rawSnippet: { before?: string; matched?: string; after?: string } | null;

  @CreateDateColumn()
  createdAt: Date;
}
