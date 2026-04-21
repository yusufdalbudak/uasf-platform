import { DataSource } from 'typeorm';
import { env } from '../config/env';
import { Target } from '../db/models/Target';
import { TargetAlias } from '../db/models/TargetAlias';
import { EvidenceLog } from '../db/models/Evidence';
import { DiscoveredService } from '../db/models/DiscoveredService';
import { SecurityFinding } from '../db/models/SecurityFinding';
import { ScenarioTemplate } from '../db/models/ScenarioTemplate';
import { Campaign } from '../db/models/Campaign';
import { AssessmentRun } from '../db/models/AssessmentRun';
import { AllowedTargetKey } from '../db/models/AllowedTargetKey';
import { Report } from '../db/models/Report';
import { DependencyVulnerability } from '../db/models/DependencyVulnerability';
import { IocIndicator } from '../db/models/IocIndicator';
import { MalwareArtifact } from '../db/models/MalwareArtifact';
import { CodeFinding } from '../db/models/CodeFinding';
import { User } from '../db/models/User';
import { AuthSession } from '../db/models/AuthSession';
import { AuthAuditLog } from '../db/models/AuthAuditLog';
import { PasswordResetToken } from '../db/models/PasswordResetToken';
import { EmailVerificationToken } from '../db/models/EmailVerificationToken';
import { TechIntelRun } from '../db/models/TechIntelRun';
import { DetectedTechnology } from '../db/models/DetectedTechnology';
import { VulnerabilityCorrelation } from '../db/models/VulnerabilityCorrelation';
import { FingerprintObservation } from '../db/models/FingerprintObservation';
import { WafValidationRun } from '../db/models/WafValidationRun';
import { WafValidationEvent } from '../db/models/WafValidationEvent';
import { NewsSource } from '../db/models/NewsSource';
import { NewsArticle } from '../db/models/NewsArticle';
import { NewsIngestionRun } from '../db/models/NewsIngestionRun';

export const AppDataSource = new DataSource({
  type: 'postgres',
  url: env.databaseUrl,
  synchronize: env.databaseSynchronize,
  logging: false,
  entities: [
    Target,
    TargetAlias,
    EvidenceLog,
    DiscoveredService,
    SecurityFinding,
    ScenarioTemplate,
    Campaign,
    AssessmentRun,
    AllowedTargetKey,
    Report,
    DependencyVulnerability,
    IocIndicator,
    MalwareArtifact,
    CodeFinding,
    User,
    AuthSession,
    AuthAuditLog,
    PasswordResetToken,
    EmailVerificationToken,
    TechIntelRun,
    DetectedTechnology,
    VulnerabilityCorrelation,
    FingerprintObservation,
    WafValidationRun,
    WafValidationEvent,
    NewsSource,
    NewsArticle,
    NewsIngestionRun,
  ],
  subscribers: [],
  migrations: [],
});

export async function initDB() {
  try {
    await AppDataSource.initialize();
    console.log('PostgreSQL database connection initialized properly.');
  } catch (error) {
    console.error('Error during Data Source initialization', error);
    process.exit(1);
  }
}
