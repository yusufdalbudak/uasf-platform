import { AppDataSource } from './connection';
import { Target } from './models/Target';
import { TargetAlias } from './models/TargetAlias';
import { EvidenceLog } from './models/Evidence';
import { ScenarioTemplate } from './models/ScenarioTemplate';
import { Campaign } from './models/Campaign';
import { AssessmentRun } from './models/AssessmentRun';
import { SecurityFinding } from './models/SecurityFinding';
import { DiscoveredService } from './models/DiscoveredService';

const JUICE_HOST = 'juiceshopnew.testapptrana.net';
const APPTRANA_LABEL = 'juiceshopnew.testapptrana.net_API';
const BROKEN_HOST = 'brokencrystals.com';
const VULNHUB_HOST = 'vulnhub.com';
const VULNHUB_WWW_HOST = 'www.vulnhub.com';

/**
 * Idempotent seed: approved assets, aliases, templates, campaign, runs, findings, discovery, evidence.
 */
export async function seedDatabase(): Promise<void> {
  const targetRepo = AppDataSource.getRepository(Target);
  const aliasRepo = AppDataSource.getRepository(TargetAlias);
  const evidenceRepo = AppDataSource.getRepository(EvidenceLog);
  const tplRepo = AppDataSource.getRepository(ScenarioTemplate);
  const campRepo = AppDataSource.getRepository(Campaign);
  const runRepo = AppDataSource.getRepository(AssessmentRun);
  const findingRepo = AppDataSource.getRepository(SecurityFinding);
  const discRepo = AppDataSource.getRepository(DiscoveredService);

  let juice = await targetRepo.findOne({ where: { hostname: JUICE_HOST } });
  if (!juice) {
    juice = targetRepo.create({
      hostname: JUICE_HOST,
      displayName: 'Authorized Juice Shop (WAAP validation)',
      assetType: 'web',
      protocol: 'https',
      port: 443,
      environment: 'authorized-test',
      businessOwner: 'Security Engineering',
      applicationOwner: 'AppTrana Demo',
      tags: ['waap', 'demo', 'api-security'],
      approvalStatus: 'approved',
      assetCriticality: 'high',
      scanPolicy: 'default-waap',
      apptranaAlias: APPTRANA_LABEL,
      notes: 'Primary webinar / PoC target. Correlates with AppTrana API Security and Logs & Reports.',
      isApproved: true,
      metadata: {
        apptranaConsolePaths: ['/api-security', '/logs-reports'],
      },
    });
    await targetRepo.save(juice);
  }

  let broken = await targetRepo.findOne({ where: { hostname: BROKEN_HOST } });
  if (!broken) {
    broken = targetRepo.create({
      hostname: BROKEN_HOST,
      displayName: 'BrokenCrystals (application assessment)',
      assetType: 'web',
      protocol: 'https',
      port: 443,
      environment: 'authorized-test',
      businessOwner: 'Security Engineering',
      applicationOwner: 'Assessment Lab',
      tags: ['dast', 'demo'],
      approvalStatus: 'approved',
      assetCriticality: 'medium',
      scanPolicy: 'app-assessment-standard',
      isApproved: true,
      metadata: { purpose: 'DAST-style assessment demos' },
    });
    await targetRepo.save(broken);
  }

  let vulnhub = await targetRepo.findOne({ where: { hostname: VULNHUB_HOST } });
  if (!vulnhub) {
    vulnhub = targetRepo.create({
      hostname: VULNHUB_HOST,
      displayName: 'VulnHub catalog surface',
      assetType: 'web',
      protocol: 'https',
      port: 443,
      environment: 'authorized-research',
      businessOwner: 'Security Research',
      applicationOwner: 'Exposure Validation',
      tags: ['osint', 'surface-assessment', 'external'],
      approvalStatus: 'approved',
      assetCriticality: 'medium',
      scanPolicy: 'app-assessment-standard',
      isApproved: true,
      metadata: {
        purpose: 'External surface validation and module-quality benchmarking',
      },
    });
    await targetRepo.save(vulnhub);
  }

  let vulnhubWww = await targetRepo.findOne({ where: { hostname: VULNHUB_WWW_HOST } });
  if (!vulnhubWww) {
    vulnhubWww = targetRepo.create({
      hostname: VULNHUB_WWW_HOST,
      displayName: 'VulnHub www surface',
      assetType: 'web',
      protocol: 'https',
      port: 443,
      environment: 'authorized-research',
      businessOwner: 'Security Research',
      applicationOwner: 'Exposure Validation',
      tags: ['osint', 'surface-assessment', 'external'],
      approvalStatus: 'approved',
      assetCriticality: 'medium',
      scanPolicy: 'app-assessment-standard',
      isApproved: true,
      metadata: {
        purpose: 'Canonical www host for live surface validation',
      },
    });
    await targetRepo.save(vulnhubWww);
  }

  const existingAlias = await aliasRepo.findOne({ where: { label: APPTRANA_LABEL } });
  if (!existingAlias && juice.id) {
    await aliasRepo.save(
      aliasRepo.create({
        targetId: juice.id,
        label: APPTRANA_LABEL,
        kind: 'apptrana_console',
      }),
    );
  }

  const templateSlugs = [
    ['waap-policy-validation', 'WAAP Policy Validation', 'waap_validation'],
    ['api-discovery-visibility', 'API Discovery Visibility Review', 'api_validation'],
    ['endpoint-inventory', 'Endpoint Inventory Review', 'application_assessment'],
    ['session-token-review', 'Session / Token Review', 'application_assessment'],
    ['security-header-assessment', 'Security Header Assessment', 'application_assessment'],
    ['approved-discovery-review', 'Approved Discovery Review', 'exposure'],
    ['executive-poc-pack', 'Executive PoC Validation Pack', 'campaign_bundle'],
  ];

  for (const [slug, name, category] of templateSlugs) {
    const exists = await tplRepo.findOne({ where: { slug } });
    if (!exists) {
      await tplRepo.save(
        tplRepo.create({
          slug,
          name,
          category,
          supportedAssetTypes: ['web', 'api'],
          description: `Policy-bound template: ${name}`,
          preconditions: { requireApprovedAsset: true },
          executionProfile: { mode: 'controlled' },
          observabilityTags: ['apptrana', 'evidence'],
          severityModel: 'cvss-style',
        }),
      );
    }
  }

  let campaign = await campRepo.findOne({ where: { name: 'Executive PoC Validation Pack' } });
  if (!campaign && juice.id && broken.id) {
    campaign = campRepo.create({
      name: 'Executive PoC Validation Pack',
      description: 'Sequential WAAP + exposure + application checks for approved assets.',
      assetScope: [juice.id, broken.id],
      templateSlugs: ['waap-policy-validation', 'endpoint-inventory', 'executive-poc-pack'],
      status: 'active',
      approvalState: 'approved',
      operatorNotes: 'Demo-ready; scheduled runs optional in Phase 2.',
    });
    await campRepo.save(campaign);
  }

  if (campaign?.id && juice.id) {
    const existingRun = await runRepo.findOne({ where: { label: 'seed-waap-baseline' } });
    if (!existingRun) {
      const start = new Date(Date.now() - 86400000);
      const end = new Date(Date.now() - 3600000);
      await runRepo.save(
        runRepo.create({
          campaignId: campaign.id,
          assetId: juice.id,
          label: 'seed-waap-baseline',
          status: 'completed',
          summary: { scenariosExecuted: 3, evidenceEvents: 12 },
          startedAt: start,
          completedAt: end,
        }),
      );
    }
  }

  if (juice.id) {
    const discCount = await discRepo.count({ where: { assetId: juice.id } });
    if (discCount === 0) {
      const now = new Date();
      await discRepo.save(
        discRepo.create({
          assetId: juice.id,
          port: 443,
          protocol: 'tcp',
          bannerSummary: 'TLS 1.2+, HTTP/2, AppTrana edge',
          evidenceSource: 'seed:discovery',
          firstSeen: now,
          lastSeen: now,
        }),
      );
      await discRepo.save(
        discRepo.create({
          assetId: juice.id,
          port: 80,
          protocol: 'tcp',
          bannerSummary: 'Redirect to HTTPS',
          evidenceSource: 'seed:discovery',
          firstSeen: now,
          lastSeen: now,
        }),
      );
    }
  }

  if ((await findingRepo.count()) === 0 && juice.id && broken.id) {
    await findingRepo.save(
      findingRepo.create({
        assetId: juice.id,
        severity: 'medium',
        confidence: 'high',
        category: 'Security Header',
        title: 'HSTS configuration review',
        technicalSummary: 'Validate HSTS via WAAP and origin response.',
        evidenceSummary: 'Seed finding for correlation demos.',
        endpoint: '/',
        status: 'open',
        findingDomain: 'dast',
      }),
    );
    await findingRepo.save(
      findingRepo.create({
        assetId: broken.id,
        severity: 'low',
        confidence: 'medium',
        category: 'Exposure signal',
        title: 'Public surface inventory checkpoint',
        technicalSummary: 'Endpoint inventory baseline for approved host.',
        evidenceSummary: 'Seed finding for application assessment domain.',
        endpoint: '/api',
        status: 'triaged',
        findingDomain: 'dast',
      }),
    );
    await findingRepo.save(
      findingRepo.create({
        assetId: null,
        severity: 'info',
        confidence: 'high',
        category: 'Process',
        title: 'IOC watchlist placeholder',
        technicalSummary: 'CTI enrichment workflows land in Phase 3.',
        evidenceSummary: 'No external IOC data in seed.',
        endpoint: null,
        status: 'open',
        findingDomain: 'ioc',
      }),
    );
  }

  const sampleCount = await evidenceRepo.count();
  if (sampleCount === 0) {
    const now = Date.now();
    const samples = [
      {
        campaignRunId: `seed_run_${now}`,
        scenarioId: 'waap-sqli-01',
        targetHostname: APPTRANA_LABEL,
        method: 'GET',
        path: "/api/users?query=seed",
        responseStatusCode: 406,
        latencyMs: 42,
        responseHeaders: { 'content-type': 'text/html', 'x-uasf-seed': 'true' },
        executionStatus: 'blocked',
        verdict: 'blocked',
        verdictConfidence: 80,
        verdictReason: 'Seed sample: HTTP 406 from upstream control.',
        expectationOutcome: 'matched',
      },
      {
        campaignRunId: `seed_run_${now}`,
        scenarioId: 'waap-xss-01',
        targetHostname: JUICE_HOST,
        method: 'GET',
        path: '/api/search?q=seed',
        responseStatusCode: 200,
        latencyMs: 118,
        responseHeaders: { 'content-type': 'application/json', 'x-uasf-seed': 'true' },
        executionStatus: 'allowed',
        verdict: 'allowed',
        verdictConfidence: 55,
        verdictReason: 'Seed sample: HTTP 200 with no mitigation indicators.',
        expectationOutcome: 'mismatched',
      },
      {
        campaignRunId: `seed_run_${now}`,
        scenarioId: 'waap-bot-01',
        targetHostname: APPTRANA_LABEL,
        method: 'GET',
        path: '/',
        responseStatusCode: 403,
        latencyMs: 31,
        responseHeaders: { 'x-uasf-seed': 'true' },
        executionStatus: 'blocked',
        verdict: 'blocked',
        verdictConfidence: 85,
        verdictReason: 'Seed sample: HTTP 403 indicates upstream rejection.',
        expectationOutcome: 'matched',
      },
    ];
    for (const row of samples) {
      await evidenceRepo.save(evidenceRepo.create(row));
    }
  }
}
