import { AppDataSource } from '../db/connection';
import { DiscoveredService } from '../db/models/DiscoveredService';
import { Target } from '../db/models/Target';
import { runDiscoveryScanner } from '../engine/modules/discoveryScanner';
import { runTlsScanner } from '../engine/modules/tlsScanner';
import { runServiceExposureScanner } from '../engine/modules/serviceExposureScanner';
import { assertSafeScanHostname } from '../engine/modules/utils';
import { resolveProtectedHostname } from '../db/targetResolution';
import { assertExecutableApprovedAsset } from '../policy/executableAsset';
import { finalizeDeepScanResult, finalizeModuleResult } from '../engine/validators';
import type {
  AssessmentModuleResult,
  DeepScanResult,
  ExecutionMeta,
  ReconData,
  ScanFinding,
  ScanSummary,
} from '../engine/scanTypes';

/**
 * Run the discovery / exposure visibility pipeline against an approved asset.
 *
 * This is intentionally a **subset** of `runVulnerabilityScan` — only the
 * non-intrusive recon/exposure modules are invoked (no opinionated web-surface
 * fuzzing). The result is shaped as a {@link DeepScanResult} so it can be
 * persisted and rendered through the same Report pipeline as application
 * assessments, but the report type is recorded as `discovery`.
 */
export async function runDiscoveryPipeline(targetKey: string): Promise<{
  result: DeepScanResult;
  servicesPersisted: number;
}> {
  const scanStartedAt = Date.now();
  await assertExecutableApprovedAsset(targetKey);
  const cleanHostname = assertSafeScanHostname(
    (await resolveProtectedHostname(targetKey)).trim(),
  );

  const reconData: ReconData = {
    ip: 'Unknown',
    tlsIssuer: 'Unknown',
    tlsValidTo: 'Unknown',
    dnsDetails: [],
  };

  const moduleResults: AssessmentModuleResult[] = [];
  const findings: ScanFinding[] = [];

  const settled = await Promise.allSettled([
    runDiscoveryScanner(cleanHostname),
    runTlsScanner(cleanHostname),
    runServiceExposureScanner(cleanHostname),
  ]);

  const fallbackModules = [
    ['discoveryScanner', 'Nmap-Discovery'],
    ['tlsScanner', 'Nmap-SSL-Cert'],
    ['serviceExposureScanner', 'Nmap-Port-Scan'],
  ] as const;

  settled.forEach((settledResult, index) => {
    if (settledResult.status === 'fulfilled') {
      moduleResults.push(finalizeModuleResult(settledResult.value, settledResult.value));
    } else {
      const [moduleName, sourceTool] = fallbackModules[index];
      const now = Date.now();
      moduleResults.push(
        finalizeModuleResult(
          {
            moduleName,
            sourceTool,
            status: 'failed',
            confidence: 0,
            startedAt: now,
            endedAt: now,
            rawEvidence: '',
            normalizedEvidence: 'Discovery module errored out.',
            findings: [],
            errors: [String(settledResult.reason)],
          },
          { moduleName, sourceTool, startedAt: now, endedAt: now },
        ),
      );
    }
  });

  const discovery = moduleResults.find((m) => m.moduleName === 'discoveryScanner');
  const tls = moduleResults.find((m) => m.moduleName === 'tlsScanner');
  const exposure = moduleResults.find((m) => m.moduleName === 'serviceExposureScanner');

  if (discovery?.extractedData?.ip) reconData.ip = discovery.extractedData.ip;
  if (discovery?.extractedData?.dnsDetails) {
    reconData.dnsDetails = [...discovery.extractedData.dnsDetails];
  }
  if (tls?.extractedData?.tlsIssuer) reconData.tlsIssuer = tls.extractedData.tlsIssuer;
  if (tls?.extractedData?.tlsValidTo) reconData.tlsValidTo = tls.extractedData.tlsValidTo;

  for (const moduleResult of moduleResults) {
    if (moduleResult.findings && moduleResult.findings.length > 0) {
      findings.push(...moduleResult.findings);
    }
  }

  const findingsBySeverity: Record<string, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  for (const finding of findings) {
    findingsBySeverity[finding.severity] = (findingsBySeverity[finding.severity] || 0) + 1;
  }

  const findingsBySourceTool: Record<string, number> = {};
  for (const moduleResult of moduleResults) {
    findingsBySourceTool[moduleResult.sourceTool] = moduleResult.findings.length;
  }

  const completedModules = moduleResults.filter(
    (m) => m.status === 'success' || m.status === 'partial',
  ).length;
  const failedModules = moduleResults.filter((m) => m.status === 'failed').length;
  const totalConfidence = moduleResults.reduce((sum, m) => sum + m.confidence, 0);

  const scanSummary: ScanSummary = {
    totalModules: moduleResults.length,
    completedModules,
    failedModules,
    averageConfidence:
      moduleResults.length > 0 ? Math.round(totalConfidence / moduleResults.length) : 0,
    findingsBySeverity,
    findingsBySourceTool,
  };

  const scanEndedAt = Date.now();
  const executionMeta: ExecutionMeta = {
    scanStartedAt,
    scanEndedAt,
    scanDurationMs: scanEndedAt - scanStartedAt,
    target: cleanHostname,
  };

  const servicesPersisted = await persistDiscoveredServices(cleanHostname, exposure);

  const result = finalizeDeepScanResult(
    {
      reconData,
      findings,
      moduleResults,
      scanSummary,
      executionMeta,
    },
    cleanHostname,
  );

  return { result, servicesPersisted };
}

/**
 * Translate the structured exposure scanner output into {@link DiscoveredService}
 * rows, keyed by `(assetId, port, protocol)`. Existing rows are updated with a
 * fresh `lastSeen`; new rows are inserted.
 */
async function persistDiscoveredServices(
  hostname: string,
  exposure: AssessmentModuleResult | undefined,
): Promise<number> {
  if (!exposure) return 0;

  const targetRepo = AppDataSource.getRepository(Target);
  const target = await targetRepo.findOne({ where: { hostname } });
  if (!target) return 0;

  const ports = parseExposurePorts(exposure);
  if (ports.length === 0) return 0;

  const repo = AppDataSource.getRepository(DiscoveredService);
  const now = new Date();
  let touched = 0;

  for (const entry of ports) {
    const existing = await repo.findOne({
      where: { assetId: target.id, port: entry.port, protocol: entry.protocol },
    });

    if (existing) {
      existing.bannerSummary = entry.banner;
      existing.evidenceSource = exposure.sourceTool;
      existing.lastSeen = now;
      await repo.save(existing);
    } else {
      await repo.save(
        repo.create({
          assetId: target.id,
          port: entry.port,
          protocol: entry.protocol,
          bannerSummary: entry.banner,
          evidenceSource: exposure.sourceTool,
          lastSeen: now,
        }),
      );
    }
    touched += 1;
  }

  return touched;
}

interface DiscoveredPortEntry {
  port: number;
  protocol: string;
  banner: string;
}

/**
 * The `serviceExposureScanner` module emits findings whose evidence string
 * looks like `nmap port-scan output reports "<port> open" for <host>.`. We
 * also fall back to scanning the raw `rawEvidence` line-by-line so the
 * persisted services list stays accurate even if finding text changes.
 */
function parseExposurePorts(moduleResult: AssessmentModuleResult): DiscoveredPortEntry[] {
  const seen = new Map<string, DiscoveredPortEntry>();

  const accumulate = (port: number, protocol: string, banner: string) => {
    const key = `${port}/${protocol}`;
    if (!seen.has(key)) {
      seen.set(key, { port, protocol, banner });
    }
  };

  for (const finding of moduleResult.findings ?? []) {
    const titleMatch = finding.title?.match(/Port\s+(\d+)/i);
    const evidenceMatch = finding.evidence?.match(/"\s*(\d+)(?:\/(tcp|udp))?\s*open\s*"/i);
    const port = titleMatch ? parseInt(titleMatch[1], 10) : evidenceMatch ? parseInt(evidenceMatch[1], 10) : NaN;
    if (!Number.isFinite(port)) continue;
    const protocol = (evidenceMatch?.[2] ?? 'tcp').toLowerCase();
    accumulate(port, protocol, (finding.description ?? '').slice(0, 240));
  }

  for (const line of (moduleResult.rawEvidence ?? '').split('\n')) {
    const m = line.match(/^\s*(\d+)\/(tcp|udp)\s+open\s+([^\s].*)?$/i);
    if (m) {
      const port = parseInt(m[1], 10);
      const protocol = m[2].toLowerCase();
      const banner = (m[3] ?? '').trim().slice(0, 240);
      accumulate(port, protocol, banner);
    }
  }

  return Array.from(seen.values());
}
