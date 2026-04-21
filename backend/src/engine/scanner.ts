import { assertExecutableApprovedAsset } from '../policy/executableAsset';
import { resolveProtectedHostname } from '../db/targetResolution';
import { collectOpenApiFindings } from './openapiAssessment';
import type { ScanFinding, ReconData, DeepScanResult, AssessmentModuleResult, ScanSummary, ExecutionMeta } from './scanTypes';
export type { ScanFinding, ReconData, DeepScanResult };

import { runDiscoveryScanner } from './modules/discoveryScanner';
import { runTlsScanner } from './modules/tlsScanner';
import { runHeaderAssessment } from './modules/headerAssessment';
import { runServiceExposureScanner } from './modules/serviceExposureScanner';
import { runWebAssessment } from './modules/webAssessment';
import { assertSafeScanHostname } from './modules/utils';
import { normalizeEvidence, deduplicateFindings } from './modules/evidenceNormalizer';
import { scoreFinding, sortFindingsByScoring } from './modules/findingScorer';
import { finalizeDeepScanResult, finalizeModuleResult } from './validators';

function buildErrorModule(moduleName: string, sourceTool: string, err: unknown): AssessmentModuleResult {
  const now = Date.now();
  return finalizeModuleResult(
    {
      moduleName,
      sourceTool,
      status: 'failed',
      confidence: 0,
      startedAt: now,
      endedAt: now,
      rawEvidence: '',
      normalizedEvidence: 'Module suffered an unhandled orchestration failure.',
      findings: [],
      errors: [String(err)],
    },
    { moduleName, sourceTool, startedAt: now, endedAt: now },
  );
}

export async function runVulnerabilityScan(targetKey: string): Promise<DeepScanResult> {
  const scanStartedAt = Date.now();
  await assertExecutableApprovedAsset(targetKey);
  const cleanHostname = assertSafeScanHostname((await resolveProtectedHostname(targetKey)).trim());
  const baseUrl = `https://${cleanHostname}`;

  const reconData: ReconData = {
    ip: 'Unknown',
    tlsIssuer: 'Unknown',
    tlsValidTo: 'Unknown',
    dnsDetails: [],
  };

  const results: AssessmentModuleResult[] = [];
  const allFindings: ScanFinding[] = [];

  const openApiFindings = await collectOpenApiFindings(baseUrl).catch(() => []);
  if (openApiFindings.length > 0) {
    allFindings.push(...openApiFindings.map(f => ({ ...f, confidence: 90 })));
    results.push(
      finalizeModuleResult(
        {
          moduleName: 'openApiAssessment',
          sourceTool: 'OpenAPI-Parser',
          status: 'success',
          confidence: 90,
          rawEvidence: '',
          normalizedEvidence: 'Discovered and parsed rich OpenAPI specifications.',
          findings: openApiFindings,
          startedAt: Date.now() - 1000,
          endedAt: Date.now(),
        },
        {
          moduleName: 'openApiAssessment',
          sourceTool: 'OpenAPI-Parser',
        },
      ),
    );
  }

  const scannerPromises = [
    runDiscoveryScanner(cleanHostname).catch(e => buildErrorModule('discoveryScanner', 'Nmap-Discovery', e)),
    runTlsScanner(cleanHostname).catch(e => buildErrorModule('tlsScanner', 'Nmap-SSL-Cert', e)),
    runHeaderAssessment(cleanHostname).catch(e => buildErrorModule('headerAssessment', 'Hybrid-HTTP-Header-Assessment', e)),
    runServiceExposureScanner(cleanHostname).catch(e => buildErrorModule('serviceExposureScanner', 'Nmap-Port-Scan', e)),
    runWebAssessment(cleanHostname).catch(e => buildErrorModule('webAssessment', 'Hybrid-Web-Surface-Assessment', e))
  ];

  const resSettled = await Promise.allSettled(scannerPromises);
  const coreResults: AssessmentModuleResult[] = resSettled.map((result, index) => {
    if (result.status === 'fulfilled') {
      return finalizeModuleResult(result.value, result.value);
    }

    const fallbackModules = [
      ['discoveryScanner', 'Nmap-Discovery'],
      ['tlsScanner', 'Nmap-SSL-Cert'],
      ['headerAssessment', 'Hybrid-HTTP-Header-Assessment'],
      ['serviceExposureScanner', 'Nmap-Port-Scan'],
      ['webAssessment', 'Hybrid-Web-Surface-Assessment'],
    ] as const;
    const [moduleName, sourceTool] = fallbackModules[index] ?? ['unknown', 'Unknown-Tool'];
    return buildErrorModule(moduleName, sourceTool, result.reason);
  });

  results.push(...coreResults);

  const discoveryRes = coreResults.find(r => r.moduleName === 'discoveryScanner');
  const tlsRes = coreResults.find(r => r.moduleName === 'tlsScanner');

  if (discoveryRes?.extractedData?.ip) reconData.ip = discoveryRes.extractedData.ip;
  if (discoveryRes?.extractedData?.dnsDetails) {
    reconData.dnsDetails = [...discoveryRes.extractedData.dnsDetails];
  }
  
  if (tlsRes?.extractedData?.tlsIssuer) reconData.tlsIssuer = tlsRes.extractedData.tlsIssuer;
  if (tlsRes?.extractedData?.tlsValidTo) reconData.tlsValidTo = tlsRes.extractedData.tlsValidTo;

  const findingsBySeverity: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const findingsBySourceTool: Record<string, number> = {};
  
  let totalConfidence = 0;
  let completedModules = 0;
  let failedModules = 0;

  for (const moduleRes of results) {
    if (moduleRes.status === 'success' || moduleRes.status === 'partial') completedModules++;
    if (moduleRes.status === 'failed') failedModules++;
    totalConfidence += moduleRes.confidence;

    if (moduleRes.findings && moduleRes.findings.length > 0) {
      const enrichedFindings = moduleRes.findings.map(f => ({
        ...f,
        confidence: f.confidence || moduleRes.confidence,
        evidence: f.evidence || `[${moduleRes.sourceTool}] ${moduleRes.normalizedEvidence}`
      }));
      allFindings.push(...enrichedFindings);
    }
  }

  const deduplicated = deduplicateFindings(allFindings);
  const scored = deduplicated.map(f => scoreFinding(f));
  const sortedFindings = sortFindingsByScoring(scored);

  for (const f of sortedFindings) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
  }

  for (const moduleRes of results) {
    findingsBySourceTool[moduleRes.sourceTool] = moduleRes.findings.length;
  }

  const scanSummary: ScanSummary = {
    totalModules: results.length,
    completedModules,
    failedModules,
    averageConfidence: Math.round(totalConfidence / results.length),
    findingsBySeverity,
    findingsBySourceTool
  };

  const scanEndedAt = Date.now();
  const executionMeta: ExecutionMeta = {
    scanStartedAt,
    scanEndedAt,
    scanDurationMs: scanEndedAt - scanStartedAt,
    target: cleanHostname,
  };

  const evidenceLines = normalizeEvidence(results);
  if (evidenceLines.length > 0) {
    reconData.dnsDetails = [...reconData.dnsDetails, ...evidenceLines];
  };

  return finalizeDeepScanResult(
    { reconData, findings: sortedFindings, moduleResults: results, scanSummary, executionMeta },
    cleanHostname,
  );
}
