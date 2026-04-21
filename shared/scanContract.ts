export const FINDING_CATEGORIES = [
  'Infrastructure',
  'Web App',
  'Misconfiguration',
  'OSINT',
  'Info',
] as const;

export const FINDING_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;

export const MODULE_STATUSES = ['success', 'failed', 'partial'] as const;

export type ScanFindingCategory = (typeof FINDING_CATEGORIES)[number];
export type ScanFindingSeverity = (typeof FINDING_SEVERITIES)[number];
export type AssessmentModuleStatus = (typeof MODULE_STATUSES)[number];

export interface ScanRequest {
  target: string;
}

export interface ScanFinding {
  id: string;
  category: ScanFindingCategory;
  title: string;
  severity: ScanFindingSeverity;
  description: string;
  cwe?: string;
  evidence?: string;
  remediation?: string;
  confidence?: number;
}

export interface ReconData {
  ip: string;
  tlsIssuer: string;
  tlsValidTo: string;
  dnsDetails: string[];
}

export interface AssessmentModuleResult {
  moduleName: string;
  sourceTool: string;
  status: AssessmentModuleStatus;
  confidence: number;
  startedAt: number;
  endedAt: number;
  rawEvidence: string;
  normalizedEvidence: string;
  findings: ScanFinding[];
  extractedData?: Partial<ReconData>;
  errors?: string[];
}

export interface ScanSummary {
  totalModules: number;
  completedModules: number;
  failedModules: number;
  averageConfidence: number;
  findingsBySeverity: Record<string, number>;
  findingsBySourceTool: Record<string, number>;
}

export interface ExecutionMeta {
  scanStartedAt: number;
  scanEndedAt: number;
  scanDurationMs: number;
  target: string;
}

export interface DeepScanResult {
  reconData: ReconData;
  findings: ScanFinding[];
  moduleResults: AssessmentModuleResult[];
  scanSummary: ScanSummary;
  executionMeta: ExecutionMeta;
}

export interface ScanErrorResponse {
  error: string;
  code?: string;
  result: DeepScanResult;
}

type RecordValue = Record<string, unknown>;

const DEFAULT_SEVERITY_COUNTS: Record<string, number> = {
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
  Info: 0,
};

function isRecord(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pickString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function pickNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function pickStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function clampConfidence(value: unknown, fallback = 0): number {
  const n = pickNumber(value, fallback);
  if (n < 0) return 0;
  if (n > 100) return 100;
  return Math.round(n);
}

export function normalizeOperatorTargetInput(raw: string): string {
  const s = raw.trim();
  if (!s) return s;
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || s.startsWith('//')) {
      const u = new URL(s.startsWith('//') ? `https:${s}` : s);
      if (u.hostname) return u.hostname.toLowerCase();
    }
    if (s.includes('/') && !/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
      const u = new URL(`https://${s}`);
      if (u.hostname) return u.hostname.toLowerCase();
    }
  } catch {
    // Preserve the raw operator key so labels like host_API still work.
  }
  if (/^[a-z0-9][a-z0-9._-]*:\d+$/i.test(s)) {
    return s.split(':')[0].toLowerCase();
  }
  return s.toLowerCase();
}

export function createEmptyReconData(): ReconData {
  return {
    ip: 'Unknown',
    tlsIssuer: 'Unknown',
    tlsValidTo: 'Unknown',
    dnsDetails: [],
  };
}

export function createEmptyScanSummary(): ScanSummary {
  return {
    totalModules: 0,
    completedModules: 0,
    failedModules: 0,
    averageConfidence: 0,
    findingsBySeverity: { ...DEFAULT_SEVERITY_COUNTS },
    findingsBySourceTool: {},
  };
}

export function createEmptyExecutionMeta(target = ''): ExecutionMeta {
  const now = Date.now();
  return {
    scanStartedAt: now,
    scanEndedAt: now,
    scanDurationMs: 0,
    target,
  };
}

export function createEmptyScanResult(target = ''): DeepScanResult {
  return {
    reconData: createEmptyReconData(),
    findings: [],
    moduleResults: [],
    scanSummary: createEmptyScanSummary(),
    executionMeta: createEmptyExecutionMeta(target),
  };
}

function normalizeFindingCategory(value: unknown): ScanFindingCategory {
  return FINDING_CATEGORIES.includes(value as ScanFindingCategory)
    ? (value as ScanFindingCategory)
    : 'Info';
}

function normalizeFindingSeverity(value: unknown): ScanFindingSeverity {
  return FINDING_SEVERITIES.includes(value as ScanFindingSeverity)
    ? (value as ScanFindingSeverity)
    : 'Info';
}

function normalizeModuleStatus(value: unknown): AssessmentModuleStatus {
  return MODULE_STATUSES.includes(value as AssessmentModuleStatus)
    ? (value as AssessmentModuleStatus)
    : 'failed';
}

function normalizeExtractedData(value: unknown): Partial<ReconData> | undefined {
  if (!isRecord(value)) return undefined;
  const extracted: Partial<ReconData> = {};

  if (typeof value.ip === 'string') extracted.ip = value.ip;
  if (typeof value.tlsIssuer === 'string') extracted.tlsIssuer = value.tlsIssuer;
  if (typeof value.tlsValidTo === 'string') extracted.tlsValidTo = value.tlsValidTo;

  const dnsDetails = pickStringArray(value.dnsDetails);
  if (dnsDetails.length > 0) {
    extracted.dnsDetails = dnsDetails;
  }

  return Object.keys(extracted).length > 0 ? extracted : undefined;
}

export function normalizeScanFinding(input: unknown, index = 0): ScanFinding {
  const record = isRecord(input) ? input : {};

  return {
    id: pickString(record.id, `finding-${index + 1}`),
    category: normalizeFindingCategory(record.category),
    title: pickString(record.title, 'Untitled finding'),
    severity: normalizeFindingSeverity(record.severity),
    description: pickString(record.description, 'No description provided.'),
    cwe: typeof record.cwe === 'string' ? record.cwe : undefined,
    evidence: typeof record.evidence === 'string' ? record.evidence : undefined,
    remediation: typeof record.remediation === 'string' ? record.remediation : undefined,
    confidence:
      record.confidence === undefined ? undefined : clampConfidence(record.confidence, 0),
  };
}

export function normalizeAssessmentModuleResult(
  input: unknown,
  fallback?: Partial<AssessmentModuleResult>,
): AssessmentModuleResult {
  const now = Date.now();
  const record = isRecord(input) ? input : {};
  const findingsRaw = Array.isArray(record.findings) ? record.findings : fallback?.findings ?? [];
  const findings = findingsRaw.map((finding, index) => normalizeScanFinding(finding, index));
  const startedAt = pickNumber(record.startedAt, fallback?.startedAt ?? now);
  const endedAt = pickNumber(record.endedAt, fallback?.endedAt ?? startedAt);

  return {
    moduleName: pickString(record.moduleName, fallback?.moduleName ?? 'unknownModule'),
    sourceTool: pickString(record.sourceTool, fallback?.sourceTool ?? 'unknown-tool'),
    status: normalizeModuleStatus(record.status ?? fallback?.status),
    confidence: clampConfidence(record.confidence, fallback?.confidence ?? 0),
    startedAt,
    endedAt: endedAt >= startedAt ? endedAt : startedAt,
    rawEvidence: pickString(record.rawEvidence, fallback?.rawEvidence ?? ''),
    normalizedEvidence: pickString(
      record.normalizedEvidence,
      fallback?.normalizedEvidence ?? 'No normalized evidence provided.',
    ),
    findings,
    extractedData:
      normalizeExtractedData(record.extractedData) ?? normalizeExtractedData(fallback?.extractedData),
    errors: pickStringArray(record.errors ?? fallback?.errors),
  };
}

function summarizeModules(
  moduleResults: AssessmentModuleResult[],
  findings: ScanFinding[],
  input: unknown,
): ScanSummary {
  const record = isRecord(input) ? input : {};
  const completedModules = moduleResults.filter(
    (moduleResult) => moduleResult.status === 'success' || moduleResult.status === 'partial',
  ).length;
  const failedModules = moduleResults.filter((moduleResult) => moduleResult.status === 'failed').length;
  const totalConfidence = moduleResults.reduce((sum, moduleResult) => sum + moduleResult.confidence, 0);
  const findingsBySeverity = { ...DEFAULT_SEVERITY_COUNTS };

  for (const finding of findings) {
    findingsBySeverity[finding.severity] = (findingsBySeverity[finding.severity] ?? 0) + 1;
  }

  const findingsBySourceTool = moduleResults.reduce<Record<string, number>>((acc, moduleResult) => {
    acc[moduleResult.sourceTool] = moduleResult.findings.length;
    return acc;
  }, {});

  const summaryCandidate = isRecord(record.scanSummary) ? record.scanSummary : record;

  return {
    totalModules: pickNumber(summaryCandidate.totalModules, moduleResults.length),
    completedModules: pickNumber(summaryCandidate.completedModules, completedModules),
    failedModules: pickNumber(summaryCandidate.failedModules, failedModules),
    averageConfidence: pickNumber(
      summaryCandidate.averageConfidence,
      moduleResults.length > 0 ? Math.round(totalConfidence / moduleResults.length) : 0,
    ),
    findingsBySeverity: isRecord(summaryCandidate.findingsBySeverity)
      ? Object.fromEntries(
          Object.entries({ ...DEFAULT_SEVERITY_COUNTS, ...summaryCandidate.findingsBySeverity }).map(
            ([key, value]) => [key, pickNumber(value, 0)],
          ),
        )
      : findingsBySeverity,
    findingsBySourceTool: isRecord(summaryCandidate.findingsBySourceTool)
      ? Object.fromEntries(
          Object.entries(summaryCandidate.findingsBySourceTool).map(([key, value]) => [
            key,
            pickNumber(value, 0),
          ]),
        )
      : findingsBySourceTool,
  };
}

export function normalizeDeepScanResult(input: unknown, targetFallback = ''): DeepScanResult {
  const record = isRecord(input) ? input : {};
  const moduleResults = Array.isArray(record.moduleResults)
    ? record.moduleResults.map((moduleResult) => normalizeAssessmentModuleResult(moduleResult))
    : [];
  const findings = Array.isArray(record.findings)
    ? record.findings.map((finding, index) => normalizeScanFinding(finding, index))
    : [];

  const reconRecord = isRecord(record.reconData) ? record.reconData : {};
  const reconData: ReconData = {
    ip: pickString(reconRecord.ip, 'Unknown'),
    tlsIssuer: pickString(reconRecord.tlsIssuer, 'Unknown'),
    tlsValidTo: pickString(reconRecord.tlsValidTo, 'Unknown'),
    dnsDetails: pickStringArray(reconRecord.dnsDetails),
  };

  const executionRecord = isRecord(record.executionMeta) ? record.executionMeta : {};
  const defaultMeta = createEmptyExecutionMeta(targetFallback);
  const scanStartedAt = pickNumber(executionRecord.scanStartedAt, defaultMeta.scanStartedAt);
  const scanEndedAt = pickNumber(executionRecord.scanEndedAt, defaultMeta.scanEndedAt);
  const target = pickString(executionRecord.target, targetFallback);

  return {
    reconData,
    findings,
    moduleResults,
    scanSummary: summarizeModules(moduleResults, findings, record.scanSummary),
    executionMeta: {
      scanStartedAt,
      scanEndedAt: scanEndedAt >= scanStartedAt ? scanEndedAt : scanStartedAt,
      scanDurationMs: pickNumber(
        executionRecord.scanDurationMs,
        Math.max(0, scanEndedAt - scanStartedAt),
      ),
      target,
    },
  };
}

export function normalizeScanErrorResponse(input: unknown, targetFallback = ''): ScanErrorResponse {
  const record = isRecord(input) ? input : {};
  const candidateResult = record.result ?? input;

  return {
    error: pickString(record.error, 'Assessment request failed.'),
    code: typeof record.code === 'string' ? record.code : undefined,
    result: normalizeDeepScanResult(candidateResult, targetFallback),
  };
}

export function parseScanRequestBody(input: unknown):
  | { ok: true; value: ScanRequest }
  | { ok: false; error: string } {
  if (!isRecord(input)) {
    return { ok: false, error: 'Request body must be a JSON object.' };
  }

  const rawTarget = typeof input.target === 'string'
    ? input.target
    : typeof input.targetHostname === 'string'
      ? input.targetHostname
      : '';

  const target = normalizeOperatorTargetInput(rawTarget);

  if (!target) {
    return { ok: false, error: 'Target hostname or label is required.' };
  }

  return { ok: true, value: { target } };
}
