import {
  createEmptyScanResult,
  normalizeAssessmentModuleResult,
  normalizeDeepScanResult,
  parseScanRequestBody,
  type AssessmentModuleResult,
  type DeepScanResult,
  type ScanRequest,
} from '../../../shared/scanContract';

export {
  createEmptyScanResult,
  normalizeAssessmentModuleResult,
  normalizeDeepScanResult,
  parseScanRequestBody,
};

export function finalizeModuleResult(
  input: unknown,
  fallback: Partial<AssessmentModuleResult>,
): AssessmentModuleResult {
  return normalizeAssessmentModuleResult(input, fallback);
}

export function finalizeDeepScanResult(input: unknown, target: string): DeepScanResult {
  return normalizeDeepScanResult(input, target);
}

export function createScanErrorResult(target: string): DeepScanResult {
  return createEmptyScanResult(target);
}

export type { AssessmentModuleResult, DeepScanResult, ScanRequest };
