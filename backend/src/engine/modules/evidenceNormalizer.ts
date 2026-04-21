import { AssessmentModuleResult, ScanFinding } from '../scanTypes';

export function normalizeEvidence(results: AssessmentModuleResult[]): string[] {
  return results.map(r => `[${r.sourceTool}] (${r.endedAt - r.startedAt}ms) ${r.normalizedEvidence}`);
}

export function deduplicateFindings(findings: ScanFinding[]): ScanFinding[] {
  const seen = new Map<string, ScanFinding>();
  for (const f of findings) {
    const existing = seen.get(f.id);
    if (!existing || ((existing.confidence ?? 0) < (f.confidence ?? 0))) {
      seen.set(f.id, f);
    }
  }
  return [...seen.values()];
}
