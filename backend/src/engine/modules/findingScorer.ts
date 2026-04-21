import { ScanFinding } from '../scanTypes';

const SEVERITY_SCORES: Record<string, number> = {
  'Critical': 100,
  'High': 80,
  'Medium': 50,
  'Low': 20,
  'Info': 0
};

export function scoreFinding(finding: ScanFinding): ScanFinding {
  let confidence = finding.confidence ?? 50;
  
  if (finding.evidence?.includes('Authoritative mapping') || finding.evidence?.includes('Nmap scan report')) {
    confidence = Math.min(100, confidence + 20);
  }

  return {
    ...finding,
    confidence
  };
}

export function sortFindingsByScoring(findings: ScanFinding[]): ScanFinding[] {
  return [...findings].sort((a, b) => {
    const sevA = SEVERITY_SCORES[a.severity] || 0;
    const sevB = SEVERITY_SCORES[b.severity] || 0;
    if (sevA !== sevB) return sevB - sevA;
    return (b.confidence || 0) - (a.confidence || 0);
  });
}
