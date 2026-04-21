import { AssessmentModuleResult, ScanFinding } from '../scanTypes';
import { assertSafeScanHostname, safeExecFile } from './utils';

export async function runDiscoveryScanner(hostname: string): Promise<AssessmentModuleResult> {
  const start = Date.now();
  const safeHostname = assertSafeScanHostname(hostname);
  let stdout = '';
  const findings: ScanFinding[] = [];
  let ip = 'Unknown';
  const dnsDetails: string[] = [];
  const errors: string[] = [];
  let status: 'success' | 'failed' | 'partial' = 'success';

  try {
    const result = await safeExecFile('nmap', ['-sn', '-Pn', '--resolve-all', safeHostname], 15000);
    stdout = result.stdout;
    
    const ipMatch = stdout.match(/Nmap scan report for .* \(([0-9.]+)\)/);
    if (ipMatch) ip = ipMatch[1];
    else {
      const match = stdout.match(/Nmap scan report for ([0-9.]+)/);
      if (match) ip = match[1];
    }
    
    if (ip !== 'Unknown') {
      dnsDetails.push(`Resolved IPv4: ${ip} via Nmap`);
      dnsDetails.push(`DNS Mapping verified`);
    } else {
      dnsDetails.push(`Could not authoritative resolve IPv4`);
      status = 'partial';
      errors.push('No IPv4 mapping returned from Nmap ping sweep.');
    }

  } catch (e: unknown) {
    stdout = String(e);
    status = 'failed';
    errors.push(String(e));
  }

  return {
    moduleName: 'discoveryScanner',
    sourceTool: 'Nmap-Discovery',
    status,
    confidence: ip !== 'Unknown' ? 95 : 50,
    startedAt: start,
    endedAt: Date.now(),
    rawEvidence: stdout,
    normalizedEvidence: `NMAP Ping Scan & DNS Resolution for ${safeHostname}`,
    findings,
    extractedData: { ip, dnsDetails },
    errors
  };
}
