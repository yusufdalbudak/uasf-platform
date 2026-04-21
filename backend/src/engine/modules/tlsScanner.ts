import { AssessmentModuleResult, ScanFinding } from '../scanTypes';
import { assertSafeScanHostname, safeExecFile } from './utils';

export async function runTlsScanner(hostname: string): Promise<AssessmentModuleResult> {
  const start = Date.now();
  const safeHostname = assertSafeScanHostname(hostname);
  let stdout = '';
  let tlsIssuer = 'Unknown';
  let tlsValidTo = 'Unknown';
  const errors: string[] = [];
  let status: 'success' | 'failed' | 'partial' = 'success';

  try {
    const result = await safeExecFile(
      'nmap',
      ['-p', '443', '--script=ssl-cert', '-Pn', safeHostname],
      15000,
    );
    stdout = result.stdout;

    const orgMatch = stdout.match(/organizationName=([^/]+)/);
    const cnMatch = stdout.match(/commonName=([^/]+)/);
    if (orgMatch) tlsIssuer = orgMatch[1].trim();
    else if (cnMatch) tlsIssuer = cnMatch[1].trim();

    const notAfterMatch = stdout.match(/Not valid after: *([0-9:T-]+)/);
    if (notAfterMatch) tlsValidTo = notAfterMatch[1];
    
    if (tlsIssuer === 'Unknown') {
      status = 'partial';
      errors.push('No TLS certificate found on port 443.');
    }

  } catch (e: unknown) {
    stdout = String(e);
    status = 'failed';
    errors.push(`TLS scan error: ${e}`);
  }

  return {
    moduleName: 'tlsScanner',
    sourceTool: 'Nmap-SSL-Cert',
    status,
    confidence: tlsIssuer !== 'Unknown' ? 90 : 20,
    startedAt: start,
    endedAt: Date.now(),
    rawEvidence: stdout,
    normalizedEvidence: `Extracted X.509 Certificate attributes (Issuer: ${tlsIssuer})`,
    findings: [],
    extractedData: { tlsIssuer, tlsValidTo },
    errors
  };
}
