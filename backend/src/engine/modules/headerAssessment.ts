import { AssessmentModuleResult, ScanFinding } from '../scanTypes';
import { assertSafeScanHostname, safeExecFile } from './utils';
import { probePreferredOrigin } from './httpProbe';

function buildHeaderFinding(
  id: string,
  title: string,
  severity: ScanFinding['severity'],
  description: string,
  evidence: string,
  cwe?: string,
  remediation?: string,
): ScanFinding {
  return {
    id,
    category: 'Web App',
    title,
    severity,
    description,
    evidence,
    cwe,
    remediation,
  };
}

export async function runHeaderAssessment(hostname: string): Promise<AssessmentModuleResult> {
  const start = Date.now();
  const safeHostname = assertSafeScanHostname(hostname);
  const findings: ScanFinding[] = [];
  const errors: string[] = [];
  let status: 'success' | 'failed' | 'partial' = 'success';
  let nmapEvidence = '';
  let httpEvidence = '';
  let observedHeaders: string[] = [];

  try {
    const result = await safeExecFile(
      'nmap',
      [
        '-p',
        '443',
        '--script=http-security-headers,http-headers',
        '--script-args',
        'http.useragent=Mozilla/5.0 WAAP',
        '-Pn',
        safeHostname,
      ],
      15000,
    );
    nmapEvidence = result.stdout;

  } catch (e: unknown) {
    errors.push(`Nmap header script failed: ${String(e)}`);
    status = 'partial';
  }

  try {
    const homepage = await probePreferredOrigin(safeHostname, {
      method: 'GET',
      timeoutMs: 12000,
      readBody: false,
      headers: {
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });

    const headers = homepage.headers;
    observedHeaders = Object.keys(headers).sort();
    const finalUrl = homepage.url;
    const isHttps = finalUrl.startsWith('https://');
    const headerNames = observedHeaders.length > 0 ? observedHeaders.join(', ') : 'none observed';
    const csp = headers['content-security-policy'] ?? '';
    const frameAncestorsProtected = /frame-ancestors\s+[^;]+/i.test(csp);
    const xFrameOptions = (headers['x-frame-options'] ?? '').toLowerCase();
    const clickjackingProtected =
      xFrameOptions.includes('sameorigin') ||
      xFrameOptions.includes('deny') ||
      frameAncestorsProtected;

    httpEvidence = [
      `[HTTP Header Probe]`,
      `Final URL: ${finalUrl}`,
      `HTTP Status: ${homepage.status}`,
      `Observed headers: ${headerNames}`,
    ].join('\n');

    if (isHttps && !headers['strict-transport-security']) {
      findings.push(
        buildHeaderFinding(
          'hdr-hsts',
          'Missing HTTP Strict Transport Security (HSTS)',
          'Medium',
          'The HTTPS response did not advertise HSTS, so browsers are not instructed to enforce secure transport for future requests.',
          `Observed on ${finalUrl} without Strict-Transport-Security.`,
          'CWE-319: Cleartext Transmission of Sensitive Information',
          'Return a Strict-Transport-Security header with an appropriate max-age and includeSubDomains only after HTTPS is consistently enforced.',
        ),
      );
    }

    if (!clickjackingProtected) {
      findings.push(
        buildHeaderFinding(
          'hdr-clickjack',
          'Clickjacking protections not observed',
          'Medium',
          'Neither X-Frame-Options nor a CSP frame-ancestors policy was observed on the primary response.',
          `Observed on ${finalUrl} without X-Frame-Options or frame-ancestors protection.`,
          'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
          'Set X-Frame-Options to DENY or SAMEORIGIN, or enforce an equivalent CSP frame-ancestors policy.',
        ),
      );
    }

    if (!headers['content-security-policy']) {
      findings.push(
        buildHeaderFinding(
          'hdr-csp',
          'Missing Content Security Policy (CSP)',
          'Medium',
          'The primary response did not include a Content-Security-Policy header, reducing client-side control over script, frame, and resource loading.',
          `Observed on ${finalUrl} without Content-Security-Policy.`,
          'CWE-693: Protection Mechanism Failure',
          'Deploy a restrictive Content-Security-Policy tailored to the application’s required script, style, frame, and connect sources.',
        ),
      );
    }

    if ((headers['x-content-type-options'] ?? '').toLowerCase() !== 'nosniff') {
      findings.push(
        buildHeaderFinding(
          'hdr-nosniff',
          'Missing X-Content-Type-Options header',
          'Low',
          'The response did not advertise X-Content-Type-Options: nosniff, leaving more room for unsafe MIME sniffing behavior in browsers.',
          `Observed on ${finalUrl} without X-Content-Type-Options: nosniff.`,
          'CWE-16: Configuration',
          'Set X-Content-Type-Options to nosniff on application responses.',
        ),
      );
    }

    if (!headers['referrer-policy']) {
      findings.push(
        buildHeaderFinding(
          'hdr-referrer-policy',
          'Missing Referrer-Policy header',
          'Low',
          'The application did not define a Referrer-Policy, so browsers may disclose more navigation context than necessary.',
          `Observed on ${finalUrl} without Referrer-Policy.`,
          'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
          'Add an explicit Referrer-Policy such as strict-origin-when-cross-origin or a stricter equivalent that matches business needs.',
        ),
      );
    }

    if (!headers['permissions-policy']) {
      findings.push(
        buildHeaderFinding(
          'hdr-permissions-policy',
          'Missing Permissions-Policy header',
          'Low',
          'The response did not define a Permissions-Policy, so browser features are not explicitly restricted at the document level.',
          `Observed on ${finalUrl} without Permissions-Policy.`,
          'CWE-16: Configuration',
          'Publish a Permissions-Policy that disables unused browser capabilities such as camera, microphone, geolocation, and USB access.',
        ),
      );
    }
  }
  catch (e: unknown) {
    errors.push(`HTTP header probe failed: ${String(e)}`);
  }

  const hasPortTable = /PORT\s+STATE\s+SERVICE/.test(nmapEvidence);
  const hasHeaderScriptOutput =
    nmapEvidence.includes('http-security-headers') || nmapEvidence.includes('http-headers');

  if (!httpEvidence && !hasPortTable && !hasHeaderScriptOutput) {
    status = 'failed';
    errors.push('No HTTP header evidence could be collected from network probes.');
  } else if (errors.length > 0) {
    status = 'partial';
  }

  const observedSummary =
    observedHeaders.length > 0 ? `Observed ${observedHeaders.length} response headers.` : 'No headers observed.';
  const normalizedEvidence =
    findings.length > 0
      ? `${observedSummary} Identified ${findings.length} header hardening gaps on the primary response.`
      : `${observedSummary} Core header hardening controls were present or no gaps were observable.`;

  return {
    moduleName: 'headerAssessment',
    sourceTool: 'Hybrid-HTTP-Header-Assessment',
    status,
    confidence: httpEvidence ? 92 : hasHeaderScriptOutput ? 70 : 40,
    startedAt: start,
    endedAt: Date.now(),
    rawEvidence: [httpEvidence, nmapEvidence].filter(Boolean).join('\n\n'),
    normalizedEvidence,
    findings,
    errors,
  };
}
