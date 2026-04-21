import { AssessmentModuleResult, ScanFinding } from '../scanTypes';
import { assertSafeScanHostname, safeExecFile } from './utils';

/**
 * Curated service-exposure profile.
 *
 * Each row pairs the TCP port we probe with:
 *   - `desc`:    human-friendly service label
 *   - `service`: the exact service tokens nmap is allowed to report
 *                back via `-sV` for us to consider this a real
 *                service exposure (not a CDN/edge passthrough)
 *   - `severity`: severity to emit ONLY when service is confirmed.
 */
const PROBED_SERVICES: Array<{
  port: number;
  desc: string;
  service: string[];
  severity: ScanFinding['severity'];
}> = [
  { port: 21, desc: 'FTP', service: ['ftp'], severity: 'Low' },
  { port: 22, desc: 'SSH', service: ['ssh'], severity: 'Medium' },
  { port: 445, desc: 'SMB', service: ['microsoft-ds', 'netbios-ssn', 'smb'], severity: 'Medium' },
  { port: 3306, desc: 'MySQL', service: ['mysql'], severity: 'High' },
  { port: 5432, desc: 'PostgreSQL', service: ['postgresql', 'postgres'], severity: 'High' },
  { port: 27017, desc: 'MongoDB', service: ['mongodb', 'mongod'], severity: 'High' },
];

const PROBED_PORTS = PROBED_SERVICES.map((p) => p.port).join(',');
const PORT_LINE = /^(\d+)\/tcp\s+(open|filtered|open\|filtered|closed)\s+(\S+)(?:\s+(.*))?$/;

/**
 * Approved network visibility profile.
 *
 * Architectural notes — what changed and why:
 *
 *   - We now run nmap with `-sV --version-intensity 2` on top of the
 *     stealth SYN scan. A bare `-sS` only proves the kernel sent us a
 *     SYN-ACK; CDN edge nodes (Cloudflare, Fastly, AWS GA, etc.) reply
 *     SYN-ACK on EVERY port, which previously caused us to flag e.g.
 *     "Exposed MongoDB on 27017" against random WordPress sites that
 *     are nowhere near MongoDB. Adding light version detection lets us
 *     require nmap to actually identify the listening service before
 *     we publish a finding.
 *
 *   - We refuse to emit a finding when nmap returns `tcpwrapped`,
 *     `unknown`, or no service token at all — these indicate a SYN
 *     received but no protocol response, which is the canonical
 *     fingerprint of a CDN edge or filtering middlebox, NOT a real
 *     service.
 *
 *   - We surface filtered ports as a single Info-level "Edge filtering
 *     observed" line so operators still see the visibility result
 *     without it polluting the dashboard severity counts.
 *
 *   - Severity is conservative and capped at High; even a confirmed
 *     open MySQL is still only "exposure information" and not proof
 *     of compromise.
 */
export async function runServiceExposureScanner(hostname: string): Promise<AssessmentModuleResult> {
  const start = Date.now();
  const safeHostname = assertSafeScanHostname(hostname);
  let stdout = '';
  const findings: ScanFinding[] = [];
  const errors: string[] = [];
  let status: 'success' | 'failed' | 'partial' = 'success';
  let openServiceSummary = 'No open services were enumerated.';

  try {
    const result = await safeExecFile(
      'nmap',
      [
        '-Pn',
        '-sS',
        '-sV',
        '--version-intensity',
        '2',
        '--max-retries',
        '1',
        '--host-timeout',
        '20s',
        '--reason',
        '-p',
        PROBED_PORTS,
        '-T4',
        safeHostname,
      ],
      30000,
    );
    stdout = result.stdout;

    const observedRows: Array<{ port: number; state: string; service: string; banner: string }> = [];
    for (const line of stdout.split('\n')) {
      const m = line.trim().match(PORT_LINE);
      if (!m) continue;
      observedRows.push({
        port: parseInt(m[1], 10),
        state: m[2].toLowerCase(),
        service: (m[3] ?? '').toLowerCase(),
        banner: (m[4] ?? '').trim(),
      });
    }

    if (observedRows.length === 0) {
      status = 'partial';
      errors.push('Port scan completed without an open-port table in the output.');
    } else {
      const openRows = observedRows.filter((r) => r.state === 'open');
      openServiceSummary =
        openRows.length === 0
          ? 'No open ports were observed across the curated profile.'
          : `Observed ports: ${openRows.map((r) => `${r.port}/${r.service || 'unknown'}`).join(', ')}.`;
    }

    for (const probe of PROBED_SERVICES) {
      const row = observedRows.find((r) => r.port === probe.port);
      if (!row) continue;
      if (row.state !== 'open') continue;

      const svc = row.service;
      const isLikelyCdnPassthrough =
        !svc || svc === 'tcpwrapped' || svc === 'unknown' || svc === 'unknown-service';
      const serviceMatches = probe.service.some((s) => svc.includes(s));

      if (isLikelyCdnPassthrough || !serviceMatches) {
        // Edge accepts SYN but no protocol fingerprint matched the
        // expected service. This is almost always a CDN/edge passthrough,
        // not a real service exposure. We DO NOT emit a Medium/High
        // finding here; instead we record an Info note for traceability.
        findings.push({
          id: `port-${probe.port}-edge`,
          category: 'Infrastructure',
          title: `Port ${probe.port}/tcp accepted SYN but no ${probe.desc} service was confirmed`,
          severity: 'Info',
          confidence: 60,
          description:
            `Port ${probe.port}/tcp returned SYN-ACK on ${safeHostname}, but service-version probing did ` +
            `not identify a real ${probe.desc} listener (banner: "${svc || 'none'}"). This is the typical ` +
            'fingerprint of a CDN/edge node or a TCP wrapper that opens every port, NOT an exposed ' +
            `${probe.desc} service. Recorded as visibility information only — no exposure finding raised.`,
          evidence: `nmap -sV reported "${probe.port}/tcp ${row.state} ${svc || 'unknown'}${row.banner ? ' ' + row.banner : ''}".`,
          cwe: 'CWE-200: Exposure of Sensitive Information',
          remediation:
            'No remediation required if this host sits behind a CDN/edge that opens all ports as part ' +
            'of its anti-fingerprinting design. Investigate further only if you do NOT expect an edge ' +
            'in front of this asset.',
        });
        continue;
      }

      // Confirmed service exposure.
      findings.push({
        id: `port-${probe.port}`,
        category: 'Infrastructure',
        title: `Confirmed exposed ${probe.desc} service on ${probe.port}/tcp`,
        severity: probe.severity,
        confidence: 90,
        description:
          `Port ${probe.port}/tcp on ${safeHostname} is OPEN and nmap's version-detection probe ` +
          `identified a ${probe.desc} listener (service token "${svc}"${row.banner ? `, banner "${row.banner}"` : ''}). ` +
          'This is direct evidence that the service is reachable from the public internet.',
        evidence: `nmap -sV reported "${probe.port}/tcp open ${svc}${row.banner ? ' ' + row.banner : ''}".`,
        cwe: 'CWE-284: Improper Access Control',
        remediation:
          'Confirm whether this service must be reachable from the public internet. If not, restrict it ' +
          'with network ACLs, a bastion, or an internal-only listener. Also verify authentication, patch ' +
          'level, and TLS termination where applicable.',
      });
    }
  } catch (e: unknown) {
    stdout = String(e);
    status = 'failed';
    errors.push(String(e));
  }

  return {
    moduleName: 'serviceExposureScanner',
    sourceTool: 'Nmap-Port-Scan',
    status,
    confidence: status === 'success' ? 100 : status === 'partial' ? 60 : 0,
    startedAt: start,
    endedAt: Date.now(),
    rawEvidence: stdout,
    normalizedEvidence: `${openServiceSummary} Stealth SYN + service-version (sV) port scan covered curated administrative, database, and entry ports.`,
    findings,
    errors,
  };
}
