import { AssessmentModuleResult, ScanFinding } from '../scanTypes';
import { probeEndpoint, probePreferredOrigin, type HttpProbeResponse } from './httpProbe';
import { assertSafeScanHostname, safeExecFile } from './utils';

type EndpointProbe = {
  key: string;
  label: string;
  path: string;
  response?: HttpProbeResponse;
  error?: string;
};

const HTML_ROUTE_LIMIT = 12;

function countMatches(text: string, pattern: RegExp): number {
  return [...text.matchAll(pattern)].length;
}

function extractTitle(html: string): string {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim() : 'Unknown title';
}

function extractInternalRoutes(html: string): string[] {
  const routes = new Set<string>();
  for (const match of html.matchAll(/href=["']([^"'#]+)(?:#[^"']*)?["']/gi)) {
    const href = match[1].trim();
    if (!href.startsWith('/') || href.startsWith('//')) {
      continue;
    }
    routes.add(href);
  }
  return [...routes].sort();
}

function findBootstrapVersion(html: string): string | null {
  const match = html.match(/bootstrap\/(\d+\.\d+(?:\.\d+)?)/i);
  return match ? match[1] : null;
}

function compareSemver(a: string, b: string): number {
  const left = a.split('.').map((part) => Number.parseInt(part, 10) || 0);
  const right = b.split('.').map((part) => Number.parseInt(part, 10) || 0);
  const maxLength = Math.max(left.length, right.length);

  for (let index = 0; index < maxLength; index += 1) {
    const diff = (left[index] ?? 0) - (right[index] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }

  return 0;
}

function makeFinding(
  id: string,
  category: ScanFinding['category'],
  title: string,
  severity: ScanFinding['severity'],
  description: string,
  evidence: string,
  remediation?: string,
): ScanFinding {
  return {
    id,
    category,
    title,
    severity,
    description,
    evidence,
    remediation,
  };
}

function summarizeProbe(probe: EndpointProbe): string {
  if (probe.response) {
    const contentType = probe.response.headers['content-type'] ?? 'unknown';
    return `${probe.label}: HTTP ${probe.response.status} (${contentType})`;
  }
  return `${probe.label}: probe error (${probe.error})`;
}

export async function runWebAssessment(hostname: string): Promise<AssessmentModuleResult> {
  const start = Date.now();
  const safeHostname = assertSafeScanHostname(hostname);
  const findings: ScanFinding[] = [];
  const errors: string[] = [];
  let status: 'success' | 'failed' | 'partial' = 'success';
  let wafEvidence = '';
  let homepageEvidence = '';
  let probeEvidence = '';
  let successfulEndpointProbes = 0;

  try {
    const result = await safeExecFile(
      'nmap',
      ['-p', '80,443', '--script=http-waf-detect', '-Pn', safeHostname],
      15000,
    );
    wafEvidence = result.stdout;

    if (wafEvidence.includes('http-waf-detect: WAF is active')) {
      findings.push(
        makeFinding(
          'waf-detect',
          'Info',
          'WAF presence indicated',
          'Info',
          'The hybrid scan observed edge protection behavior consistent with a Web Application Firewall or managed reverse proxy.',
          'Nmap http-waf-detect reported active filtering in front of the target.',
        ),
      );
    }
  } catch (error: unknown) {
    status = 'partial';
    errors.push(`WAF heuristic failed: ${String(error)}`);
  }

  try {
    const homepage = await probePreferredOrigin(safeHostname, {
      method: 'GET',
      timeoutMs: 15000,
      readBody: true,
    });

    const title = extractTitle(homepage.body);
    const formsCount = countMatches(homepage.body, /<form\b/gi);
    const inputsCount = countMatches(homepage.body, /<input\b/gi);
    const buttonsCount = countMatches(homepage.body, /<button\b/gi);
    const internalRoutes = extractInternalRoutes(homepage.body);
    const sampledRoutes = internalRoutes.slice(0, HTML_ROUTE_LIMIT);
    const bootstrapVersion = findBootstrapVersion(homepage.body);
    const hasSearchSurface =
      /<form[^>]+action=["'][^"']*search/i.test(homepage.body) ||
      /<input[^>]+type=["']search["']/i.test(homepage.body) ||
      /<input[^>]+name=["']q["']/i.test(homepage.body);

    const endpointDefinitions = [
      { key: 'robots', label: 'robots.txt', path: '/robots.txt' },
      { key: 'sitemap', label: 'sitemap.xml', path: '/sitemap.xml' },
      { key: 'securityTxt', label: 'security.txt', path: '/security.txt' },
      { key: 'wellKnownSecurityTxt', label: '.well-known/security.txt', path: '/.well-known/security.txt' },
      { key: 'rssFeed', label: 'RSS feed', path: '/feeds/added/rss/' },
      { key: 'contact', label: 'Contact workflow', path: '/contact/' },
      { key: 'submission', label: 'Submission workflow', path: '/submit/vm/' },
    ] as const;

    const endpointProbes: EndpointProbe[] = await Promise.all(
      endpointDefinitions.map(async (definition) => {
        try {
          const response = await probeEndpoint(homepage.url, definition.path, 8000);
          return { ...definition, response };
        } catch (error: unknown) {
          return { ...definition, error: String(error) };
        }
      }),
    );

    successfulEndpointProbes = endpointProbes.filter((probe) => probe.response).length;
    const endpointProbeErrors = endpointProbes
      .filter((probe) => probe.error)
      .map((probe) => `${probe.label}: ${probe.error}`);
    if (endpointProbeErrors.length > 0) {
      errors.push(...endpointProbeErrors);
    }
    const probeMap = Object.fromEntries(endpointProbes.map((probe) => [probe.key, probe]));

    homepageEvidence = [
      `[Homepage Probe]`,
      `Final URL: ${homepage.url}`,
      `HTTP Status: ${homepage.status}`,
      `Title: ${title}`,
      `Forms: ${formsCount}, inputs: ${inputsCount}, buttons: ${buttonsCount}`,
      `Sampled internal routes: ${sampledRoutes.length > 0 ? sampledRoutes.join(', ') : 'none observed'}`,
      `Bootstrap version: ${bootstrapVersion ?? 'not observed'}`,
    ].join('\n');

    probeEvidence = [
      `[Surface Probes]`,
      ...endpointProbes.map((probe) => summarizeProbe(probe)),
    ].join('\n');

    const sitemapProbe = probeMap.sitemap;
    if (sitemapProbe?.response?.status === 200) {
      findings.push(
        makeFinding(
          'web-sitemap-exposure',
          'OSINT',
          'Public sitemap exposes broad content inventory',
          'Low',
          'A publicly accessible sitemap expands unauthenticated route discovery and helps attackers enumerate content and entry points at scale.',
          `Observed ${sitemapProbe.label} at ${sitemapProbe.response.url} returning HTTP 200.`,
          'Keep the sitemap intentional, remove sensitive or low-value routes from the generated index, and align it with a deliberate public-content exposure policy.',
        ),
      );
    }

    const feedProbe = probeMap.rssFeed;
    if (feedProbe?.response?.status === 200) {
      findings.push(
        makeFinding(
          'web-rss-feed',
          'OSINT',
          'Public RSS feed expands unauthenticated monitoring surface',
          'Info',
          'A machine-readable feed allows continuous monitoring of newly published content and can accelerate external reconnaissance.',
          `Observed ${feedProbe.label} at ${feedProbe.response.url} returning HTTP 200.`,
          'Retain the feed only if it is intentionally public and ensure it does not disclose preview-only or internal publication metadata.',
        ),
      );
    }

    const securityTxtMissing =
      probeMap.securityTxt?.response?.status === 404 &&
      probeMap.wellKnownSecurityTxt?.response?.status === 404;
    if (securityTxtMissing) {
      findings.push(
        makeFinding(
          'web-missing-security-txt',
          'Misconfiguration',
          'Missing security.txt contact metadata',
          'Low',
          'The site does not publish a security.txt file at the conventional locations, which weakens the standard path for coordinated disclosure and operator contact.',
          'Both /security.txt and /.well-known/security.txt returned HTTP 404 during live probing.',
          'Publish a security.txt file with security contact, policy, and disclosure metadata under /.well-known/security.txt.',
        ),
      );
    }

    const contactOpen = probeMap.contact?.response?.status === 200;
    const submissionOpen = probeMap.submission?.response?.status === 200;
    if (hasSearchSurface || contactOpen || submissionOpen) {
      const exposedWorkflows = [
        hasSearchSurface ? 'homepage search workflow' : null,
        contactOpen ? '/contact/' : null,
        submissionOpen ? '/submit/vm/' : null,
      ].filter(Boolean);

      findings.push(
        makeFinding(
          'web-public-workflows',
          'OSINT',
          'Public interaction workflows are readily enumerable',
          'Info',
          'The application exposes interactive search/contact/submission flows to unauthenticated users, which increases fuzzing, spam, and enumeration opportunities even when those flows are legitimate business features.',
          `Observed ${exposedWorkflows.join(', ')} during live probing.`,
          'Ensure these workflows are rate-limited, monitored, and covered by server-side validation and abuse controls.',
        ),
      );
    }

    if (internalRoutes.length >= 10) {
      findings.push(
        makeFinding(
          'web-route-inventory',
          'OSINT',
          'Homepage markup discloses a rich internal route inventory',
          'Info',
          'The landing page itself exposes a substantial set of internal routes, which lowers the cost of unauthenticated reconnaissance.',
          `Observed ${internalRoutes.length} unique internal routes in homepage markup, including ${sampledRoutes.slice(0, 6).join(', ')}.`,
          'Keep the public navigation deliberate, avoid leaking low-value operational routes in templates, and treat route enumeration as part of the exposed attack surface.',
        ),
      );
    }

    if (bootstrapVersion && compareSemver(bootstrapVersion, '5.0.0') < 0) {
      findings.push(
        makeFinding(
          'web-legacy-bootstrap',
          'Misconfiguration',
          'Legacy Bootstrap dependency observed in client-side surface',
          'Low',
          'The homepage references an older Bootstrap 4.x asset, which is a signal to review client-side dependency patch currency and supply-chain governance.',
          `Observed Bootstrap ${bootstrapVersion} in the homepage asset references.`,
          'Review the front-end dependency inventory, confirm the exact asset provenance, and upgrade or pin to a current, supported version where feasible.',
        ),
      );
    }
  } catch (error: unknown) {
    errors.push(`Homepage content probe failed: ${String(error)}`);
  }

  if (!homepageEvidence && !wafEvidence) {
    status = 'failed';
  } else if (errors.length > 0) {
    status = 'partial';
  }

  const normalizedEvidence = homepageEvidence
    ? `Enumerated public web surface with ${successfulEndpointProbes} endpoint probes and identified ${findings.length} web-facing observations.`
    : 'Web surface assessment fell back to limited network heuristics only.';

  return {
    moduleName: 'webAssessment',
    sourceTool: 'Hybrid-Web-Surface-Assessment',
    status,
    confidence: homepageEvidence ? 88 : wafEvidence ? 60 : 0,
    startedAt: start,
    endedAt: Date.now(),
    rawEvidence: [homepageEvidence, probeEvidence, wafEvidence].filter(Boolean).join('\n\n'),
    normalizedEvidence,
    findings,
    errors,
  };
}
