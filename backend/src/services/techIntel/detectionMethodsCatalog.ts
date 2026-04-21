/**
 * UASF Tech Intelligence — Detection Methods Catalog
 *
 * Operator-facing catalog of every fingerprint detection technique the
 * engine can run.  The Detection Methods tab in the Tech Intelligence
 * dashboard reads this catalog directly so operators can audit the
 * toolbox without reading adapter code.
 *
 * Each entry cites the OWASP WSTG v4 test that inspired it whenever
 * possible.  Entries marked `active` probe the target; entries marked
 * `passive` only interpret traffic / responses that would be emitted
 * anyway.  Active probes remain safe-by-design:
 *
 *   - They use canonical HTTP verbs and bounded timeouts.
 *   - They never attempt bypass, stealth, fragmentation, spoofing,
 *     or payload-evasion behaviour.
 *   - They are gated by the approved-asset policy before the engine runs.
 */

import type { DetectionMethodCatalogEntry } from './signalTypes';

export const DETECTION_METHODS_CATALOG: DetectionMethodCatalogEntry[] = [
  // ------------------------------------------------------------------
  // 1. Passive HTTP / TLS fingerprinting
  // ------------------------------------------------------------------
  {
    id: 'passive_http.server_header',
    family: 'passive_http',
    label: 'Server header banner',
    description:
      'Reads the `Server` response header and attributes product/version when the value is recognisable (e.g. `nginx/1.24.0`).',
    owaspReference: 'OWASP WSTG-INFO-02',
    kind: 'passive',
    typicalWeight: 0.85,
  },
  {
    id: 'passive_http.x_powered_by',
    family: 'passive_http',
    label: 'X-Powered-By header',
    description:
      'Reads the `X-Powered-By` response header.  Common vector for runtime / language disclosure (PHP, ASP.NET, Express).',
    owaspReference: 'OWASP WSTG-INFO-02',
    kind: 'passive',
    typicalWeight: 0.8,
  },
  {
    id: 'passive_http.via_header',
    family: 'passive_http',
    label: 'Via / forwarding header',
    description: 'Parses `Via`, `X-Forwarded-Server`, `X-Cache` headers to identify reverse proxies / CDNs.',
    kind: 'passive',
    typicalWeight: 0.65,
  },
  {
    id: 'passive_http.cookie_marker',
    family: 'passive_http',
    label: 'Cookie name marker',
    description:
      'Inspects `Set-Cookie` names and prefixes (e.g. `JSESSIONID`, `PHPSESSID`, `BIGipServer…`, `__cf_bm`).',
    kind: 'passive',
    typicalWeight: 0.6,
  },
  {
    id: 'passive_http.security_headers',
    family: 'passive_http',
    label: 'Security-header profile',
    description:
      'Scores the presence/absence pattern of CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy — a soft stack fingerprint.',
    owaspReference: 'OWASP WSTG-CONF-08',
    kind: 'passive',
    typicalWeight: 0.25,
  },
  {
    id: 'passive_http.edge_headers',
    family: 'passive_http',
    label: 'Edge / CDN headers',
    description:
      'Reads vendor-specific edge headers (`cf-ray`, `x-amz-cf-id`, `x-akamai-*`, `x-azure-ref`, `x-vercel-*`).',
    kind: 'passive',
    typicalWeight: 0.75,
  },
  {
    id: 'passive_http.cache_mitigation',
    family: 'passive_http',
    label: 'Cache / mitigation hints',
    description:
      'Reads `X-Cache-Status`, `CF-Cache-Status`, `X-Served-By`, and similar to hint at the serving layer.',
    kind: 'passive',
    typicalWeight: 0.35,
  },
  // ------------------------------------------------------------------
  // 2. TLS fingerprinting
  // ------------------------------------------------------------------
  {
    id: 'tls.certificate_metadata',
    family: 'tls',
    label: 'Certificate issuer / SAN',
    description:
      'Parses certificate issuer, SANs, and validity.  CDN / hosting platforms leak themselves through the issuer CN (e.g. Amazon, Google Trust Services).',
    owaspReference: 'OWASP WSTG-CRYP-01',
    kind: 'passive',
    typicalWeight: 0.5,
  },
  // ------------------------------------------------------------------
  // 3. Body and markup fingerprinting
  // ------------------------------------------------------------------
  {
    id: 'markup.meta_generator',
    family: 'markup',
    label: 'Meta generator tag',
    description:
      'Reads `<meta name="generator">` which many CMSs (WordPress, Drupal, Ghost, Hugo) emit with an exact version.',
    owaspReference: 'OWASP WSTG-INFO-08',
    kind: 'passive',
    typicalWeight: 0.9,
  },
  {
    id: 'markup.body_signature',
    family: 'markup',
    label: 'HTML body signature',
    description:
      'Searches the HTML body for framework-specific markers (e.g. `wp-content`, `Shopify.theme`, `__NEXT_DATA__`, `data-reactroot`).',
    kind: 'passive',
    typicalWeight: 0.6,
  },
  {
    id: 'markup.asset_naming',
    family: 'markup',
    label: 'Static asset naming',
    description:
      'Looks at `<script>` / `<link>` URL patterns (e.g. `/wp-content/plugins/`, `/_next/static/`, `/assets/application-…`).',
    kind: 'passive',
    typicalWeight: 0.55,
  },
  {
    id: 'markup.inline_script_marker',
    family: 'markup',
    label: 'Inline script marker',
    description:
      'Looks at identifiers in inline `<script>` bodies (e.g. `window.__INITIAL_STATE__`, `Drupal.settings`, `jQuery`).',
    kind: 'passive',
    typicalWeight: 0.45,
  },
  {
    id: 'markup.html_comment',
    family: 'markup',
    label: 'HTML comment leakage',
    description:
      'Surfaces comment markers that leak platform identifiers (e.g. `<!-- Built with Hugo -->`).',
    owaspReference: 'OWASP WSTG-INFO-05',
    kind: 'passive',
    typicalWeight: 0.5,
  },
  // ------------------------------------------------------------------
  // 4. URL and route fingerprinting
  // ------------------------------------------------------------------
  {
    id: 'url_route.robots',
    family: 'url_route',
    label: 'robots.txt disclosure',
    description:
      'Issues a bounded GET to `/robots.txt` and inspects the disallow list for platform-specific paths.',
    owaspReference: 'OWASP WSTG-INFO-03',
    kind: 'active',
    typicalWeight: 0.5,
  },
  {
    id: 'url_route.sitemap',
    family: 'url_route',
    label: 'sitemap.xml disclosure',
    description: 'Issues a bounded GET to `/sitemap.xml` to surface CMS-managed paths.',
    owaspReference: 'OWASP WSTG-INFO-03',
    kind: 'active',
    typicalWeight: 0.3,
  },
  {
    id: 'url_route.security_txt',
    family: 'url_route',
    label: '.well-known/security.txt',
    description: 'Reads the operator-friendly disclosure file at `/.well-known/security.txt`.',
    kind: 'active',
    typicalWeight: 0.2,
  },
  {
    id: 'url_route.default_surface',
    family: 'url_route',
    label: 'Default surface probe',
    description:
      'Issues bounded HEAD requests to canonical platform paths (e.g. `/wp-login.php`, `/administrator/`, `/_next/static/chunks`, `/graphql`, `/api/`).  Status, size, and content-type are treated as signals — the engine never attempts authentication or parameter mutation.',
    owaspReference: 'OWASP WSTG-CONF-05',
    kind: 'active',
    typicalWeight: 0.6,
  },
  {
    id: 'url_route.favicon_fingerprint',
    family: 'url_route',
    label: 'Favicon hash',
    description:
      'Fetches `/favicon.ico` and produces a short hash of its bytes.  Platforms that ship a default favicon are identifiable even with stripped banners.',
    kind: 'active',
    typicalWeight: 0.35,
  },
  // ------------------------------------------------------------------
  // 5. DOM / XPath / structural features
  // ------------------------------------------------------------------
  {
    id: 'dom_structural.tag_profile',
    family: 'dom_structural',
    label: 'Tag frequency profile',
    description:
      'Counts common HTML tags (script, link, meta, div, section) to produce a structural feature vector that supports clustering-style inference.  Inspired by ML-based fingerprint recognition research.',
    kind: 'passive',
    typicalWeight: 0.25,
  },
  {
    id: 'dom_structural.resource_inclusion',
    family: 'dom_structural',
    label: 'Resource inclusion pattern',
    description:
      'Characterises the resource loading pattern (same-origin vs CDN hosts, JS/CSS ratios, bundle-name entropy).  Helps distinguish framework output from hand-authored pages.',
    kind: 'passive',
    typicalWeight: 0.3,
  },
  {
    id: 'dom_structural.layout_markers',
    family: 'dom_structural',
    label: 'Layout marker classes',
    description:
      'Detects framework-flavoured class tokens (`wp-block-…`, `elementor-`, `mui-`, `bootstrap col-`) without relying on any single literal string.',
    kind: 'passive',
    typicalWeight: 0.4,
  },
  // ------------------------------------------------------------------
  // 6. Controlled response-behaviour fingerprinting
  // ------------------------------------------------------------------
  {
    id: 'behavior.method_variance',
    family: 'behavior',
    label: 'HTTP method variance',
    description:
      'Observes header / status differences between GET and HEAD on the root URL.  A safe diagnostic — never sends forged payloads or bypass-style requests.',
    owaspReference: 'OWASP WSTG-INFO-06',
    kind: 'active',
    typicalWeight: 0.3,
  },
  {
    id: 'behavior.not_found_signature',
    family: 'behavior',
    label: '404 signature',
    description:
      'Issues a bounded GET to a random non-existent path (e.g. `/uasf-fp-<random>`) and reads the 404 status + body signature.  Different servers render distinctive 404 pages.',
    owaspReference: 'OWASP WSTG-ERRH-01',
    kind: 'active',
    typicalWeight: 0.4,
  },
  {
    id: 'behavior.trailing_slash',
    family: 'behavior',
    label: 'Trailing-slash handling',
    description:
      'Compares responses to `/` and `/index`.  Some servers normalise, some redirect; the redirect pattern reveals the serving layer.',
    kind: 'active',
    typicalWeight: 0.2,
  },
  {
    id: 'behavior.options_probe',
    family: 'behavior',
    label: 'OPTIONS probe',
    description:
      'Sends an `OPTIONS *` request (or method OPTIONS to `/`) and reads the `Allow` header.  Never enables dangerous verbs.',
    kind: 'active',
    typicalWeight: 0.3,
  },
  // ------------------------------------------------------------------
  // 7. Service / infrastructure fingerprinting
  // ------------------------------------------------------------------
  {
    id: 'service.nmap_service_version',
    family: 'service',
    label: 'Nmap safe service-version',
    description:
      'Controlled Nmap call (`-sT -sV` against a fixed port set) to capture service banners.  Gated by profile `enableNmap` — the binary is never invoked with operator-supplied flags.',
    owaspReference: 'OWASP WSTG-INFO-02',
    kind: 'active',
    typicalWeight: 0.8,
  },
  {
    id: 'service.edge_relationship',
    family: 'service',
    label: 'Edge / origin relationship',
    description:
      'Combines TLS issuer + CDN headers + IP reply characteristics to hint at the edge provider (Cloudflare, Fastly, Akamai, CloudFront).',
    kind: 'passive',
    typicalWeight: 0.4,
  },
];

export function findCatalogEntry(methodId: string): DetectionMethodCatalogEntry | null {
  return DETECTION_METHODS_CATALOG.find((m) => m.id === methodId) ?? null;
}

export function catalogByFamily(): Record<string, DetectionMethodCatalogEntry[]> {
  const out: Record<string, DetectionMethodCatalogEntry[]> = {};
  for (const entry of DETECTION_METHODS_CATALOG) {
    (out[entry.family] ??= []).push(entry);
  }
  return out;
}
