/**
 * UASF Tech Intelligence — Curated Profiles
 *
 * The platform deliberately does NOT expose a free-form "type your own
 * scanner command" surface.  Operators pick from a small, vetted list of
 * profiles with hard-bounded behaviour:
 *
 *   - Each profile declares which probes are enabled.
 *   - Each profile declares which adapters (signal families) are enabled.
 *   - Each profile carries timeouts, concurrency, and HTTP-only flags.
 *   - Profiles can opt-in to the controlled Nmap engine (port-set is
 *     fixed — there is no raw flag pass-through).
 *
 * This file is intentionally short and read-only.  Add new profiles
 * with a code review.
 */

export type TechIntelProbe =
  | 'http_root_get'
  | 'http_root_head'
  | 'http_well_known'
  | 'http_robots'
  | 'http_sitemap'
  | 'tls_certificate'
  | 'nmap_top_web_ports'
  | 'nmap_safe_service_versions';

/**
 * Which signal-family adapters the profile is allowed to run.  Each
 * adapter corresponds to one of the seven OWASP-inspired fingerprint
 * families.  Turning adapters off keeps very-lightweight profiles fast
 * and bounded.
 */
export interface AdapterFlags {
  passiveHttp: boolean;
  markup: boolean;
  urlRoute: boolean;
  structural: boolean;
  behavior: boolean;
  service: boolean;
}

export interface TechIntelProfile {
  id: string;
  name: string;
  description: string;
  /** Probes the engine is allowed to run for this profile. */
  probes: TechIntelProbe[];
  /** Adapter families enabled for this profile. */
  adapters: AdapterFlags;
  /** Per-probe HTTP timeout (ms). */
  httpTimeoutMs: number;
  /** Hard cap on parallel HTTP requests issued during a run. */
  maxConcurrency: number;
  /** Whether to enable the controlled Nmap engine for this profile. */
  enableNmap: boolean;
  /** Nmap engine timeout (ms). */
  nmapTimeoutMs: number;
}

const DEFAULT_ADAPTERS: AdapterFlags = {
  passiveHttp: true,
  markup: true,
  urlRoute: false,
  structural: true,
  behavior: false,
  service: true,
};

export const TECH_INTEL_PROFILES: TechIntelProfile[] = [
  {
    id: 'basic-http-fingerprint',
    name: 'Basic HTTP Fingerprint',
    description:
      'Lightweight HTTP/HEAD probe of the root URL only.  Runs the passive HTTP + markup + structural adapters against the response.  Safe default for a quick, low-traffic stack review.',
    probes: ['http_root_get', 'http_root_head'],
    adapters: { ...DEFAULT_ADAPTERS },
    httpTimeoutMs: 8_000,
    maxConcurrency: 2,
    enableNmap: false,
    nmapTimeoutMs: 0,
  },
  {
    id: 'web-stack-fingerprint',
    name: 'Web Stack & Runtime Fingerprint Review',
    description:
      'HTTP probe of the root, robots.txt, sitemap.xml and well-known endpoints.  Runs the passive HTTP, markup, structural, and URL-route adapters so framework/CMS/runtime markers, default-surface probes, and asset-naming patterns all contribute to fusion.',
    probes: [
      'http_root_get',
      'http_root_head',
      'http_robots',
      'http_sitemap',
      'http_well_known',
    ],
    adapters: { ...DEFAULT_ADAPTERS, urlRoute: true },
    httpTimeoutMs: 8_000,
    maxConcurrency: 3,
    enableNmap: false,
    nmapTimeoutMs: 0,
  },
  {
    id: 'edge-waf-presence',
    name: 'Edge / WAF Presence Review',
    description:
      'Targeted at identifying CDN, edge, and WAF intermediaries.  Runs the passive-HTTP adapter (edge headers, cookies, Via / forwarding) plus the service adapter (TLS issuer attribution).',
    probes: ['http_root_get', 'http_root_head', 'tls_certificate'],
    adapters: {
      passiveHttp: true,
      markup: false,
      urlRoute: false,
      structural: false,
      behavior: false,
      service: true,
    },
    httpTimeoutMs: 8_000,
    maxConcurrency: 2,
    enableNmap: false,
    nmapTimeoutMs: 0,
  },
  {
    id: 'tls-and-cert-intelligence',
    name: 'DNS & Certificate Intelligence',
    description:
      'TLS certificate inspection (issuer, expiry, SAN summary) plus an HTTP HEAD probe to attribute the cert to the live origin / edge.  Runs the service + passive-HTTP adapters.',
    probes: ['http_root_head', 'tls_certificate'],
    adapters: {
      passiveHttp: true,
      markup: false,
      urlRoute: false,
      structural: false,
      behavior: false,
      service: true,
    },
    httpTimeoutMs: 6_000,
    maxConcurrency: 2,
    enableNmap: false,
    nmapTimeoutMs: 0,
  },
  {
    id: 'multi-signal-fingerprint',
    name: 'Multi-Signal Fingerprint (OWASP-aligned)',
    description:
      'Runs every safe signal family (passive HTTP, TLS, markup, URL-route default-surface probes, DOM/structural feature vector, controlled response-behaviour diagnostics) against the approved target.  Produces the richest evidence trace without Nmap.  Inspired by OWASP WSTG v4 information-gathering tests and structural-feature fingerprint research.',
    probes: [
      'http_root_get',
      'http_root_head',
      'http_robots',
      'http_sitemap',
      'http_well_known',
      'tls_certificate',
    ],
    adapters: {
      passiveHttp: true,
      markup: true,
      urlRoute: true,
      structural: true,
      behavior: true,
      service: true,
    },
    httpTimeoutMs: 9_000,
    maxConcurrency: 4,
    enableNmap: false,
    nmapTimeoutMs: 0,
  },
  {
    id: 'controlled-visibility-sweep',
    name: 'Controlled Full Visibility Sweep',
    description:
      'Runs the complete multi-signal engine + a controlled, fixed-port-set Nmap probe (top web service ports, version detection only — no scripts, no host discovery flags).  Approved targets only.',
    probes: [
      'http_root_get',
      'http_root_head',
      'http_robots',
      'http_sitemap',
      'http_well_known',
      'tls_certificate',
      'nmap_top_web_ports',
      'nmap_safe_service_versions',
    ],
    adapters: {
      passiveHttp: true,
      markup: true,
      urlRoute: true,
      structural: true,
      behavior: true,
      service: true,
    },
    httpTimeoutMs: 10_000,
    maxConcurrency: 4,
    enableNmap: true,
    nmapTimeoutMs: 60_000,
  },
];

export function findProfileById(profileId: string): TechIntelProfile | null {
  return TECH_INTEL_PROFILES.find((p) => p.id === profileId) ?? null;
}
