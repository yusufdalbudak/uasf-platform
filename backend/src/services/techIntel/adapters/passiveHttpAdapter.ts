/**
 * Passive HTTP adapter.
 *
 * Reads response headers and cookies that the target already emits and
 * produces atomic `RawObservation` records.  No network I/O here —
 * the engine collects the headers up-front and passes them in via
 * {@link AdapterContext}.
 */

import type { RawObservation } from '../signalTypes';
import type { AdapterContext } from './sharedContext';
import { clip } from './sharedContext';

interface HeaderSignature {
  header: string;
  productKey: string;
  productName: string;
  vendor?: string;
  category: RawObservation['category'];
  /** Optional regex for version capture in the value. */
  versionPattern?: RegExp;
  /** Weight baseline — adapter may scale by match fidelity. */
  weight?: number;
  methodId?:
    | 'passive_http.server_header'
    | 'passive_http.x_powered_by'
    | 'passive_http.via_header'
    | 'passive_http.edge_headers'
    | 'passive_http.cache_mitigation';
}

const HEADER_SIGNATURES: HeaderSignature[] = [
  // Server / runtime banners
  {
    header: 'server',
    productKey: 'nginx',
    productName: 'NGINX',
    vendor: 'F5 / NGINX Inc.',
    category: 'web_server',
    versionPattern: /nginx\/(\d+\.\d+(?:\.\d+)?)/i,
    weight: 0.85,
    methodId: 'passive_http.server_header',
  },
  {
    header: 'server',
    productKey: 'apache_httpd',
    productName: 'Apache HTTP Server',
    vendor: 'Apache Software Foundation',
    category: 'web_server',
    versionPattern: /Apache\/?\s*(\d+\.\d+(?:\.\d+)?)?/i,
    weight: 0.85,
    methodId: 'passive_http.server_header',
  },
  {
    header: 'server',
    productKey: 'iis',
    productName: 'Microsoft IIS',
    vendor: 'Microsoft',
    category: 'web_server',
    versionPattern: /Microsoft-IIS\/(\d+\.\d+)/i,
    weight: 0.85,
    methodId: 'passive_http.server_header',
  },
  {
    header: 'server',
    productKey: 'litespeed',
    productName: 'LiteSpeed',
    vendor: 'LiteSpeed Technologies',
    category: 'web_server',
    versionPattern: /LiteSpeed\/?\s*(\d+\.\d+(?:\.\d+)?)?/i,
    weight: 0.8,
    methodId: 'passive_http.server_header',
  },
  {
    header: 'server',
    productKey: 'caddy',
    productName: 'Caddy',
    category: 'web_server',
    versionPattern: /Caddy\/?\s*(\d+\.\d+(?:\.\d+)?)?/i,
    weight: 0.8,
    methodId: 'passive_http.server_header',
  },
  {
    header: 'server',
    productKey: 'cloudflare',
    productName: 'Cloudflare',
    vendor: 'Cloudflare',
    category: 'cdn_edge',
    weight: 0.9,
    methodId: 'passive_http.server_header',
  },
  {
    header: 'server',
    productKey: 'cloudfront',
    productName: 'Amazon CloudFront',
    vendor: 'AWS',
    category: 'cdn_edge',
    weight: 0.9,
    methodId: 'passive_http.server_header',
  },
  {
    header: 'server',
    productKey: 'akamai_ghost',
    productName: 'Akamai',
    vendor: 'Akamai',
    category: 'cdn_edge',
    weight: 0.9,
    methodId: 'passive_http.server_header',
  },
  // X-Powered-By runtimes
  {
    header: 'x-powered-by',
    productKey: 'php',
    productName: 'PHP',
    category: 'language_runtime',
    versionPattern: /PHP\/(\d+\.\d+(?:\.\d+)?)/i,
    weight: 0.85,
    methodId: 'passive_http.x_powered_by',
  },
  {
    header: 'x-powered-by',
    productKey: 'aspnet',
    productName: 'ASP.NET',
    vendor: 'Microsoft',
    category: 'application_framework',
    versionPattern: /ASP\.NET\s*(\d+(?:\.\d+)?)?/i,
    weight: 0.85,
    methodId: 'passive_http.x_powered_by',
  },
  {
    header: 'x-powered-by',
    productKey: 'express',
    productName: 'Express',
    category: 'application_framework',
    weight: 0.8,
    methodId: 'passive_http.x_powered_by',
  },
  {
    header: 'x-powered-by',
    productKey: 'next_js',
    productName: 'Next.js',
    vendor: 'Vercel',
    category: 'application_framework',
    weight: 0.8,
    methodId: 'passive_http.x_powered_by',
  },
  // Edge header markers
  { header: 'cf-ray', productKey: 'cloudflare', productName: 'Cloudflare', category: 'cdn_edge', weight: 0.95, methodId: 'passive_http.edge_headers' },
  { header: 'x-amz-cf-id', productKey: 'cloudfront', productName: 'Amazon CloudFront', vendor: 'AWS', category: 'cdn_edge', weight: 0.95, methodId: 'passive_http.edge_headers' },
  { header: 'x-vercel-id', productKey: 'vercel', productName: 'Vercel Edge', vendor: 'Vercel', category: 'cdn_edge', weight: 0.9, methodId: 'passive_http.edge_headers' },
  { header: 'x-azure-ref', productKey: 'azure_front_door', productName: 'Azure Front Door', vendor: 'Microsoft', category: 'cdn_edge', weight: 0.9, methodId: 'passive_http.edge_headers' },
  { header: 'x-served-by', productKey: 'fastly', productName: 'Fastly', vendor: 'Fastly', category: 'cdn_edge', weight: 0.75, methodId: 'passive_http.edge_headers' },
  { header: 'x-akamai-transformed', productKey: 'akamai_ghost', productName: 'Akamai', vendor: 'Akamai', category: 'cdn_edge', weight: 0.9, methodId: 'passive_http.edge_headers' },
  // Via / forwarding
  {
    header: 'via',
    productKey: 'cloudfront',
    productName: 'Amazon CloudFront',
    vendor: 'AWS',
    category: 'cdn_edge',
    versionPattern: /cloudfront/i,
    weight: 0.8,
    methodId: 'passive_http.via_header',
  },
  // Cache markers
  {
    header: 'cf-cache-status',
    productKey: 'cloudflare',
    productName: 'Cloudflare',
    category: 'cdn_edge',
    weight: 0.6,
    methodId: 'passive_http.cache_mitigation',
  },
];

/** Cookie name markers (cookie name itself is the signal). */
const COOKIE_SIGNATURES: Array<{
  prefix: string;
  productKey: string;
  productName: string;
  vendor?: string;
  category: RawObservation['category'];
  weight?: number;
}> = [
  { prefix: 'phpsessid', productKey: 'php', productName: 'PHP', category: 'language_runtime', weight: 0.7 },
  { prefix: 'jsessionid', productKey: 'java_servlet', productName: 'Java Servlet Container', category: 'application_framework', weight: 0.7 },
  { prefix: 'asp.net_sessionid', productKey: 'aspnet', productName: 'ASP.NET', vendor: 'Microsoft', category: 'application_framework', weight: 0.7 },
  { prefix: 'bigipserver', productKey: 'f5_bigip', productName: 'F5 BIG-IP', vendor: 'F5', category: 'reverse_proxy', weight: 0.85 },
  { prefix: '__cf_bm', productKey: 'cloudflare', productName: 'Cloudflare', category: 'cdn_edge', weight: 0.9 },
  { prefix: 'wordpress_logged_in_', productKey: 'wordpress', productName: 'WordPress', category: 'cms_platform', weight: 0.85 },
  { prefix: 'laravel_session', productKey: 'laravel', productName: 'Laravel', category: 'application_framework', weight: 0.7 },
  { prefix: '_shopify_', productKey: 'shopify', productName: 'Shopify', category: 'cms_platform', weight: 0.8 },
];

/** Security-header presence pattern → tech hint.  Soft signal only. */
const SECURITY_HEADER_NAMES = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];

export function runPassiveHttpAdapter(context: AdapterContext): RawObservation[] {
  const out: RawObservation[] = [];

  // Header-based observations
  for (const sig of HEADER_SIGNATURES) {
    const value = context.headers[sig.header];
    if (typeof value !== 'string' || value.length === 0) continue;
    let version: string | null = null;
    if (sig.versionPattern) {
      const m = sig.versionPattern.exec(value);
      if (m && m[1]) version = m[1];
    }
    out.push({
      family: 'passive_http',
      methodId: sig.methodId ?? 'passive_http.server_header',
      methodLabel: labelForMethod(sig.methodId ?? 'passive_http.server_header'),
      signalKey: sig.header,
      signalValue: clip(value, 220),
      evidenceSnippet: clip(`${sig.header}: ${value}`, 220),
      productKey: sig.productKey,
      productName: sig.productName,
      vendor: sig.vendor ?? null,
      category: sig.category,
      versionLiteral: version,
      versionState: version ? 'exact' : sig.header === 'server' || sig.header === 'x-powered-by' ? 'probable' : 'family',
      weight: sig.weight ?? 0.6,
      vendorMatch: true,
      intent: version ? 'version_match' : 'product_match',
    });
  }

  // Cookie markers
  for (const [name] of Object.entries(context.cookies)) {
    const sig = COOKIE_SIGNATURES.find((s) => name === s.prefix || name.startsWith(s.prefix));
    if (!sig) continue;
    out.push({
      family: 'passive_http',
      methodId: 'passive_http.cookie_marker',
      methodLabel: 'Cookie name marker',
      signalKey: name,
      signalValue: name,
      evidenceSnippet: clip(`Set-Cookie name: ${name}`, 200),
      productKey: sig.productKey,
      productName: sig.productName,
      vendor: sig.vendor ?? null,
      category: sig.category,
      versionLiteral: null,
      versionState: 'unknown',
      weight: sig.weight ?? 0.55,
      vendorMatch: true,
      intent: 'product_match',
    });
  }

  // Security-header profile (soft signal)
  const present = SECURITY_HEADER_NAMES.filter((h) => context.headers[h]);
  if (present.length >= 3) {
    out.push({
      family: 'passive_http',
      methodId: 'passive_http.security_headers',
      methodLabel: 'Security-header profile',
      signalKey: 'security_header_count',
      signalValue: present.join(', '),
      evidenceSnippet: clip(`Security headers present: ${present.join(', ')}`, 220),
      productKey: null,
      versionLiteral: null,
      weight: 0.1,
      vendorMatch: false,
      intent: 'structural_hint',
    });
  }

  return out;
}

function labelForMethod(id: string): string {
  switch (id) {
    case 'passive_http.server_header':
      return 'Server header banner';
    case 'passive_http.x_powered_by':
      return 'X-Powered-By header';
    case 'passive_http.via_header':
      return 'Via / forwarding header';
    case 'passive_http.edge_headers':
      return 'Edge / CDN headers';
    case 'passive_http.cache_mitigation':
      return 'Cache / mitigation hints';
    case 'passive_http.cookie_marker':
      return 'Cookie name marker';
    default:
      return id;
  }
}
