/**
 * URL / route adapter.
 *
 * Issues a bounded set of safe GET/HEAD requests against canonical
 * platform-default paths and records what came back.  Every probe:
 *
 *   - uses a bounded AbortController timeout inherited from the
 *     engine's profile,
 *   - sends no mutation verbs (GET/HEAD only),
 *   - never attempts authentication, parameter mutation, or path
 *     traversal,
 *   - treats any non-transport failure (even 4xx/5xx) as a signal, not
 *     an error.
 *
 * The adapter is policy-gated by the engine: the approved-asset check
 * has already succeeded before we are called.
 */

import type { RawObservation } from '../signalTypes';
import type { AdapterContext } from './sharedContext';
import { clip } from './sharedContext';
import { probeUrl } from '../../../engine/modules/httpProbe';

interface RoutePattern {
  path: string;
  method: 'HEAD' | 'GET';
  /** Only fire the observation when the response status matches one of these. */
  interestingStatuses: number[];
  productKey: string;
  productName: string;
  vendor?: string;
  category: RawObservation['category'];
  weight?: number;
  description: string;
}

const DEFAULT_ROUTES: RoutePattern[] = [
  { path: '/wp-login.php', method: 'HEAD', interestingStatuses: [200, 302, 301], productKey: 'wordpress', productName: 'WordPress', category: 'cms_platform', weight: 0.85, description: 'WordPress login handler' },
  { path: '/wp-json/', method: 'HEAD', interestingStatuses: [200, 401, 403, 301], productKey: 'wordpress', productName: 'WordPress', category: 'cms_platform', weight: 0.6, description: 'WP REST API root' },
  { path: '/administrator/', method: 'HEAD', interestingStatuses: [200, 301, 302], productKey: 'joomla', productName: 'Joomla', category: 'cms_platform', weight: 0.75, description: 'Joomla admin surface' },
  { path: '/user/login', method: 'HEAD', interestingStatuses: [200, 301, 302], productKey: 'drupal', productName: 'Drupal', category: 'cms_platform', weight: 0.55, description: 'Drupal user login' },
  { path: '/_next/static/chunks/', method: 'HEAD', interestingStatuses: [403, 404, 200], productKey: 'next_js', productName: 'Next.js', vendor: 'Vercel', category: 'application_framework', weight: 0.65, description: 'Next.js static chunks directory' },
  { path: '/graphql', method: 'HEAD', interestingStatuses: [200, 400, 405], productKey: 'graphql', productName: 'GraphQL endpoint', category: 'api_framework', weight: 0.55, description: 'Common GraphQL endpoint' },
];

/** favicon fingerprint: fetch /favicon.ico and hash the bytes (short hash). */
async function collectFaviconHash(baseUrl: string, timeoutMs: number): Promise<{ hash: string; byteLength: number } | null> {
  try {
    const response = await fetch(`${baseUrl}/favicon.ico`, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(Math.min(timeoutMs, 5000)),
    });
    if (response.status !== 200) return null;
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength === 0 || buffer.byteLength > 128 * 1024) return null;
    const bytes = new Uint8Array(buffer);
    // Cheap 32-bit FNV-1a hash — sufficient for a structural signal.
    let h = 0x811c9dc5;
    for (let i = 0; i < bytes.length; i += 1) {
      h ^= bytes[i];
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return { hash: h.toString(16).padStart(8, '0'), byteLength: bytes.length };
  } catch {
    return null;
  }
}

export async function runRouteAdapter(context: AdapterContext): Promise<RawObservation[]> {
  const out: RawObservation[] = [];
  if (!context.baseUrl) return out;
  const baseUrl = context.baseUrl;

  // Default-surface probes (bounded, in parallel).
  await Promise.all(
    DEFAULT_ROUTES.map(async (route) => {
      try {
        const response = await probeUrl(`${baseUrl}${route.path}`, {
          method: route.method,
          timeoutMs: Math.min(context.httpTimeoutMs, 6000),
          readBody: false,
        });
        if (!route.interestingStatuses.includes(response.status)) return;
        out.push({
          family: 'url_route',
          methodId: 'url_route.default_surface',
          methodLabel: 'Default surface probe',
          signalKey: route.path,
          signalValue: `HTTP ${response.status}`,
          evidenceSnippet: clip(
            `${route.method} ${route.path} → ${response.status} · ${route.description}`,
            220,
          ),
          productKey: route.productKey,
          productName: route.productName,
          vendor: route.vendor ?? null,
          category: route.category,
          versionLiteral: null,
          versionState: 'unknown',
          weight: route.weight ?? 0.55,
          vendorMatch: true,
          intent: 'product_match',
          metadata: { path: route.path, status: response.status, method: route.method },
        });
      } catch {
        // transport failure — drop silently, this is a hint probe not a fact probe
      }
    }),
  );

  // Favicon hash — independent, parallel.
  const fav = await collectFaviconHash(baseUrl, context.httpTimeoutMs);
  if (fav) {
    out.push({
      family: 'url_route',
      methodId: 'url_route.favicon_fingerprint',
      methodLabel: 'Favicon hash',
      signalKey: 'favicon',
      signalValue: fav.hash,
      evidenceSnippet: clip(`favicon.ico FNV-1a=${fav.hash} (${fav.byteLength} bytes)`, 200),
      productKey: null,
      versionLiteral: null,
      weight: 0.1,
      vendorMatch: false,
      intent: 'structural_hint',
      metadata: { hash: fav.hash, byteLength: fav.byteLength },
    });
  }

  return out;
}
