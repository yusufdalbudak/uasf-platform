/**
 * Controlled response-behavior adapter.
 *
 * Issues a small, strictly-bounded set of diagnostic probes whose only
 * purpose is to differentiate serving technologies by how they respond
 * to canonical HTTP requests.  This module MUST NOT implement any
 * bypass, stealth, spoofing, fragmentation, or evasion behaviour —
 * every probe is a well-known diagnostic pattern referenced by OWASP
 * WSTG-INFO-06 / ERRH-01.
 *
 * Each probe records an observation that contributes a small amount of
 * weight to the fusion model (never authoritative on its own).
 */

import type { RawObservation } from '../signalTypes';
import type { AdapterContext } from './sharedContext';
import { clip } from './sharedContext';
import { probeUrl } from '../../../engine/modules/httpProbe';

interface BehaviorResponse {
  status: number;
  server: string | null;
  bodyLength: number;
  bodySnippet: string;
  allowHeader: string | null;
}

async function probeResponse(url: string, method: 'GET' | 'HEAD', timeoutMs: number): Promise<BehaviorResponse | null> {
  try {
    const response = await probeUrl(url, {
      method,
      timeoutMs: Math.min(timeoutMs, 6000),
      readBody: method === 'GET',
    });
    return {
      status: response.status,
      server: response.headers['server'] ?? null,
      bodyLength: response.body?.length ?? 0,
      bodySnippet: (response.body ?? '').slice(0, 160),
      allowHeader: response.headers['allow'] ?? null,
    };
  } catch {
    return null;
  }
}

/**
 * Raw `fetch()` wrapper so we can exercise OPTIONS — the shared
 * httpProbe helper only allows GET/HEAD by design.  We keep the scope
 * tight: single URL, bounded timeout, no body.
 */
async function rawOptions(url: string, timeoutMs: number): Promise<{ status: number; allow: string | null } | null> {
  try {
    const response = await fetch(url, {
      method: 'OPTIONS',
      redirect: 'follow',
      signal: AbortSignal.timeout(Math.min(timeoutMs, 5000)),
    });
    return { status: response.status, allow: response.headers.get('allow') };
  } catch {
    return null;
  }
}

export async function runBehaviorAdapter(context: AdapterContext): Promise<RawObservation[]> {
  const out: RawObservation[] = [];
  if (!context.baseUrl) return out;
  const baseUrl = context.baseUrl;

  // ------------------------------------------------------------------
  // 1. Method variance (GET vs HEAD on root)
  // ------------------------------------------------------------------
  const [rootGet, rootHead] = await Promise.all([
    probeResponse(`${baseUrl}/`, 'GET', context.httpTimeoutMs),
    probeResponse(`${baseUrl}/`, 'HEAD', context.httpTimeoutMs),
  ]);
  if (rootGet && rootHead) {
    const differed = rootGet.status !== rootHead.status || rootGet.server !== rootHead.server;
    out.push({
      family: 'behavior',
      methodId: 'behavior.method_variance',
      methodLabel: 'HTTP method variance',
      signalKey: 'get_vs_head',
      signalValue: `GET=${rootGet.status} HEAD=${rootHead.status}${differed ? ' (differ)' : ''}`,
      evidenceSnippet: clip(
        `GET / → ${rootGet.status} server=${rootGet.server ?? '—'} · HEAD / → ${rootHead.status} server=${rootHead.server ?? '—'}`,
        220,
      ),
      productKey: null,
      versionLiteral: null,
      weight: differed ? 0.2 : 0.1,
      vendorMatch: false,
      intent: 'behavior_hint',
      metadata: { getStatus: rootGet.status, headStatus: rootHead.status, differed },
    });
  }

  // ------------------------------------------------------------------
  // 2. 404 signature — random non-existent path
  // ------------------------------------------------------------------
  const randomPath = `/uasf-fp-${Math.random().toString(36).slice(2, 10)}`;
  const notFound = await probeResponse(`${baseUrl}${randomPath}`, 'GET', context.httpTimeoutMs);
  if (notFound) {
    const signature404 = summarise404(notFound.bodySnippet);
    out.push({
      family: 'behavior',
      methodId: 'behavior.not_found_signature',
      methodLabel: '404 signature',
      signalKey: 'not_found_signature',
      signalValue: clip(signature404, 200),
      evidenceSnippet: clip(
        `GET ${randomPath} → ${notFound.status} (${notFound.bodyLength}B) — ${signature404}`,
        240,
      ),
      productKey: null,
      versionLiteral: null,
      weight: notFound.status === 404 ? 0.2 : 0.1,
      vendorMatch: false,
      intent: 'behavior_hint',
      metadata: { status: notFound.status, bodyLength: notFound.bodyLength, signature: signature404 },
    });
  }

  // ------------------------------------------------------------------
  // 3. Trailing-slash handling
  // ------------------------------------------------------------------
  const [noSlash, withSlash] = await Promise.all([
    probeResponse(`${baseUrl}/index`, 'HEAD', context.httpTimeoutMs),
    probeResponse(`${baseUrl}/index/`, 'HEAD', context.httpTimeoutMs),
  ]);
  if (noSlash && withSlash) {
    out.push({
      family: 'behavior',
      methodId: 'behavior.trailing_slash',
      methodLabel: 'Trailing-slash handling',
      signalKey: 'trailing_slash',
      signalValue: `no-slash=${noSlash.status} slash=${withSlash.status}`,
      evidenceSnippet: clip(
        `HEAD /index → ${noSlash.status} · HEAD /index/ → ${withSlash.status}`,
        200,
      ),
      productKey: null,
      versionLiteral: null,
      weight: 0.08,
      vendorMatch: false,
      intent: 'behavior_hint',
    });
  }

  // ------------------------------------------------------------------
  // 4. OPTIONS probe
  // ------------------------------------------------------------------
  const options = await rawOptions(`${baseUrl}/`, context.httpTimeoutMs);
  if (options) {
    out.push({
      family: 'behavior',
      methodId: 'behavior.options_probe',
      methodLabel: 'OPTIONS probe',
      signalKey: 'options_allow',
      signalValue: options.allow ?? '<no Allow header>',
      evidenceSnippet: clip(
        `OPTIONS / → ${options.status} · Allow: ${options.allow ?? 'n/a'}`,
        200,
      ),
      productKey: null,
      versionLiteral: null,
      weight: 0.12,
      vendorMatch: false,
      intent: 'behavior_hint',
      metadata: { status: options.status, allow: options.allow },
    });
  }

  return out;
}

function summarise404(body: string): string {
  if (!body) return 'empty body';
  const trimmed = body.trim().replace(/\s+/g, ' ');
  if (/nginx/i.test(trimmed)) return 'nginx default 404';
  if (/apache/i.test(trimmed)) return 'Apache default 404';
  if (/iis|internet information services/i.test(trimmed)) return 'IIS default 404';
  if (/cloudflare/i.test(trimmed)) return 'Cloudflare challenge / error';
  if (/not found/i.test(trimmed)) return 'generic "not found" page';
  return trimmed.slice(0, 80);
}
