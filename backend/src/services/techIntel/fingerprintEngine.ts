/**
 * UASF Tech Intelligence — Fingerprint Engine
 *
 * Takes a curated profile + an approved target, runs the allowed probes,
 * evaluates the rule library, and returns a normalized list of
 * {@link FingerprintCandidate}s.  The engine is the only place that
 * touches the network or the controlled Nmap binary.
 *
 * Safety guarantees:
 *
 *   - The hostname has already been allowed by `assertExecutableApprovedAsset`
 *     before we are called; we additionally re-validate it via
 *     `assertSafeScanHostname` to avoid command-injection inputs leaking
 *     into Nmap argv.
 *   - No raw user input is forwarded as Nmap args; the port set, scripts,
 *     and flags are hard-coded per profile.
 *   - All HTTP requests use a bounded `AbortController` timeout and follow
 *     redirects.
 *   - Rule evaluation is pure, in-process, and has no side effects.
 */

import {
  FINGERPRINT_RULES,
  extractVersionFamily,
  type FingerprintRule,
  type RuleMatcher,
} from './fingerprintRules';
import type { TechIntelProfile, TechIntelProbe } from './profiles';
import {
  type FingerprintConfidence,
  type TechnologyCategory,
  type VersionCertainty,
} from '../../db/models/DetectedTechnology';
import { probeUrl } from '../../engine/modules/httpProbe';
import { runTlsScanner } from '../../engine/modules/tlsScanner';
import { assertSafeScanHostname, safeExecFile } from '../../engine/modules/utils';
import type { AdapterContext } from './adapters/sharedContext';
import { runPassiveHttpAdapter } from './adapters/passiveHttpAdapter';
import { runMarkupAdapter } from './adapters/markupAdapter';
import { runStructuralAdapter } from './adapters/structuralAdapter';
import { runRouteAdapter } from './adapters/routeAdapter';
import { runBehaviorAdapter } from './adapters/behaviorAdapter';
import { runServiceAdapter } from './adapters/serviceAdapter';
import { fuseWithLegacyCandidates, type FusedCandidate } from './signalFusion';
import type { RawObservation } from './signalTypes';

// ---------------------------------------------------------------
// Public types
// ---------------------------------------------------------------

export interface FingerprintEvidence {
  source: 'header' | 'cookie' | 'body_marker' | 'tls' | 'banner' | 'meta_tag' | 'asset' | 'script' | 'rule';
  detail: string;
  matchedRule?: string;
}

export interface FingerprintCandidate {
  productKey: string;
  productName: string;
  vendor: string | null;
  category: TechnologyCategory;
  version: string | null;
  versionFamily: string | null;
  versionCertainty: VersionCertainty;
  confidence: FingerprintConfidence;
  evidence: FingerprintEvidence[];
}

export interface FingerprintEngineResult {
  resolvedHostname: string;
  /**
   * Legacy rule-engine candidates.  Kept for backward compatibility with
   * the operator-facing summary; the orchestrator actually persists
   * {@link fusedCandidates} (which also includes every legacy candidate
   * after fusion with the new signal layer).
   */
  candidates: FingerprintCandidate[];
  /**
   * Fused candidates produced by the multi-signal engine.  This is the
   * authoritative detection output: each entry includes a 0..100
   * confidence score, the signal families that contributed, and the
   * observation ids to back-reference in the evidence trace.
   */
  fusedCandidates: FusedCandidate[];
  /**
   * Atomic per-signal observations emitted by each adapter.  Persisted
   * as the immutable evidence ledger for the run.
   */
  observations: RawObservation[];
  /**
   * Detection method ids that actually fired during this run.  Derived
   * from `observations`; surfaced so the UI can list "methods exercised"
   * cheaply.
   */
  methodsExercised: string[];
  rawSummary: {
    httpProbed: boolean;
    nmapProbed: boolean;
    tlsProbed: boolean;
    /**
     * Probe ids the engine actually executed against the target.  Subset
     * of `profile.probes`; used by the orchestrator to record an
     * execution trace so operators can verify profile→backend integrity
     * without trusting the profile id alone.
     */
    executedProbes: TechIntelProbe[];
    /** Adapter ids that actually ran for this profile. */
    adaptersExecuted: string[];
    durationMs: number;
    errors: string[];
  };
}

// ---------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------

/**
 * Snapshot of "what the engine has seen on this target".  Built from
 * the union of HTTP / TLS / Nmap probes; consumed by the rule
 * evaluator below.
 */
interface ObservationContext {
  /** Lower-cased response headers from the most useful HTTP probe. */
  headers: Record<string, string>;
  /** Parsed cookies (lower-case names). */
  cookies: Record<string, string>;
  /** Raw HTML body preview (≤16 KB). */
  body: string;
  /** Asset / script URLs extracted from the HTML body. */
  scriptUrls: string[];
  assetUrls: string[];
  /** Meta tag fragments extracted from the HTML body. */
  metaTags: string[];
  /** Service banners from the controlled Nmap probe (port → banner string). */
  serviceBanners: Array<{ port: number; protocol: string; service: string; product?: string; version?: string; banner?: string }>;
  /** TLS evidence harvested from the existing tls module. */
  tls: { issuer?: string; subject?: string; notAfter?: string; sans?: string[] } | null;
}

const CONFIDENCE_ORDER: Record<FingerprintConfidence, number> = {
  low: 1,
  medium: 2,
  high: 3,
  very_high: 4,
};

// ---------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------

/**
 * Run the fingerprint pipeline.  Caller is responsible for asserting
 * `assertExecutableApprovedAsset` first; we still re-validate the
 * hostname here so we never feed unsafe input to Nmap.
 */
export async function runFingerprintEngine(
  hostname: string,
  profile: TechIntelProfile,
): Promise<FingerprintEngineResult> {
  const startedAt = Date.now();
  const errors: string[] = [];

  const safeHostname = assertSafeScanHostname(hostname);
  const context: ObservationContext = {
    headers: {},
    cookies: {},
    body: '',
    scriptUrls: [],
    assetUrls: [],
    metaTags: [],
    serviceBanners: [],
    tls: null,
  };

  let httpProbed = false;
  let nmapProbed = false;
  let tlsProbed = false;
  const executedProbes: TechIntelProbe[] = [];

  if (profile.probes.some((p) => p.startsWith('http_'))) {
    try {
      const fired = await collectHttpObservations(safeHostname, profile, context, errors);
      httpProbed = fired.length > 0;
      executedProbes.push(...fired);
    } catch (err) {
      errors.push(`HTTP probe failed: ${(err as Error).message}`);
    }
  }

  if (profile.probes.includes('tls_certificate')) {
    try {
      const tlsModule = await runTlsScanner(safeHostname);
      tlsProbed = true;
      executedProbes.push('tls_certificate');
      context.tls = parseTlsModuleNotes(tlsModule.normalizedEvidence ?? '');
    } catch (err) {
      errors.push(`TLS probe failed: ${(err as Error).message}`);
    }
  }

  if (
    profile.enableNmap &&
    (profile.probes.includes('nmap_top_web_ports') || profile.probes.includes('nmap_safe_service_versions'))
  ) {
    try {
      await collectNmapServiceVersions(safeHostname, profile, context, errors);
      nmapProbed = true;
      if (profile.probes.includes('nmap_top_web_ports')) executedProbes.push('nmap_top_web_ports');
      if (profile.probes.includes('nmap_safe_service_versions')) executedProbes.push('nmap_safe_service_versions');
    } catch (err) {
      errors.push(`Service-version probe failed: ${(err as Error).message}`);
    }
  }

  const candidates = evaluateRules(context);

  // ------------------------------------------------------------------
  // Multi-signal adapter layer
  // ------------------------------------------------------------------
  const adapterContext: AdapterContext = {
    baseUrl: derivePreferredBaseUrl(safeHostname, httpProbed),
    headers: context.headers,
    cookies: context.cookies,
    body: context.body,
    scriptUrls: context.scriptUrls,
    assetUrls: context.assetUrls,
    metaTags: context.metaTags,
    tls: context.tls,
    serviceBanners: context.serviceBanners,
    hostname: safeHostname,
    httpTimeoutMs: profile.httpTimeoutMs,
  };

  const observations: RawObservation[] = [];
  const adaptersExecuted: string[] = [];

  // Always-safe adapters (pure interpretation over already-collected data).
  if (profile.adapters.passiveHttp) {
    try {
      observations.push(...runPassiveHttpAdapter(adapterContext));
      adaptersExecuted.push('passive_http');
    } catch (err) {
      errors.push(`passive_http adapter: ${(err as Error).message}`);
    }
  }
  if (profile.adapters.markup) {
    try {
      observations.push(...runMarkupAdapter(adapterContext));
      adaptersExecuted.push('markup');
    } catch (err) {
      errors.push(`markup adapter: ${(err as Error).message}`);
    }
  }
  if (profile.adapters.structural) {
    try {
      observations.push(...runStructuralAdapter(adapterContext));
      adaptersExecuted.push('dom_structural');
    } catch (err) {
      errors.push(`structural adapter: ${(err as Error).message}`);
    }
  }
  if (profile.adapters.service) {
    try {
      observations.push(...runServiceAdapter(adapterContext));
      adaptersExecuted.push('service');
    } catch (err) {
      errors.push(`service adapter: ${(err as Error).message}`);
    }
  }

  // Active adapters (issue additional bounded probes).
  if (profile.adapters.urlRoute && adapterContext.baseUrl) {
    try {
      observations.push(...(await runRouteAdapter(adapterContext)));
      adaptersExecuted.push('url_route');
    } catch (err) {
      errors.push(`url_route adapter: ${(err as Error).message}`);
    }
  }
  if (profile.adapters.behavior && adapterContext.baseUrl) {
    try {
      observations.push(...(await runBehaviorAdapter(adapterContext)));
      adaptersExecuted.push('behavior');
    } catch (err) {
      errors.push(`behavior adapter: ${(err as Error).message}`);
    }
  }

  // Fuse adapter observations with the legacy rule-engine candidates.
  const fusedCandidates = fuseWithLegacyCandidates(observations, candidates);

  const methodsExercised = [...new Set(observations.map((o) => o.methodId))];

  return {
    resolvedHostname: safeHostname,
    candidates,
    fusedCandidates,
    observations,
    methodsExercised,
    rawSummary: {
      httpProbed,
      nmapProbed,
      tlsProbed,
      executedProbes,
      adaptersExecuted,
      durationMs: Date.now() - startedAt,
      errors,
    },
  };
}

function derivePreferredBaseUrl(hostname: string, httpProbed: boolean): string | null {
  if (!httpProbed) return null;
  // The `pickPreferredScheme` helper has already confirmed at least one
  // scheme replies; we cannot know which without surfacing it, so we
  // default to HTTPS and fall back is handled at probe-time inside each
  // adapter via try/catch.  This keeps adapters simple and the engine
  // honest about what it has verified.
  return `https://${hostname}`;
}

// ---------------------------------------------------------------
// Probes
// ---------------------------------------------------------------

async function collectHttpObservations(
  hostname: string,
  profile: TechIntelProfile,
  context: ObservationContext,
  errors: string[],
): Promise<TechIntelProbe[]> {
  const fired: TechIntelProbe[] = [];
  const baseUrl = await pickPreferredScheme(hostname, profile, errors);
  if (!baseUrl) return fired;

  // 1. Root GET — primary observation source.
  if (profile.probes.includes('http_root_get')) {
    try {
      const response = await probeUrl(`${baseUrl}/`, {
        method: 'GET',
        timeoutMs: profile.httpTimeoutMs,
        readBody: true,
      });
      Object.assign(context.headers, response.headers);
      mergeCookies(context.cookies, response.headers);
      context.body = (response.body || '').slice(0, 16 * 1024);
      extractAssetsAndMeta(context);
      fired.push('http_root_get');
    } catch (err) {
      errors.push(`http_root_get: ${(err as Error).message}`);
    }
  }

  // 2. Root HEAD — second header source (some intermediaries differ on HEAD).
  if (profile.probes.includes('http_root_head')) {
    try {
      const response = await probeUrl(`${baseUrl}/`, {
        method: 'HEAD',
        timeoutMs: profile.httpTimeoutMs,
        readBody: false,
      });
      // Fill in headers HEAD added that GET didn't have.
      for (const [k, v] of Object.entries(response.headers)) {
        if (!(k in context.headers)) context.headers[k] = v;
      }
      mergeCookies(context.cookies, response.headers);
      fired.push('http_root_head');
    } catch (err) {
      errors.push(`http_root_head: ${(err as Error).message}`);
    }
  }

  // 3. /robots.txt — sometimes leaks CMS hints.
  if (profile.probes.includes('http_robots')) {
    if (await tryGet(baseUrl, '/robots.txt', profile.httpTimeoutMs, context, errors)) {
      fired.push('http_robots');
    }
  }

  // 4. /sitemap.xml — same idea.
  if (profile.probes.includes('http_sitemap')) {
    if (await tryGet(baseUrl, '/sitemap.xml', profile.httpTimeoutMs, context, errors)) {
      fired.push('http_sitemap');
    }
  }

  // 5. /.well-known/security.txt — operator-friendly soft signal.
  if (profile.probes.includes('http_well_known')) {
    if (await tryGet(baseUrl, '/.well-known/security.txt', profile.httpTimeoutMs, context, errors)) {
      fired.push('http_well_known');
    }
  }
  return fired;
}

async function tryGet(
  baseUrl: string,
  path: string,
  timeoutMs: number,
  context: ObservationContext,
  errors: string[],
): Promise<boolean> {
  try {
    const response = await probeUrl(`${baseUrl}${path}`, {
      method: 'GET',
      timeoutMs,
      readBody: true,
    });
    if (response.status >= 200 && response.status < 400 && response.body) {
      // Append a small body sample so rules can match on extra files.
      context.body = `${context.body}\n${response.body.slice(0, 4 * 1024)}`;
    }
    return true;
  } catch (err) {
    errors.push(`probe ${path}: ${(err as Error).message}`);
    return false;
  }
}

async function pickPreferredScheme(
  hostname: string,
  profile: TechIntelProfile,
  errors: string[],
): Promise<string | null> {
  for (const scheme of ['https', 'http'] as const) {
    try {
      const response = await probeUrl(`${scheme}://${hostname}/`, {
        method: 'HEAD',
        timeoutMs: Math.min(profile.httpTimeoutMs, 5_000),
        readBody: false,
      });
      // Accept anything that isn't an outright transport failure.
      if (response.status > 0) return `${scheme}://${hostname}`;
    } catch (err) {
      errors.push(`scheme ${scheme}: ${(err as Error).message}`);
    }
  }
  return null;
}

function mergeCookies(target: Record<string, string>, headers: Record<string, string>): void {
  // fetch() folds duplicate Set-Cookie headers into one comma-joined string;
  // we walk the resulting list conservatively and only keep the cookie name.
  const raw = headers['set-cookie'];
  if (!raw) return;
  const candidates = raw.split(/,(?=[^,]+=)/);
  for (const candidate of candidates) {
    const [pair] = candidate.split(';');
    if (!pair) continue;
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name) target[name.toLowerCase()] = value;
  }
}

function extractAssetsAndMeta(context: ObservationContext): void {
  if (!context.body) return;
  // Script / link href asset URLs.
  const srcRegex = /<(?:script|link|img)[^>]*?(?:src|href)=["']([^"']+)["']/gi;
  for (const match of context.body.matchAll(srcRegex)) {
    const url = match[1];
    if (!url) continue;
    if (/\.js(?:\?|$)/i.test(url)) context.scriptUrls.push(url);
    else context.assetUrls.push(url);
  }
  // Meta tags (kept as raw fragments so rules can apply their own regex).
  const metaRegex = /<meta\b[^>]*>/gi;
  for (const match of context.body.matchAll(metaRegex)) {
    context.metaTags.push(match[0]);
  }
}

function parseTlsModuleNotes(normalized: string): ObservationContext['tls'] {
  if (!normalized) return null;
  const issuer = /issuer\s*:\s*([^\n]+)/i.exec(normalized)?.[1]?.trim() ?? undefined;
  const notAfter = /not\s*after\s*:\s*([^\n]+)/i.exec(normalized)?.[1]?.trim() ?? undefined;
  return { issuer, notAfter };
}

/**
 * Controlled, fixed-argument Nmap invocation used by the
 * `controlled-visibility-sweep` profile only.  Every flag is hard-coded;
 * we never accept user-supplied arguments.
 */
async function collectNmapServiceVersions(
  hostname: string,
  profile: TechIntelProfile,
  context: ObservationContext,
  errors: string[],
): Promise<void> {
  const args = [
    '-Pn',                                         // skip host discovery (we're already approved)
    '--unprivileged',                              // safer in containers
    '-sT',                                         // full TCP connect (no raw sockets)
    '-T3',                                         // polite timing
    '-p',
    '80,443,8080,8443,8000,8888,3000,5000',        // top web service ports — fixed set
    '--open',                                      // only emit open ports
    '-sV',                                         // service-version detection
    '--version-intensity', '5',                    // moderate intensity (default-ish)
    '--max-retries', '2',
    '--script-timeout', '20s',
    '--host-timeout', `${Math.max(20_000, profile.nmapTimeoutMs - 5_000)}ms`,
    '-oX', '-',                                    // XML to stdout for parsing
    hostname,
  ];

  const result = await safeExecFile('nmap', args, profile.nmapTimeoutMs);
  if (result.stderr) errors.push(`nmap stderr: ${result.stderr.slice(0, 200)}`);
  context.serviceBanners.push(...parseNmapXml(result.stdout));
}

function parseNmapXml(xml: string): ObservationContext['serviceBanners'] {
  if (!xml) return [];
  const out: ObservationContext['serviceBanners'] = [];
  const portRegex = /<port\s+protocol="([^"]+)"\s+portid="(\d+)"[\s\S]*?<\/port>/g;
  for (const portMatch of xml.matchAll(portRegex)) {
    const [block, protocol, port] = portMatch;
    if (!/<state[^>]+state="open"/.test(block)) continue;
    const service = /<service\b([^/]*)\/?>/.exec(block)?.[1] ?? '';
    const get = (attr: string) => new RegExp(`${attr}="([^"]*)"`).exec(service)?.[1];
    out.push({
      protocol,
      port: Number(port),
      service: get('name') ?? 'unknown',
      product: get('product'),
      version: get('version'),
      banner: [get('product'), get('version'), get('extrainfo')].filter(Boolean).join(' ') || undefined,
    });
  }
  return out;
}

// ---------------------------------------------------------------
// Rule evaluation
// ---------------------------------------------------------------

function evaluateRules(context: ObservationContext): FingerprintCandidate[] {
  const byProduct = new Map<string, FingerprintCandidate>();

  for (const rule of FINGERPRINT_RULES) {
    for (const matcher of rule.matchers) {
      const hits = collectMatcherHits(matcher, context);
      for (const hit of hits) {
        upsertCandidate(byProduct, rule, matcher, hit);
      }
    }
  }

  // Service-banner fallback: if Nmap reported a product/version we don't
  // have a rule for, surface it under category=service_banner so the
  // operator still sees it inventoried.
  for (const banner of context.serviceBanners) {
    if (!banner.product) continue;
    const productKey = banner.product.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 64);
    if (byProduct.has(productKey)) continue;
    const version = banner.version ?? null;
    byProduct.set(productKey, {
      productKey,
      productName: banner.product,
      vendor: null,
      category: 'service_banner',
      version,
      versionFamily: extractVersionFamily(version),
      versionCertainty: version ? 'probable' : 'unknown',
      confidence: 'medium',
      evidence: [
        {
          source: 'banner',
          detail: `Nmap service-version: ${banner.product} ${version ?? ''} on ${banner.protocol}/${banner.port}`.trim(),
        },
      ],
    });
  }

  return [...byProduct.values()].sort((a, b) => {
    if (a.category !== b.category) return a.category.localeCompare(b.category);
    return a.productName.localeCompare(b.productName);
  });
}

interface MatcherHit {
  source: FingerprintEvidence['source'];
  detail: string;
  capturedVersion: string | null;
}

function collectMatcherHits(matcher: RuleMatcher, context: ObservationContext): MatcherHit[] {
  const hits: MatcherHit[] = [];
  switch (matcher.source) {
    case 'header': {
      const value = matcher.field ? context.headers[matcher.field.toLowerCase()] : undefined;
      if (typeof value !== 'string' || value.length === 0) return hits;
      const m = matcher.pattern.exec(value);
      if (m) hits.push({ source: 'header', detail: `${matcher.field}: ${value}`, capturedVersion: m[1] ?? null });
      return hits;
    }
    case 'cookie': {
      // We match on cookie *name* primarily; some rules also test value with the regex.
      const cookieName = matcher.field?.toLowerCase();
      if (!cookieName) return hits;
      // Some cookies are dynamic-prefixed (e.g. BIGipServerXYZ); use startsWith for those.
      const matchedName = Object.keys(context.cookies).find(
        (name) => name === cookieName || name.startsWith(cookieName),
      );
      if (!matchedName) return hits;
      const value = context.cookies[matchedName];
      const m = matcher.pattern.exec(value || matchedName);
      if (m) {
        hits.push({
          source: 'cookie',
          detail: `Set-Cookie: ${matchedName}`,
          capturedVersion: m[1] ?? null,
        });
      }
      return hits;
    }
    case 'body_marker': {
      const m = matcher.pattern.exec(context.body);
      if (m) hits.push({ source: 'body_marker', detail: m[0].slice(0, 160), capturedVersion: m[1] ?? null });
      return hits;
    }
    case 'meta_tag': {
      for (const tag of context.metaTags) {
        const m = matcher.pattern.exec(tag);
        if (m) {
          hits.push({ source: 'meta_tag', detail: tag.slice(0, 200), capturedVersion: m[1] ?? null });
        }
      }
      return hits;
    }
    case 'asset': {
      for (const url of context.assetUrls) {
        const m = matcher.pattern.exec(url);
        if (m) hits.push({ source: 'asset', detail: url.slice(0, 200), capturedVersion: m[1] ?? null });
      }
      return hits;
    }
    case 'script': {
      for (const url of context.scriptUrls) {
        const m = matcher.pattern.exec(url);
        if (m) hits.push({ source: 'script', detail: url.slice(0, 200), capturedVersion: m[1] ?? null });
      }
      return hits;
    }
    case 'tls': {
      const tls = context.tls;
      if (!tls) return hits;
      const haystack = [tls.issuer, tls.subject, ...(tls.sans ?? [])].filter(Boolean).join(' ');
      const m = matcher.pattern.exec(haystack);
      if (m) hits.push({ source: 'tls', detail: haystack.slice(0, 200), capturedVersion: m[1] ?? null });
      return hits;
    }
    case 'banner': {
      // For now only used by the synthetic "Nmap fallback" branch above;
      // not applied directly via rules.
      return hits;
    }
    default:
      return hits;
  }
}

function upsertCandidate(
  store: Map<string, FingerprintCandidate>,
  rule: FingerprintRule,
  matcher: RuleMatcher,
  hit: MatcherHit,
): void {
  const existing = store.get(rule.productKey);
  const newConfidence = matcher.baseConfidence ?? 'medium';
  const newVersion = hit.capturedVersion;
  const newCertainty = matcher.versionCertainty ?? (newVersion ? 'probable' : 'unknown');
  const evidence: FingerprintEvidence = {
    source: hit.source,
    detail: hit.detail,
    matchedRule: rule.productKey,
  };

  if (!existing) {
    store.set(rule.productKey, {
      productKey: rule.productKey,
      productName: rule.productName,
      vendor: rule.vendor ?? null,
      category: rule.category,
      version: newVersion,
      versionFamily: extractVersionFamily(newVersion, rule),
      versionCertainty: newCertainty,
      confidence: newConfidence,
      evidence: [evidence],
    });
    return;
  }

  // Merge: keep the strongest version certainty + version, take the max
  // confidence, and append the evidence (deduplicated).
  if (rankCertainty(newCertainty) > rankCertainty(existing.versionCertainty) && newVersion) {
    existing.version = newVersion;
    existing.versionFamily = extractVersionFamily(newVersion, rule);
    existing.versionCertainty = newCertainty;
  } else if (existing.version === null && newVersion) {
    existing.version = newVersion;
    existing.versionFamily = extractVersionFamily(newVersion, rule);
    existing.versionCertainty = newCertainty;
  }

  if (CONFIDENCE_ORDER[newConfidence] > CONFIDENCE_ORDER[existing.confidence]) {
    existing.confidence = newConfidence;
  } else if (existing.evidence.length >= 2 && CONFIDENCE_ORDER[existing.confidence] < CONFIDENCE_ORDER.high) {
    // Two converging signals upgrade one tier (capped at high).
    existing.confidence = bumpConfidence(existing.confidence);
  }

  if (!existing.evidence.some((e) => e.source === evidence.source && e.detail === evidence.detail)) {
    existing.evidence.push(evidence);
  }
}

function rankCertainty(c: VersionCertainty): number {
  switch (c) {
    case 'exact':
      return 4;
    case 'probable':
      return 3;
    case 'family':
      return 2;
    case 'unknown':
      return 1;
  }
}

function bumpConfidence(current: FingerprintConfidence): FingerprintConfidence {
  switch (current) {
    case 'low':
      return 'medium';
    case 'medium':
      return 'high';
    case 'high':
    case 'very_high':
      return 'high';
  }
}
