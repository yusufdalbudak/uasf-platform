/**
 * Shared observation context passed to every Tech Intelligence adapter.
 *
 * The context is the read-only, pre-collected view of the target built
 * by the engine's probe phase.  Adapters never issue new probes
 * themselves (with the single exception of the URL-route and behaviour
 * adapters, which are allowed to issue bounded, safe-by-design HTTP
 * requests).  Everything else is interpretation.
 */

export interface AdapterContext {
  /** Base URL the engine resolved (`https://example.com` or `http://…`). */
  baseUrl: string | null;
  /** Lower-cased HTTP response headers from the root GET/HEAD. */
  headers: Record<string, string>;
  /** Parsed cookies (name → value, lower-case name). */
  cookies: Record<string, string>;
  /** HTML body preview (≤16 KB) from the root GET. */
  body: string;
  /** Extracted `<script src=…>` URLs. */
  scriptUrls: string[];
  /** Extracted `<link href=…>` / `<img src=…>` non-script URLs. */
  assetUrls: string[];
  /** Raw `<meta …>` fragments from the body. */
  metaTags: string[];
  /** TLS evidence harvested from the TLS scanner (may be null). */
  tls: { issuer?: string; subject?: string; notAfter?: string; sans?: string[] } | null;
  /** Service banners from the controlled Nmap probe. */
  serviceBanners: Array<{
    port: number;
    protocol: string;
    service: string;
    product?: string;
    version?: string;
    banner?: string;
  }>;
  /** Host that was probed (already asserted safe). */
  hostname: string;
  /** HTTP timeout budget the engine was started with. */
  httpTimeoutMs: number;
}

/** Small helper to truncate an evidence string to a bounded length. */
export function clip(value: string, max = 160): string {
  if (!value) return '';
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}
