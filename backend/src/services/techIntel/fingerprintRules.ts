/**
 * UASF Tech Intelligence — Fingerprint Rule Library
 *
 * Declarative, vendor-agnostic detection rules for the fingerprinting
 * engine.  Each rule is a tiny piece of code-light data:
 *
 *   { product, vendor, category, sources… }
 *
 * with one or more "where to look" sources.  Sources are matched with a
 * regular expression; when a match contains a capture group, that group
 * becomes the version string.
 *
 * Design choices:
 *
 *   - **No exec, no eval.**  Rules are pure data; the engine in
 *     `fingerprintEngine.ts` interprets them.  This keeps the surface
 *     area auditable and lets us test rules in isolation.
 *
 *   - **Explicit version certainty.**  Each rule declares what kind of
 *     version evidence it produces (`exact`, `probable`, `family`, or
 *     `unknown`) so we never accidentally upgrade a guessed version to
 *     "definitely vulnerable" in the correlator.
 *
 *   - **Confidence is per-source, not per-rule.**  The engine combines
 *     converging signals: two independent sources matching the same
 *     product upgrade the confidence; a single header banner sits at
 *     `medium`.
 *
 *   - **Curated set, not a 1500-rule fingerprint zoo.**  We focus on the
 *     vendors most relevant for an enterprise validation framework:
 *     web servers, edge / CDN / WAF platforms, popular runtimes,
 *     widely-deployed CMSes, and a handful of JS libraries.  Adding new
 *     rules is a one-PR data change.
 */

import type {
  FingerprintConfidence,
  TechnologyCategory,
  VersionCertainty,
} from '../../db/models/DetectedTechnology';

export type RuleSource =
  | 'header'
  | 'cookie'
  | 'body_marker'
  | 'tls'
  | 'banner'
  | 'meta_tag'
  | 'asset'
  | 'script';

export interface RuleMatcher {
  /**
   * Where the engine should look for this matcher.  For `header` /
   * `cookie` the `field` selects the specific header / cookie name
   * (lower-cased).  For everything else `field` is ignored.
   */
  source: RuleSource;
  field?: string;
  /**
   * Regular expression evaluated against the source content.  When the
   * regex contains a capture group, the first group's value becomes the
   * detected version string.
   */
  pattern: RegExp;
  /** Version certainty produced by **this matcher** when it fires. */
  versionCertainty?: VersionCertainty;
  /** Per-matcher base confidence (default `medium`). */
  baseConfidence?: FingerprintConfidence;
  /** Free-form note shown in the evidence drawer. */
  note?: string;
}

export interface FingerprintRule {
  /** Stable identity used as the join key for vulnerability correlation. */
  productKey: string;
  productName: string;
  vendor?: string;
  category: TechnologyCategory;
  matchers: RuleMatcher[];
  /**
   * Optional: extract a major.minor "family" from the captured version
   * string.  Default: `^(\d+(?:\.\d+)?)` which yields `1.2` from `1.2.3`.
   */
  versionFamilyExtractor?: RegExp;
}

const DEFAULT_FAMILY_EXTRACTOR = /^(\d+(?:\.\d+)?)/;

/**
 * Curated rule set.  Order is irrelevant — the engine evaluates all
 * matchers and merges duplicate productKey hits.
 */
export const FINGERPRINT_RULES: FingerprintRule[] = [
  // ---------------------------------------------------------------
  // Web servers
  // ---------------------------------------------------------------
  {
    productKey: 'nginx',
    productName: 'nginx',
    vendor: 'F5 / nginx.org',
    category: 'web_server',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bnginx(?:\/(\d+\.\d+(?:\.\d+)?))?/i,
        versionCertainty: 'exact',
        baseConfidence: 'high',
        note: 'Server header banner',
      },
      {
        source: 'header',
        field: 'x-powered-by',
        pattern: /\bnginx(?:\/(\d+\.\d+(?:\.\d+)?))?/i,
        versionCertainty: 'probable',
        baseConfidence: 'medium',
      },
    ],
  },
  {
    productKey: 'apache_httpd',
    productName: 'Apache HTTP Server',
    vendor: 'Apache Software Foundation',
    category: 'web_server',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bApache(?:\/(\d+\.\d+(?:\.\d+)?))?/i,
        versionCertainty: 'exact',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'iis',
    productName: 'Microsoft IIS',
    vendor: 'Microsoft',
    category: 'web_server',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bMicrosoft-IIS(?:\/(\d+\.\d+))?/i,
        versionCertainty: 'exact',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'caddy',
    productName: 'Caddy',
    vendor: 'caddyserver.com',
    category: 'web_server',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bCaddy(?:\/(\d+\.\d+(?:\.\d+)?))?/i,
        versionCertainty: 'exact',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'lighttpd',
    productName: 'lighttpd',
    category: 'web_server',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\blighttpd(?:\/(\d+\.\d+(?:\.\d+)?))?/i,
        versionCertainty: 'exact',
        baseConfidence: 'high',
      },
    ],
  },

  // ---------------------------------------------------------------
  // CDN / Edge / Reverse proxies
  // ---------------------------------------------------------------
  {
    productKey: 'cloudflare',
    productName: 'Cloudflare',
    vendor: 'Cloudflare, Inc.',
    category: 'cdn_edge',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bcloudflare\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
      {
        source: 'header',
        field: 'cf-ray',
        pattern: /^[a-f0-9]{12,}/i,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
        note: 'cf-ray response header',
      },
      {
        source: 'cookie',
        field: '__cf_bm',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
        note: 'Cloudflare bot-management cookie',
      },
    ],
  },
  {
    productKey: 'akamai',
    productName: 'Akamai Edge',
    vendor: 'Akamai Technologies',
    category: 'cdn_edge',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bakamaighost\b|\bakamai\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
      {
        source: 'header',
        field: 'x-akamai-transformed',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'cloudfront',
    productName: 'Amazon CloudFront',
    vendor: 'Amazon Web Services',
    category: 'cdn_edge',
    matchers: [
      {
        source: 'header',
        field: 'via',
        pattern: /\bcloudfront\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
      {
        source: 'header',
        field: 'x-amz-cf-id',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'fastly',
    productName: 'Fastly',
    vendor: 'Fastly, Inc.',
    category: 'cdn_edge',
    matchers: [
      {
        source: 'header',
        field: 'x-served-by',
        pattern: /\bcache-/i,
        versionCertainty: 'unknown',
        baseConfidence: 'medium',
      },
      {
        source: 'header',
        field: 'x-fastly-request-id',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
    ],
  },

  // ---------------------------------------------------------------
  // WAFs (presence detection only — no bypass logic)
  // ---------------------------------------------------------------
  {
    productKey: 'apptrana',
    productName: 'AppTrana WAAP',
    vendor: 'Indusface',
    category: 'waf',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bapptrana\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
      {
        source: 'header',
        field: 'x-apptrana',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'imperva',
    productName: 'Imperva / Incapsula',
    vendor: 'Imperva',
    category: 'waf',
    matchers: [
      {
        source: 'header',
        field: 'x-iinfo',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
      {
        source: 'cookie',
        field: 'incap_ses',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'sucuri',
    productName: 'Sucuri Web Application Firewall',
    vendor: 'Sucuri',
    category: 'waf',
    matchers: [
      {
        source: 'header',
        field: 'x-sucuri-id',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
      {
        source: 'header',
        field: 'server',
        pattern: /\bsucuri\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'awswaf',
    productName: 'AWS WAF',
    vendor: 'Amazon Web Services',
    category: 'waf',
    matchers: [
      {
        source: 'header',
        field: 'x-amzn-waf-action',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'f5_bigip',
    productName: 'F5 BIG-IP',
    vendor: 'F5 Networks',
    category: 'waf',
    matchers: [
      {
        source: 'header',
        field: 'server',
        pattern: /\bbig-?ip\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
      {
        source: 'cookie',
        field: 'BIGipServer',
        pattern: /.+/,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
    ],
  },

  // ---------------------------------------------------------------
  // Application frameworks / runtimes
  // ---------------------------------------------------------------
  {
    productKey: 'express',
    productName: 'Express.js',
    vendor: 'OpenJS Foundation',
    category: 'application_framework',
    matchers: [
      {
        source: 'header',
        field: 'x-powered-by',
        pattern: /\bExpress\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'php',
    productName: 'PHP',
    vendor: 'PHP Group',
    category: 'language_runtime',
    matchers: [
      {
        source: 'header',
        field: 'x-powered-by',
        pattern: /\bPHP\/(\d+\.\d+(?:\.\d+)?)/i,
        versionCertainty: 'exact',
        baseConfidence: 'high',
      },
      {
        source: 'cookie',
        field: 'phpsessid',
        pattern: /.+/i,
        versionCertainty: 'unknown',
        baseConfidence: 'medium',
      },
    ],
  },
  {
    productKey: 'aspnet',
    productName: 'ASP.NET',
    vendor: 'Microsoft',
    category: 'application_framework',
    matchers: [
      {
        source: 'header',
        field: 'x-powered-by',
        pattern: /\bASP\.NET\b/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
      {
        source: 'header',
        field: 'x-aspnet-version',
        pattern: /(\d+\.\d+(?:\.\d+)?)/,
        versionCertainty: 'exact',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'rails',
    productName: 'Ruby on Rails',
    vendor: 'rubyonrails.org',
    category: 'application_framework',
    matchers: [
      {
        source: 'cookie',
        field: '_rails_session',
        pattern: /.+/i,
        versionCertainty: 'unknown',
        baseConfidence: 'medium',
      },
      {
        source: 'header',
        field: 'x-runtime',
        pattern: /\d+/,
        versionCertainty: 'unknown',
        baseConfidence: 'low',
        note: 'X-Runtime header is a Rack convention; Rails is probable but not guaranteed.',
      },
    ],
  },
  {
    productKey: 'django',
    productName: 'Django',
    vendor: 'Django Software Foundation',
    category: 'application_framework',
    matchers: [
      {
        source: 'cookie',
        field: 'csrftoken',
        pattern: /.+/i,
        versionCertainty: 'unknown',
        baseConfidence: 'medium',
      },
      {
        source: 'cookie',
        field: 'sessionid',
        pattern: /.+/i,
        versionCertainty: 'unknown',
        baseConfidence: 'low',
      },
    ],
  },

  // ---------------------------------------------------------------
  // CMS / Platforms
  // ---------------------------------------------------------------
  {
    productKey: 'wordpress',
    productName: 'WordPress',
    vendor: 'WordPress.org',
    category: 'cms_platform',
    matchers: [
      {
        source: 'meta_tag',
        pattern: /name=["']generator["'][^>]+content=["']WordPress\s+(\d+\.\d+(?:\.\d+)?)?/i,
        versionCertainty: 'exact',
        baseConfidence: 'very_high',
      },
      {
        source: 'asset',
        pattern: /\/wp-content\//i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
      {
        source: 'asset',
        pattern: /\/wp-includes\//i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'drupal',
    productName: 'Drupal',
    vendor: 'Drupal Association',
    category: 'cms_platform',
    matchers: [
      {
        source: 'header',
        field: 'x-generator',
        pattern: /\bDrupal\s*(\d+(?:\.\d+)?)?/i,
        versionCertainty: 'probable',
        baseConfidence: 'high',
      },
      {
        source: 'meta_tag',
        pattern: /name=["']generator["'][^>]+content=["']Drupal\s+(\d+(?:\.\d+)?)?/i,
        versionCertainty: 'probable',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'joomla',
    productName: 'Joomla!',
    vendor: 'Open Source Matters',
    category: 'cms_platform',
    matchers: [
      {
        source: 'meta_tag',
        pattern: /name=["']generator["'][^>]+content=["']Joomla!?\s*(?:-\s*Open Source Content Management)?(?:\s+(\d+(?:\.\d+)?))?/i,
        versionCertainty: 'probable',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'shopify',
    productName: 'Shopify',
    vendor: 'Shopify Inc.',
    category: 'cms_platform',
    matchers: [
      {
        source: 'header',
        field: 'x-shopid',
        pattern: /\d+/,
        versionCertainty: 'unknown',
        baseConfidence: 'very_high',
      },
      {
        source: 'header',
        field: 'x-shardid',
        pattern: /\d+/,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
    ],
  },

  // ---------------------------------------------------------------
  // JS libraries / frontend frameworks (asset / script markers)
  // ---------------------------------------------------------------
  {
    productKey: 'jquery',
    productName: 'jQuery',
    vendor: 'OpenJS Foundation',
    category: 'js_library',
    matchers: [
      {
        source: 'script',
        pattern: /jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
        versionCertainty: 'exact',
        baseConfidence: 'high',
      },
      {
        source: 'body_marker',
        pattern: /window\.jQuery|jQuery\.fn\.jquery/i,
        versionCertainty: 'unknown',
        baseConfidence: 'medium',
      },
    ],
  },
  {
    productKey: 'react',
    productName: 'React',
    vendor: 'Meta Platforms',
    category: 'js_library',
    matchers: [
      {
        source: 'script',
        pattern: /react[@/-](\d+\.\d+(?:\.\d+)?)/i,
        versionCertainty: 'probable',
        baseConfidence: 'high',
      },
      {
        source: 'body_marker',
        pattern: /data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__/i,
        versionCertainty: 'unknown',
        baseConfidence: 'medium',
      },
    ],
  },
  {
    productKey: 'angular',
    productName: 'Angular',
    vendor: 'Google',
    category: 'js_library',
    matchers: [
      {
        source: 'body_marker',
        pattern: /ng-version=["'](\d+\.\d+(?:\.\d+)?)["']/i,
        versionCertainty: 'exact',
        baseConfidence: 'very_high',
      },
    ],
  },
  {
    productKey: 'vue',
    productName: 'Vue.js',
    vendor: 'Evan You / Vue.js team',
    category: 'js_library',
    matchers: [
      {
        source: 'script',
        pattern: /vue[@/-](\d+\.\d+(?:\.\d+)?)/i,
        versionCertainty: 'probable',
        baseConfidence: 'high',
      },
    ],
  },
  {
    productKey: 'bootstrap',
    productName: 'Bootstrap',
    vendor: 'Twitter / OSS',
    category: 'js_library',
    matchers: [
      {
        source: 'script',
        pattern: /bootstrap[@/-](\d+\.\d+(?:\.\d+)?)/i,
        versionCertainty: 'probable',
        baseConfidence: 'medium',
      },
    ],
  },

  // ---------------------------------------------------------------
  // Analytics / tag managers (low-noise, useful inventory)
  // ---------------------------------------------------------------
  {
    productKey: 'google_analytics',
    productName: 'Google Analytics',
    vendor: 'Google',
    category: 'analytics',
    matchers: [
      {
        source: 'script',
        pattern: /www\.google-analytics\.com\/analytics\.js|googletagmanager\.com\/gtag\/js/i,
        versionCertainty: 'unknown',
        baseConfidence: 'high',
      },
    ],
  },
];

/**
 * Helper used by the engine: extract the major.minor "family" from a raw
 * version string, falling back to the raw value if extraction fails.
 */
export function extractVersionFamily(rawVersion: string | null, rule?: FingerprintRule): string | null {
  if (!rawVersion) return null;
  const re = rule?.versionFamilyExtractor ?? DEFAULT_FAMILY_EXTRACTOR;
  const m = re.exec(rawVersion);
  return m ? m[1] : rawVersion;
}
