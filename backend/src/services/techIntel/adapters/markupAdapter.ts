/**
 * Markup adapter.
 *
 * Produces observations from the HTML body, `<meta>` fragments, and
 * `<script>` / `<link>` asset URLs.  Pure interpretation; no I/O.
 */

import type { RawObservation } from '../signalTypes';
import type { AdapterContext } from './sharedContext';
import { clip } from './sharedContext';

interface BodySignature {
  productKey: string;
  productName: string;
  vendor?: string;
  category: RawObservation['category'];
  pattern: RegExp;
  weight?: number;
  versionCapture?: boolean;
  methodId?:
    | 'markup.body_signature'
    | 'markup.asset_naming'
    | 'markup.inline_script_marker'
    | 'markup.meta_generator'
    | 'markup.html_comment';
}

const META_GENERATOR_PATTERNS: Array<{
  pattern: RegExp;
  productKey: string;
  productName: string;
  vendor?: string;
  category: RawObservation['category'];
}> = [
  { pattern: /WordPress\s*(\d+\.\d+(?:\.\d+)?)?/i, productKey: 'wordpress', productName: 'WordPress', category: 'cms_platform' },
  { pattern: /Drupal\s*(\d+(?:\.\d+)?)/i, productKey: 'drupal', productName: 'Drupal', category: 'cms_platform' },
  { pattern: /Joomla!?\s*(\d+\.\d+(?:\.\d+)?)?/i, productKey: 'joomla', productName: 'Joomla', category: 'cms_platform' },
  { pattern: /Ghost\s*(\d+\.\d+(?:\.\d+)?)?/i, productKey: 'ghost', productName: 'Ghost', category: 'cms_platform' },
  { pattern: /Hugo\s*(\d+\.\d+(?:\.\d+)?)?/i, productKey: 'hugo', productName: 'Hugo', category: 'application_framework' },
  { pattern: /Shopify/i, productKey: 'shopify', productName: 'Shopify', category: 'cms_platform' },
  { pattern: /Gatsby\s*(\d+\.\d+(?:\.\d+)?)?/i, productKey: 'gatsby', productName: 'Gatsby', category: 'application_framework' },
  { pattern: /Wix\.com/i, productKey: 'wix', productName: 'Wix', category: 'cms_platform' },
];

const BODY_SIGNATURES: BodySignature[] = [
  { productKey: 'wordpress', productName: 'WordPress', category: 'cms_platform', pattern: /\/wp-content\//i, weight: 0.75, methodId: 'markup.body_signature' },
  { productKey: 'drupal', productName: 'Drupal', category: 'cms_platform', pattern: /sites\/default\/files\//i, weight: 0.75, methodId: 'markup.body_signature' },
  { productKey: 'shopify', productName: 'Shopify', category: 'cms_platform', pattern: /Shopify\.theme/i, weight: 0.85, methodId: 'markup.body_signature' },
  { productKey: 'next_js', productName: 'Next.js', vendor: 'Vercel', category: 'application_framework', pattern: /__NEXT_DATA__|\/_next\/static\//, weight: 0.85, methodId: 'markup.body_signature' },
  { productKey: 'react', productName: 'React', category: 'js_library', pattern: /data-reactroot|data-reactid/i, weight: 0.7, methodId: 'markup.body_signature' },
  { productKey: 'angular', productName: 'Angular', vendor: 'Google', category: 'js_library', pattern: /ng-version="(\d+\.\d+(?:\.\d+)?)?"/i, weight: 0.85, versionCapture: true, methodId: 'markup.body_signature' },
  { productKey: 'vue', productName: 'Vue.js', category: 'js_library', pattern: /id="app".*?v-app|__VUE__|vue@(\d+\.\d+(?:\.\d+)?)/i, weight: 0.65, versionCapture: true, methodId: 'markup.body_signature' },
  { productKey: 'magento', productName: 'Magento', vendor: 'Adobe', category: 'cms_platform', pattern: /mage-init|Mage\.Cookies/i, weight: 0.8, methodId: 'markup.body_signature' },
  { productKey: 'laravel', productName: 'Laravel', category: 'application_framework', pattern: /laravel_session|csrf-token/i, weight: 0.6, methodId: 'markup.body_signature' },
  { productKey: 'jquery', productName: 'jQuery', category: 'js_library', pattern: /jquery(?:[-.](\d+\.\d+(?:\.\d+)?))?/i, weight: 0.5, versionCapture: true, methodId: 'markup.inline_script_marker' },
];

const ASSET_PATTERNS: Array<{
  pattern: RegExp;
  productKey: string;
  productName: string;
  vendor?: string;
  category: RawObservation['category'];
  weight?: number;
  versionCapture?: boolean;
}> = [
  { pattern: /\/wp-content\/(?:plugins|themes)\//i, productKey: 'wordpress', productName: 'WordPress', category: 'cms_platform', weight: 0.85 },
  { pattern: /\/_next\/static\//i, productKey: 'next_js', productName: 'Next.js', vendor: 'Vercel', category: 'application_framework', weight: 0.85 },
  { pattern: /\/_nuxt\//i, productKey: 'nuxt_js', productName: 'Nuxt.js', category: 'application_framework', weight: 0.85 },
  { pattern: /\/ajax\/libs\/jquery\/(\d+\.\d+(?:\.\d+)?)\//i, productKey: 'jquery', productName: 'jQuery', category: 'js_library', weight: 0.75, versionCapture: true },
  { pattern: /\/cdn\/shop\//i, productKey: 'shopify', productName: 'Shopify', category: 'cms_platform', weight: 0.85 },
];

export function runMarkupAdapter(context: AdapterContext): RawObservation[] {
  const out: RawObservation[] = [];
  const body = context.body;

  // Meta generator tags
  for (const meta of context.metaTags) {
    const lower = meta.toLowerCase();
    if (!/name\s*=\s*["']?generator["']?/.test(lower)) continue;
    const content = /content\s*=\s*["']([^"']+)["']/i.exec(meta)?.[1];
    if (!content) continue;
    for (const sig of META_GENERATOR_PATTERNS) {
      const m = sig.pattern.exec(content);
      if (!m) continue;
      const version = m[1] ?? null;
      out.push({
        family: 'markup',
        methodId: 'markup.meta_generator',
        methodLabel: 'Meta generator tag',
        signalKey: 'meta:generator',
        signalValue: clip(content, 220),
        evidenceSnippet: clip(meta, 220),
        productKey: sig.productKey,
        productName: sig.productName,
        vendor: sig.vendor ?? null,
        category: sig.category,
        versionLiteral: version,
        versionState: version ? 'exact' : 'probable',
        weight: version ? 0.9 : 0.75,
        vendorMatch: true,
        intent: version ? 'version_match' : 'product_match',
      });
    }
  }

  // Body signatures
  for (const sig of BODY_SIGNATURES) {
    const m = sig.pattern.exec(body);
    if (!m) continue;
    const version = sig.versionCapture ? m[1] ?? null : null;
    out.push({
      family: 'markup',
      methodId: sig.methodId ?? 'markup.body_signature',
      methodLabel: labelForMethod(sig.methodId ?? 'markup.body_signature'),
      signalKey: sig.productKey,
      signalValue: clip(m[0], 200),
      evidenceSnippet: clip(m[0], 200),
      productKey: sig.productKey,
      productName: sig.productName,
      vendor: sig.vendor ?? null,
      category: sig.category,
      versionLiteral: version,
      versionState: version ? 'probable' : 'unknown',
      weight: sig.weight ?? 0.55,
      vendorMatch: true,
      intent: version ? 'version_match' : 'product_match',
    });
  }

  // Asset naming
  for (const url of [...context.scriptUrls, ...context.assetUrls]) {
    for (const sig of ASSET_PATTERNS) {
      const m = sig.pattern.exec(url);
      if (!m) continue;
      const version = sig.versionCapture ? m[1] ?? null : null;
      out.push({
        family: 'markup',
        methodId: 'markup.asset_naming',
        methodLabel: 'Static asset naming',
        signalKey: sig.productKey,
        signalValue: clip(url, 200),
        evidenceSnippet: clip(url, 200),
        productKey: sig.productKey,
        productName: sig.productName,
        vendor: sig.vendor ?? null,
        category: sig.category,
        versionLiteral: version,
        versionState: version ? 'exact' : 'probable',
        weight: sig.weight ?? 0.55,
        vendorMatch: true,
        intent: version ? 'version_match' : 'product_match',
      });
      break;
    }
  }

  // HTML comment leakage (soft signal)
  const commentRegex = /<!--\s*([^<>]{0,120})\s*-->/g;
  let m: RegExpExecArray | null;
  let commentHits = 0;
  while ((m = commentRegex.exec(body)) && commentHits < 3) {
    const text = m[1] ?? '';
    const lower = text.toLowerCase();
    const hit = /hugo|generated by|built with|powered by/.test(lower);
    if (!hit) continue;
    commentHits += 1;
    out.push({
      family: 'markup',
      methodId: 'markup.html_comment',
      methodLabel: 'HTML comment leakage',
      signalKey: 'html_comment',
      signalValue: clip(text, 180),
      evidenceSnippet: clip(text, 180),
      productKey: null,
      versionLiteral: null,
      weight: 0.25,
      vendorMatch: false,
      intent: 'structural_hint',
    });
  }

  return out;
}

function labelForMethod(id: string): string {
  switch (id) {
    case 'markup.body_signature':
      return 'HTML body signature';
    case 'markup.asset_naming':
      return 'Static asset naming';
    case 'markup.inline_script_marker':
      return 'Inline script marker';
    case 'markup.meta_generator':
      return 'Meta generator tag';
    case 'markup.html_comment':
      return 'HTML comment leakage';
    default:
      return id;
  }
}
