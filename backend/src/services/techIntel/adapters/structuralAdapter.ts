/**
 * DOM / structural adapter.
 *
 * Produces structural feature observations from the root HTML.  These
 * are lower-weight "shape" signals that, on their own, don't identify a
 * product — they corroborate other adapters and give the signal-fusion
 * engine something to work with when banner markers are stripped.
 *
 * This module is the closest analog to the ML-style fingerprint
 * recognition research: we produce a compact structural feature vector
 * (tag counts, asset ratios, class-token bigrams) that can later be fed
 * into a clustering/classification pipeline without changing the
 * adapter surface.
 */

import type { RawObservation } from '../signalTypes';
import type { AdapterContext } from './sharedContext';
import { clip } from './sharedContext';

const LAYOUT_TOKENS: Array<{ regex: RegExp; productKey: string; productName: string; category: RawObservation['category']; weight: number }> = [
  { regex: /class="[^"]*\bwp-block-/i, productKey: 'wordpress', productName: 'WordPress', category: 'cms_platform', weight: 0.6 },
  { regex: /class="[^"]*\belementor-/i, productKey: 'elementor', productName: 'Elementor', category: 'application_framework', weight: 0.7 },
  { regex: /class="[^"]*\bmui-/i, productKey: 'material_ui', productName: 'Material UI', category: 'js_library', weight: 0.55 },
  { regex: /class="[^"]*\b(col|row|container)(?:-fluid|-\d+)?\b/i, productKey: 'bootstrap', productName: 'Bootstrap', category: 'js_library', weight: 0.3 },
  { regex: /class="[^"]*\btailwind/i, productKey: 'tailwind_css', productName: 'Tailwind CSS', category: 'js_library', weight: 0.55 },
  { regex: /class="[^"]*\b(?:tw-[a-z0-9]+|bg-[a-z]+-\d+)\b/i, productKey: 'tailwind_css', productName: 'Tailwind CSS', category: 'js_library', weight: 0.4 },
];

export function runStructuralAdapter(context: AdapterContext): RawObservation[] {
  const out: RawObservation[] = [];
  const body = context.body;
  if (!body) return out;

  // Tag-frequency profile
  const counts = {
    script: countTag(body, 'script'),
    link: countTag(body, 'link'),
    meta: countTag(body, 'meta'),
    div: countTag(body, 'div'),
    section: countTag(body, 'section'),
    img: countTag(body, 'img'),
  };
  out.push({
    family: 'dom_structural',
    methodId: 'dom_structural.tag_profile',
    methodLabel: 'Tag frequency profile',
    signalKey: 'tag_counts',
    signalValue: JSON.stringify(counts),
    evidenceSnippet: clip(
      `tags: script=${counts.script} link=${counts.link} meta=${counts.meta} div=${counts.div} section=${counts.section} img=${counts.img}`,
      200,
    ),
    productKey: null,
    versionLiteral: null,
    weight: 0.15,
    vendorMatch: false,
    intent: 'structural_hint',
    metadata: counts,
  });

  // Resource inclusion pattern
  const scriptCount = context.scriptUrls.length;
  const assetCount = context.assetUrls.length;
  const hosts = new Set<string>();
  for (const url of [...context.scriptUrls, ...context.assetUrls]) {
    try {
      if (url.startsWith('//')) hosts.add(new URL(`https:${url}`).hostname);
      else if (url.startsWith('http')) hosts.add(new URL(url).hostname);
    } catch {
      // ignore malformed URL; still counted above
    }
  }
  if (scriptCount + assetCount > 0) {
    out.push({
      family: 'dom_structural',
      methodId: 'dom_structural.resource_inclusion',
      methodLabel: 'Resource inclusion pattern',
      signalKey: 'resource_stats',
      signalValue: JSON.stringify({ scripts: scriptCount, assets: assetCount, hosts: hosts.size }),
      evidenceSnippet: clip(
        `scripts=${scriptCount}, assets=${assetCount}, distinct hosts=${hosts.size}`,
        200,
      ),
      productKey: null,
      versionLiteral: null,
      weight: 0.15,
      vendorMatch: false,
      intent: 'structural_hint',
      metadata: { scriptCount, assetCount, hostCount: hosts.size, hosts: [...hosts].slice(0, 8) },
    });
  }

  // Layout marker classes
  for (const token of LAYOUT_TOKENS) {
    const m = token.regex.exec(body);
    if (!m) continue;
    out.push({
      family: 'dom_structural',
      methodId: 'dom_structural.layout_markers',
      methodLabel: 'Layout marker classes',
      signalKey: token.productKey,
      signalValue: clip(m[0], 200),
      evidenceSnippet: clip(m[0], 200),
      productKey: token.productKey,
      productName: token.productName,
      category: token.category,
      versionLiteral: null,
      versionState: 'unknown',
      weight: token.weight,
      vendorMatch: true,
      intent: 'family_hint',
    });
  }

  return out;
}

function countTag(body: string, tag: string): number {
  const pattern = new RegExp(`<${tag}\\b`, 'gi');
  return (body.match(pattern) ?? []).length;
}
