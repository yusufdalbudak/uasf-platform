/**
 * Service / infrastructure adapter.
 *
 * Converts the already-collected service-banner + TLS evidence into
 * `RawObservation` records so they participate in fusion on equal
 * footing with the rest of the adapters.  This module never invokes
 * Nmap or opens sockets on its own — the engine's probe phase has
 * already captured both sources.
 */

import type { RawObservation } from '../signalTypes';
import type { AdapterContext } from './sharedContext';
import { clip } from './sharedContext';
import { extractFamily } from '../confidenceModel';

export function runServiceAdapter(context: AdapterContext): RawObservation[] {
  const out: RawObservation[] = [];

  // ------------------------------------------------------------------
  // Service banners (Nmap)
  // ------------------------------------------------------------------
  for (const banner of context.serviceBanners) {
    if (!banner.product && !banner.service) continue;
    const productName = banner.product ?? banner.service ?? 'unknown';
    const productKey = productName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .slice(0, 64) || 'unknown_service';
    out.push({
      family: 'service',
      methodId: 'service.nmap_service_version',
      methodLabel: 'Nmap safe service-version',
      signalKey: `${banner.protocol}/${banner.port}`,
      signalValue: clip(banner.banner ?? productName, 200),
      evidenceSnippet: clip(
        `Nmap ${banner.protocol}/${banner.port}: ${productName}${banner.version ? ` ${banner.version}` : ''}`,
        220,
      ),
      productKey,
      productName,
      category: 'service_banner',
      versionLiteral: banner.version ?? null,
      versionState: banner.version ? 'exact' : 'unknown',
      weight: 0.75,
      vendorMatch: Boolean(banner.product),
      intent: banner.version ? 'version_match' : 'product_match',
      metadata: { port: banner.port, protocol: banner.protocol, service: banner.service },
    });
  }

  // ------------------------------------------------------------------
  // TLS certificate → edge / hosting hint
  // ------------------------------------------------------------------
  const tls = context.tls;
  if (tls) {
    const issuer = tls.issuer ?? '';
    const hit = classifyIssuer(issuer);
    if (hit) {
      out.push({
        family: 'tls',
        methodId: 'tls.certificate_metadata',
        methodLabel: 'Certificate issuer / SAN',
        signalKey: 'issuer',
        signalValue: clip(issuer, 200),
        evidenceSnippet: clip(`TLS issuer: ${issuer}`, 200),
        productKey: hit.productKey,
        productName: hit.productName,
        vendor: hit.vendor ?? null,
        category: hit.category,
        versionLiteral: null,
        versionState: 'unknown',
        weight: hit.weight,
        vendorMatch: true,
        intent: 'product_match',
        metadata: { issuer, notAfter: tls.notAfter },
      });
    } else if (issuer) {
      out.push({
        family: 'tls',
        methodId: 'tls.certificate_metadata',
        methodLabel: 'Certificate issuer / SAN',
        signalKey: 'issuer',
        signalValue: clip(issuer, 200),
        evidenceSnippet: clip(`TLS issuer: ${issuer}`, 200),
        productKey: null,
        versionLiteral: null,
        weight: 0.2,
        vendorMatch: false,
        intent: 'structural_hint',
        metadata: { issuer, notAfter: tls.notAfter },
      });
    }
  }

  // ------------------------------------------------------------------
  // Edge/origin relationship hint from passive headers + TLS
  // ------------------------------------------------------------------
  const cfRay = context.headers['cf-ray'];
  const viaHeader = context.headers['via'];
  const x_cf_id = context.headers['x-amz-cf-id'];
  const cdnEvidence: string[] = [];
  if (cfRay) cdnEvidence.push(`cf-ray: ${cfRay}`);
  if (x_cf_id) cdnEvidence.push(`x-amz-cf-id: ${x_cf_id}`);
  if (viaHeader) cdnEvidence.push(`via: ${viaHeader}`);
  if (cdnEvidence.length >= 1) {
    out.push({
      family: 'service',
      methodId: 'service.edge_relationship',
      methodLabel: 'Edge / origin relationship',
      signalKey: 'edge_hint',
      signalValue: clip(cdnEvidence.join(' | '), 200),
      evidenceSnippet: clip(cdnEvidence.join(' | '), 220),
      productKey: null,
      versionLiteral: null,
      weight: 0.15,
      vendorMatch: false,
      intent: 'structural_hint',
    });
  }

  // Suppress unused-import lint if extractFamily is trimmed by tree-shaking in tests.
  void extractFamily;
  return out;
}

function classifyIssuer(
  issuer: string,
): { productKey: string; productName: string; vendor?: string; category: RawObservation['category']; weight: number } | null {
  const i = issuer.toLowerCase();
  if (!i) return null;
  if (i.includes("let's encrypt") || i.includes('r3') || i.includes('r10') || i.includes('r11')) {
    return { productKey: 'letsencrypt', productName: "Let's Encrypt", vendor: 'ISRG', category: 'tls', weight: 0.4 };
  }
  if (i.includes('cloudflare')) {
    return { productKey: 'cloudflare', productName: 'Cloudflare', vendor: 'Cloudflare', category: 'cdn_edge', weight: 0.6 };
  }
  if (i.includes('amazon') || i.includes('aws')) {
    return { productKey: 'aws_acm', productName: 'AWS Certificate Manager', vendor: 'AWS', category: 'cdn_edge', weight: 0.5 };
  }
  if (i.includes('google trust') || i.includes('gts ca')) {
    return { productKey: 'google_trust', productName: 'Google Trust Services', vendor: 'Google', category: 'tls', weight: 0.4 };
  }
  if (i.includes('digicert')) {
    return { productKey: 'digicert', productName: 'DigiCert', vendor: 'DigiCert', category: 'tls', weight: 0.3 };
  }
  if (i.includes('microsoft')) {
    return { productKey: 'microsoft_rsa', productName: 'Microsoft TLS CA', vendor: 'Microsoft', category: 'tls', weight: 0.4 };
  }
  return null;
}
