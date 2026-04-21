import { normalizeTargetKey, stripAppTranaApiSuffix } from '../policy/policy';
import { findApprovedAssetByNormalizedKey } from '../services/assetRegistry';

/**
 * Resolves an operator-supplied key (hostname, URL, or AppTrana label) to the protected hostname used in URLs.
 */
export async function resolveProtectedHostname(targetKey: string): Promise<string> {
  const keyNorm = normalizeTargetKey(targetKey);
  const asset = await findApprovedAssetByNormalizedKey(keyNorm);
  if (asset?.hostname) {
    return asset.hostname;
  }
  return stripAppTranaApiSuffix(keyNorm);
}
