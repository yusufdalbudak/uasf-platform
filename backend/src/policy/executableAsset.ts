import { env } from '../config/env';
import { isTargetKeyAllowed, normalizeTargetKey } from './policy';
import { findApprovedAssetByNormalizedKey } from '../services/assetRegistry';
import { PolicyForbiddenTargetError } from '../safety/guard';

/** No matching row in the approved asset registry (policy may still allowlist the key). */
export class AssetNotRegisteredError extends Error {
  constructor(public readonly targetKey: string) {
    super(`Asset not registered: ${targetKey}`);
    this.name = 'AssetNotRegisteredError';
  }
}

/** Registry row exists but is not approved for executable workflows. */
export class AssetNotApprovedError extends Error {
  constructor(
    public readonly targetKey: string,
    public readonly approvalStatus: string,
  ) {
    super(`Asset not approved for execution: ${targetKey} (${approvalStatus})`);
    this.name = 'AssetNotApprovedError';
  }
}

/**
 * Enforces allowlist + optional registry + approval. All outbound assessment jobs should await this.
 */
export async function assertExecutableApprovedAsset(targetKey: string): Promise<void> {
  const n = normalizeTargetKey(targetKey);
  if (!(await isTargetKeyAllowed(targetKey))) {
    throw new PolicyForbiddenTargetError(n);
  }
  if (!env.requireRegisteredAsset) {
    return;
  }
  const asset = await findApprovedAssetByNormalizedKey(n);
  if (!asset) {
    throw new AssetNotRegisteredError(n);
  }
  if (asset.approvalStatus !== 'approved' || asset.isApproved === false) {
    throw new AssetNotApprovedError(n, asset.approvalStatus);
  }
}
