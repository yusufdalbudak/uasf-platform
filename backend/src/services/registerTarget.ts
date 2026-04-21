import { AppDataSource } from '../db/connection';
import { Target } from '../db/models/Target';
import { AllowedTargetKey } from '../db/models/AllowedTargetKey';
import { normalizeTargetKey } from '../policy/policy';

const HOST_REGEX = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/i;

export type ValidateResult =
  | { ok: true; key: string }
  | { ok: false; error: string };

/** Validates a hostname for registry + allowlist (web assets; no raw URLs). */
export function validateRegistryHostname(raw: string): ValidateResult {
  const key = normalizeTargetKey(raw);
  if (!key) return { ok: false, error: 'Hostname is required' };
  if (key.length > 253) return { ok: false, error: 'Hostname too long' };
  if (key.includes('..')) return { ok: false, error: 'Invalid hostname' };
  if (!HOST_REGEX.test(key)) return { ok: false, error: 'Invalid hostname format' };
  return { ok: true, key };
}

export async function registerApprovedWebTarget(opts: {
  hostnameInput: string;
  displayName?: string | null;
  environment?: string | null;
  apptranaAlias?: string | null;
}): Promise<{ target: Target; targetCreated: boolean; allowlistCreated: boolean }> {
  const v = validateRegistryHostname(opts.hostnameInput);
  if (v.ok === false) {
    throw new Error(v.error);
  }
  const key = v.key;

  const targetRepo = AppDataSource.getRepository(Target);
  const allowRepo = AppDataSource.getRepository(AllowedTargetKey);

  let target = await targetRepo.findOne({ where: { hostname: key } });
  let targetCreated = false;

  if (!target) {
    target = targetRepo.create({
      hostname: key,
      displayName: (opts.displayName?.trim() || key) as string,
      assetType: 'web',
      protocol: 'https',
      port: 443,
      environment: opts.environment?.trim() || 'operator-console',
      businessOwner: null,
      applicationOwner: null,
      tags: ['operator-added'],
      approvalStatus: 'approved',
      assetCriticality: 'medium',
      scanPolicy: 'default-waap',
      apptranaAlias: opts.apptranaAlias?.trim() || null,
      notes: 'Registered from Exposure Management console',
      isApproved: true,
      metadata: { source: 'dashboard' },
    });
    await targetRepo.save(target);
    targetCreated = true;
  }

  let allowlistCreated = false;
  const existingAllow = await allowRepo.findOne({ where: { key } });
  if (!existingAllow) {
    await allowRepo.save(
      allowRepo.create({
        key,
        source: 'operator',
        notes: 'Console registration',
      }),
    );
    allowlistCreated = true;
  }

  return { target, targetCreated, allowlistCreated };
}
