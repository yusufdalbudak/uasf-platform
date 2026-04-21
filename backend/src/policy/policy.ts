import { env } from '../config/env';
import { AppDataSource } from '../db/connection';
import { AllowedTargetKey } from '../db/models/AllowedTargetKey';
import { normalizeOperatorTargetInput } from '../../../shared/scanContract';

/**
 * Normalizes operator input for policy checks and outbound URLs:
 * strips `http(s)://`, paths, query strings, and ports; preserves AppTrana-style labels
 * (e.g. `app.example.com_API`) when the value is not a URL.
 */
export function normalizeTargetKey(input: string): string {
  return normalizeOperatorTargetInput(input);
}

/** Normalized allowlist entries from deployment env only. */
export function getEnvAllowlistKeys(): string[] {
  return env.allowedTargets
    .split(',')
    .map((s) => normalizeTargetKey(s.trim()))
    .filter(Boolean);
}

/** Env keys plus operator-added keys from the database (async). */
export async function getMergedAllowlistKeys(): Promise<string[]> {
  const envKeys = getEnvAllowlistKeys();
  const repo = AppDataSource.getRepository(AllowedTargetKey);
  const rows = await repo.find();
  const dbKeys = rows.map((r) => r.key);
  return [...new Set([...envKeys, ...dbKeys])].sort();
}

/**
 * Returns true if the hostname/label is on the deployment allowlist OR registered as an operator allowlist key.
 */
export async function isTargetKeyAllowed(targetKey: string): Promise<boolean> {
  const n = normalizeTargetKey(targetKey);
  if (!n) return false;
  if (getEnvAllowlistKeys().includes(n)) return true;
  const repo = AppDataSource.getRepository(AllowedTargetKey);
  const row = await repo.findOne({ where: { key: n } });
  return !!row;
}

/**
 * Resolves a protected hostname for HTTPS requests when only legacy heuristics apply
 * (e.g. AppTrana console label `host_API` → `host`).
 */
export function stripAppTranaApiSuffix(hostnameOrLabel: string): string {
  return hostnameOrLabel.replace(/_API$/i, '');
}
