import { AppDataSource } from '../db/connection';
import { Target } from '../db/models/Target';
import { TargetAlias } from '../db/models/TargetAlias';

/**
 * Looks up an approved asset by normalized hostname or AppTrana label (case-insensitive).
 */
export async function findApprovedAssetByNormalizedKey(keyNorm: string): Promise<Target | null> {
  const aliasRepo = AppDataSource.getRepository(TargetAlias);
  const alias = await aliasRepo
    .createQueryBuilder('a')
    .leftJoinAndSelect('a.target', 'target')
    .where('LOWER(a.label) = :l', { l: keyNorm })
    .getOne();
  if (alias?.target) {
    return alias.target;
  }

  const targetRepo = AppDataSource.getRepository(Target);
  return targetRepo
    .createQueryBuilder('t')
    .where('LOWER(t.hostname) = :h', { h: keyNorm })
    .getOne();
}
