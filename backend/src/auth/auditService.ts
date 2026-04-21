import { AppDataSource } from '../db/connection';
import {
  AuthAuditLog,
  type AuthAuditAction,
} from '../db/models/AuthAuditLog';

/**
 * Append a row to the auth audit ledger.
 *
 * Failures are SWALLOWED so a transient DB issue never blocks a user from
 * logging in or out — the ledger is best-effort. If you want stronger
 * delivery guarantees, replace this with a queue producer.
 */
export interface AuditEvent {
  action: AuthAuditAction;
  userId: string | null;
  email: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata?: Record<string, unknown> | null;
}

export async function recordAuditEvent(evt: AuditEvent): Promise<void> {
  try {
    const repo = AppDataSource.getRepository(AuthAuditLog);
    await repo.save(
      repo.create({
        action: evt.action,
        userId: evt.userId,
        email: evt.email,
        ipAddress: evt.ipAddress,
        userAgent: evt.userAgent ? evt.userAgent.slice(0, 512) : null,
        metadata: evt.metadata ?? null,
      }),
    );
  } catch (e) {
    console.warn('[auth] audit log write failed', (e as Error).message);
  }
}
