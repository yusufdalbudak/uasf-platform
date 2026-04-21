import { FastifyRequest, FastifyReply } from 'fastify';
import { isTargetKeyAllowed, normalizeTargetKey } from '../policy/policy';

/**
 * Safety control plane: liveness/readiness endpoints bypass enforcement.
 * Outbound requests are validated again in the assessment worker.
 */
export async function preHandlerSafetyGuard(request: FastifyRequest, _reply: FastifyReply) {
  const path = request.url.split('?')[0];
  if (path === '/api/health' || path === '/api/ready') {
    return;
  }
}

/** Thrown when a requested target key is not permitted by deployment policy (HTTP 403). */
export class PolicyForbiddenTargetError extends Error {
  constructor(public readonly targetKey: string) {
    super(`Policy denied target: ${targetKey}`);
    this.name = 'PolicyForbiddenTargetError';
  }
}

/** Throws {@link PolicyForbiddenTargetError} if the target key is not on the allowlist. */
export async function assertTargetKeyAllowed(targetKey: string): Promise<void> {
  if (!(await isTargetKeyAllowed(targetKey))) {
    const n = normalizeTargetKey(targetKey);
    throw new PolicyForbiddenTargetError(n || targetKey.trim());
  }
}
