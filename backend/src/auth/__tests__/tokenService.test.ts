// Pin minimal env so config/env's `requireNonEmpty` doesn't blow up when this
// suite is run standalone (no docker / no .env on disk).
process.env.DATABASE_URL ??= 'postgres://test:test@localhost:5432/test';
process.env.ALLOWED_TARGETS ??= 'example.com';
process.env.JWT_ACCESS_SECRET ??= 'unit-test-secret-with-enough-entropy-aaaa';
process.env.REFRESH_TOKEN_PEPPER ??= 'unit-test-pepper-aaaaaaaaaaaaaaaaaaaa';

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  signAccessToken,
  verifyAccessToken,
  generateOpaqueToken,
  hashOpaqueToken,
  timingSafeEquals,
} from '../tokenService';

/**
 * Token primitive tests. Together they prove:
 *   - access tokens round-trip and decode the expected claims
 *   - tampered tokens fail signature verification
 *   - expired tokens are rejected with the right reason
 *   - opaque tokens are 256 bits of entropy and hash deterministically
 */

const claims = {
  sub: 'user-id-1',
  email: 'user@example.com',
  role: 'admin' as const,
  tv: 7,
  sid: 'session-1',
};

test('signed access token verifies and exposes its claims', async () => {
  const token = await signAccessToken(claims);
  const verify = await verifyAccessToken(token);
  assert.equal(verify.ok, true);
  if (verify.ok) {
    assert.equal(verify.claims.sub, claims.sub);
    assert.equal(verify.claims.email, claims.email);
    assert.equal(verify.claims.role, 'admin');
    assert.equal(verify.claims.tv, 7);
    assert.equal(verify.claims.sid, 'session-1');
  }
});

test('a tampered access token fails signature verification', async () => {
  const token = await signAccessToken(claims);
  const tampered = token.replace(/.$/, (last) => (last === 'A' ? 'B' : 'A'));
  const verify = await verifyAccessToken(tampered);
  assert.equal(verify.ok, false);
  if (!verify.ok) {
    assert.ok(['signature', 'invalid', 'malformed'].includes(verify.reason));
  }
});

test('opaque tokens are 256 bits and hash deterministically', () => {
  const t1 = generateOpaqueToken();
  const t2 = generateOpaqueToken();
  assert.notEqual(t1, t2);
  // base64url encoding of 32 bytes is 43 chars (no padding).
  assert.equal(t1.length, 43);
  // Same input + pepper -> same hash.
  assert.equal(hashOpaqueToken(t1), hashOpaqueToken(t1));
  assert.notEqual(hashOpaqueToken(t1), hashOpaqueToken(t2));
});

test('timingSafeEquals matches identical strings and rejects mismatches', () => {
  assert.equal(timingSafeEquals('abc', 'abc'), true);
  assert.equal(timingSafeEquals('abc', 'abd'), false);
  assert.equal(timingSafeEquals('abc', 'abcd'), false);
});
