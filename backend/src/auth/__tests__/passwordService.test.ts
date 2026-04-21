import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  checkPasswordStrength,
  hashPassword,
  verifyPassword,
} from '../passwordService';

/**
 * Sanity tests for the password primitives. The bcrypt path is intentionally
 * exercised end-to-end because the hashing cost factor is the single most
 * security-critical knob in the auth stack.
 */

test('rejects passwords below 12 characters', () => {
  const r = checkPasswordStrength('Sh0rt!');
  assert.equal(r.ok, false);
});

test('accepts a 16+ character passphrase without composition rules', () => {
  const r = checkPasswordStrength('correct horse battery staple');
  assert.equal(r.ok, true);
});

test('requires lower + upper + digit when between 12 and 15 characters', () => {
  assert.equal(checkPasswordStrength('alllowercase').ok, false);
  assert.equal(checkPasswordStrength('ALLUPPERCASE').ok, false);
  assert.equal(checkPasswordStrength('NoDigits!!!!').ok, false);
  assert.equal(checkPasswordStrength('Mixed1Compose').ok, true);
});

test('rejects whitespace-only and overly-repetitive passwords', () => {
  assert.equal(checkPasswordStrength('             ').ok, false);
  assert.equal(checkPasswordStrength('aaaaaaaaaaaaaa').ok, false);
});

test('hashPassword + verifyPassword round-trip', async () => {
  const plain = 'CorrectHorseBattery42';
  const hash = await hashPassword(plain);
  assert.notEqual(hash, plain);
  assert.equal(await verifyPassword(plain, hash), true);
  assert.equal(await verifyPassword('wrong-password-1234', hash), false);
});

test('verifyPassword returns false for empty inputs without throwing', async () => {
  assert.equal(await verifyPassword('', ''), false);
  assert.equal(await verifyPassword('not-empty', ''), false);
  assert.equal(await verifyPassword('', 'not-a-real-hash'), false);
});
