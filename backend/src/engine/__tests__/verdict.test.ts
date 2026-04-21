/**
 * UASF Verdict Engine tests.
 *
 * Runs under the Node built-in test runner so no extra dependency is required:
 *   npx ts-node --transpile-only --test src/engine/__tests__/verdict.test.ts
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyResponseVerdict } from '../verdict';

test('network failures classify as network_error', () => {
  const result = classifyResponseVerdict({
    status: -1,
    headers: null,
    bodyPreview: null,
    errorMessage: 'fetch failed',
  });
  assert.equal(result.verdict, 'network_error');
  assert.ok(result.confidence >= 90);
  assert.ok(result.signals.some((signal) => signal.name === 'transport:network-error'));
});

test('plain HTTP 200 with no mitigation indicators is allowed', () => {
  const result = classifyResponseVerdict({
    status: 200,
    headers: { 'content-type': 'text/html' },
    bodyPreview: '<html><body>Hello</body></html>',
  });
  assert.equal(result.verdict, 'allowed');
});

test('HTTP 200 with Cloudflare challenge body is challenged, not allowed', () => {
  const result = classifyResponseVerdict({
    status: 200,
    headers: { server: 'cloudflare', 'cf-ray': 'abc' },
    bodyPreview: '<title>Attention Required! | Cloudflare</title><div class="cf-error-details">Ray ID</div>',
  });
  assert.equal(result.verdict, 'challenged');
  assert.ok(result.signals.some((signal) => signal.name.startsWith('challenge:')));
});

test('HTTP 403 is classified as blocked', () => {
  const result = classifyResponseVerdict({
    status: 403,
    headers: { server: 'nginx' },
    bodyPreview: 'Forbidden',
  });
  assert.equal(result.verdict, 'blocked');
});

test('HTTP 500 is classified as origin_rejected', () => {
  const result = classifyResponseVerdict({
    status: 500,
    headers: { server: 'nginx' },
    bodyPreview: 'Internal Server Error',
  });
  assert.equal(result.verdict, 'origin_rejected');
});

test('an explicit WAF mitigation header trumps a 200 status', () => {
  const result = classifyResponseVerdict({
    status: 200,
    headers: { server: 'nginx', 'x-apptrana': 'blocked' },
    bodyPreview: '',
  });
  assert.equal(result.verdict, 'blocked');
});

test('Cloudflare cf-mitigated challenge header is classified as challenged', () => {
  const result = classifyResponseVerdict({
    status: 403,
    headers: { 'cf-mitigated': 'challenge', server: 'cloudflare' },
    bodyPreview: '',
  });
  assert.equal(result.verdict, 'challenged');
});

test('Akamai-only edge headers are surfaced as edge_mitigated when status is 200', () => {
  const result = classifyResponseVerdict({
    status: 200,
    headers: { server: 'AkamaiGHost' },
    bodyPreview: '<html><body>Hello</body></html>',
  });
  assert.equal(result.verdict, 'edge_mitigated');
});
