/**
 * Smoke-test public APIs after `docker compose up -d --build`.
 *
 * Waits for /api/health before running checks (backend may need 10–40s after container start).
 *
 * Usage:
 *   API_BASE=http://127.0.0.1:3001 node scripts/verify-api.mjs
 *   API_BASE=http://localhost:3001 WAIT_MS=120000 node scripts/verify-api.mjs
 */
const base = (process.env.API_BASE || 'http://127.0.0.1:3001').replace(/\/$/, '');
const maxWaitMs = parseInt(process.env.WAIT_MS || '90000', 10);
const scanTarget = (process.env.VERIFY_SCAN_TARGET || '').trim();
const scanMinFindings = parseInt(process.env.VERIFY_SCAN_MIN_FINDINGS || '1', 10);

async function fetchWithTimeout(url, ms) {
  const c = new AbortController();
  const id = setTimeout(() => c.abort(), ms);
  try {
    return await fetch(url, { signal: c.signal });
  } finally {
    clearTimeout(id);
  }
}

async function postJsonWithTimeout(url, body, ms) {
  const c = new AbortController();
  const id = setTimeout(() => c.abort(), ms);
  try {
    return await fetch(url, {
      method: 'POST',
      signal: c.signal,
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });
  } finally {
    clearTimeout(id);
  }
}

const paths = [
  ['/api/health', (j) => j.status === 'ok'],
  ['/api/ready', (j) => j.status === 'ready'],
  ['/api/assets', (j) => Array.isArray(j.assets)],
  ['/api/dashboard/summary', (j) => typeof j.approvedAssets === 'number'],
  ['/api/dashboard/overview?window=daily', (j) => j.selectedWindow === 'daily' && Array.isArray(j.sectionStatus)],
  ['/api/scenario-templates', (j) => Array.isArray(j.templates)],
  ['/api/campaign-scenarios', (j) => Array.isArray(j.scenarios)],
  ['/api/campaigns', (j) => Array.isArray(j.campaigns)],
  ['/api/campaigns/activity', (j) => Array.isArray(j.runs)],
  ['/api/runs', (j) => Array.isArray(j.runs)],
  ['/api/findings', (j) => Array.isArray(j.findings)],
  ['/api/evidence', (j) => Array.isArray(j)],
  ['/api/policy/allowed-target-keys', (j) => Array.isArray(j.keys)],
];

function formatFetchError(e) {
  const parts = [e?.message || String(e)];
  if (e?.cause) parts.push(`cause: ${e.cause.message || e.cause}`);
  return parts.join(' | ');
}

function isScanContractValid(result) {
  return (
    result &&
    typeof result === 'object' &&
    result.reconData &&
    typeof result.reconData === 'object' &&
    Array.isArray(result.findings) &&
    Array.isArray(result.moduleResults) &&
    result.scanSummary &&
    typeof result.scanSummary === 'object' &&
    result.executionMeta &&
    typeof result.executionMeta === 'object'
  );
}

async function waitForBackend() {
  const healthUrl = `${base}/api/health`;
  const start = Date.now();
  let attempt = 0;
  while (Date.now() - start < maxWaitMs) {
    attempt++;
    try {
      const res = await fetchWithTimeout(healthUrl, 5000);
      if (res.ok) {
        const j = await res.json();
        if (j.status === 'ok') {
          if (attempt > 1) {
            console.log(`Backend ready at ${base} (after ${attempt} attempt(s), ${Math.round((Date.now() - start) / 1000)}s)\n`);
          }
          return;
        }
      }
    } catch (e) {
      if (attempt === 1 || attempt % 10 === 0) {
        process.stdout.write(
          `\rWaiting for backend at ${base}... (${Math.round((Date.now() - start) / 1000)}s / ${Math.round(maxWaitMs / 1000)}s)`,
        );
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.error(`\n\nTimed out after ${maxWaitMs}ms — ${healthUrl} never returned OK.`);
  console.error('Check: docker compose ps   and   docker compose logs backend --tail 50');
  process.exit(1);
}

async function main() {
  await waitForBackend();

  let failed = 0;
  for (const [path, check] of paths) {
    const url = `${base}${path}`;
    try {
      const res = await fetchWithTimeout(url, 30000);
      const j = await res.json();
      if (!res.ok) {
        console.error(`FAIL ${path} HTTP ${res.status}`, j);
        failed++;
        continue;
      }
      if (!check(j)) {
        console.error(`FAIL ${path} unexpected body`, j);
        failed++;
        continue;
      }
      console.log(`OK ${path}`);
    } catch (e) {
      console.error(`FAIL ${path}`, formatFetchError(e));
      failed++;
    }
  }

  if (scanTarget) {
    try {
      const url = `${base}/api/scan/run`;
      const res = await postJsonWithTimeout(url, { target: scanTarget }, 120000);
      const j = await res.json();
      if (!res.ok) {
        console.error(`FAIL /api/scan/run HTTP ${res.status}`, j);
        failed++;
      } else if (!isScanContractValid(j)) {
        console.error('FAIL /api/scan/run invalid scan contract', j);
        failed++;
      } else if (j.findings.length < scanMinFindings) {
        console.error(
          `FAIL /api/scan/run expected at least ${scanMinFindings} findings for ${scanTarget}, got ${j.findings.length}`,
          j.scanSummary,
        );
        failed++;
      } else {
        console.log(
          `OK /api/scan/run target=${scanTarget} findings=${j.findings.length} modules=${j.moduleResults.length}`,
        );
      }
    } catch (e) {
      console.error('FAIL /api/scan/run', formatFetchError(e));
      failed++;
    }
  }

  if (failed) {
    console.error(`\n${failed} check(s) failed. Base URL: ${base}`);
    process.exit(1);
  }
  console.log('\nAll API checks passed.');
}

main();
