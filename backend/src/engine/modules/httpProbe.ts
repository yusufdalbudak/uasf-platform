import { assertSafeScanHostname } from './utils';

export interface HttpProbeResponse {
  url: string;
  status: number;
  ok: boolean;
  redirected: boolean;
  headers: Record<string, string>;
  body: string;
}

interface HttpProbeOptions {
  method?: 'GET' | 'HEAD';
  timeoutMs?: number;
  readBody?: boolean;
  headers?: Record<string, string>;
}

const DEFAULT_FETCH_HEADERS = {
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'User-Agent': 'Mozilla/5.0 (compatible; AppTrana Validation Platform/1.0)',
};

function headersToObject(headers: Headers): Record<string, string> {
  const normalized: Record<string, string> = {};
  headers.forEach((value, key) => {
    normalized[key.toLowerCase()] = value;
  });
  return normalized;
}

export async function probeUrl(
  url: string,
  options: HttpProbeOptions = {},
): Promise<HttpProbeResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 10000);

  try {
    const response = await fetch(url, {
      method: options.method ?? 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        ...DEFAULT_FETCH_HEADERS,
        ...(options.headers ?? {}),
      },
    });

    const body =
      options.readBody === false || (options.method ?? 'GET') === 'HEAD'
        ? ''
        : await response.text();

    return {
      url: response.url,
      status: response.status,
      ok: response.ok,
      redirected: response.redirected,
      headers: headersToObject(response.headers),
      body,
    };
  } finally {
    clearTimeout(timeout);
  }
}

export async function probePreferredOrigin(
  hostname: string,
  options: HttpProbeOptions = {},
): Promise<HttpProbeResponse> {
  const safeHostname = assertSafeScanHostname(hostname);
  let lastError: unknown;

  for (const scheme of ['https', 'http'] as const) {
    try {
      return await probeUrl(`${scheme}://${safeHostname}/`, options);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError ?? new Error(`Unable to probe origin for ${safeHostname}`);
}

export async function probeRelativeUrl(
  baseUrl: string,
  path: string,
  options: HttpProbeOptions = {},
): Promise<HttpProbeResponse> {
  const targetUrl = new URL(path, baseUrl).toString();
  return probeUrl(targetUrl, options);
}

export async function probeEndpoint(baseUrl: string, path: string, timeoutMs = 8000): Promise<HttpProbeResponse> {
  try {
    const headResponse = await probeRelativeUrl(baseUrl, path, {
      method: 'HEAD',
      timeoutMs,
      readBody: false,
    });
    if (headResponse.status !== 405 && headResponse.status !== 501) {
      return headResponse;
    }
  } catch {
    // Fall back to GET below.
  }

  return probeRelativeUrl(baseUrl, path, { method: 'GET', timeoutMs, readBody: false });
}
