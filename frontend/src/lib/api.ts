/**
 * Browser-side API client.
 *
 * Responsibilities:
 *
 *   1. Resolves relative paths to the configured API base (`/api` by default
 *      or `VITE_API_URL` when proxying / running on a separate origin).
 *
 *   2. Always sends `credentials: 'include'` so the httpOnly refresh-token
 *      cookie flows on /auth/refresh and /auth/logout calls.
 *
 *   3. Attaches the in-memory access token as `Authorization: Bearer ...`
 *      whenever one is set via `setAccessToken()`. Kept in memory so
 *      JavaScript-context XSS still cannot exfiltrate the bearer to
 *      `localStorage` / `document.cookie`.
 *
 *   4. On 401 responses for protected calls, transparently invokes the
 *      registered refresh handler and replays the original request ONCE.
 *      The auth context registers that handler so the rest of the UI never
 *      has to think about token rotation.
 */

const apiBase = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '') ?? '/api';

function buildApiUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${apiBase}${normalizedPath}`;
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`API returned invalid JSON for ${response.url}`);
  }
}

export class ApiError extends Error {
  readonly status: number;
  readonly data: unknown;

  constructor(message: string, status: number, data: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

// ---------------------------------------------------------------------------
// Auth state injected by the auth context
// ---------------------------------------------------------------------------

let accessToken: string | null = null;
let onRefresh: (() => Promise<string | null>) | null = null;
let onUnauthenticated: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}
export function getAccessToken(): string | null {
  return accessToken;
}
export function registerRefreshHandler(handler: (() => Promise<string | null>) | null): void {
  onRefresh = handler;
}
export function registerUnauthenticatedHandler(handler: (() => void) | null): void {
  onUnauthenticated = handler;
}

function isAuthEndpoint(path: string): boolean {
  return path.startsWith('/auth/') || path.startsWith('/api/auth/');
}

async function performFetch(path: string, init: RequestInit | undefined, includeAuthHeader: boolean): Promise<Response> {
  const headers = new Headers(init?.headers ?? {});
  // Default JSON content-type for non-GET requests when a body is present.
  if (init?.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (includeAuthHeader && accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }
  return fetch(buildApiUrl(path), {
    ...init,
    headers,
    // Always include cookies so the refresh-cookie works on /auth/refresh.
    credentials: 'include',
  });
}

export async function apiFetchJson<T>(
  path: string,
  init?: RequestInit,
): Promise<{ data: T; response: Response }> {
  // Don't ever try to refresh a /auth/* call: those endpoints are how we'd
  // refresh in the first place, and the /login + /refresh + /logout calls
  // already speak the public contract.
  const isAuth = isAuthEndpoint(path);
  let response = await performFetch(path, init, !isAuth);

  if (response.status === 401 && !isAuth && onRefresh) {
    // One transparent retry: refresh the access token, then replay.
    let refreshed: string | null = null;
    try {
      refreshed = await onRefresh();
    } catch {
      refreshed = null;
    }
    if (refreshed) {
      response = await performFetch(path, init, true);
    } else if (onUnauthenticated) {
      // Cleanly notify the auth context so it can reset state + redirect.
      onUnauthenticated();
    }
  }

  const data = (await parseJsonBody(response)) as T;
  if (!response.ok) {
    const message =
      typeof data === 'object' &&
      data !== null &&
      'error' in data &&
      typeof (data as { error?: unknown }).error === 'string'
        ? (data as { error: string }).error
        : `HTTP ${response.status}`;
    throw new ApiError(message, response.status, data);
  }
  return { data, response };
}

// ---------------------------------------------------------------------------
// Signed download helpers
// ---------------------------------------------------------------------------

/**
 * Returns a fully-qualified, browser-openable URL for an authenticated GET
 * download endpoint (HTML/PDF reports etc.).  Uses `POST /downloads/sign`
 * to mint a short-lived signed token bound to the path so the browser can
 * navigate to it directly without `Authorization` headers — eliminating
 * the raw `AUTH_REQUIRED` JSON tab failure when operators click View/PDF
 * on a report row.
 *
 * `path` MUST be a backend-allowlisted absolute API path (e.g.
 * `/api/reports/<id>/pdf`); the server refuses to sign anything else.
 */
export async function buildSignedDownloadUrl(path: string): Promise<string> {
  const { data } = await apiFetchJson<{ url: string }>('/downloads/sign', {
    method: 'POST',
    body: JSON.stringify({ path }),
  });
  // The backend always emits an absolute API path beginning with `/api/`
  // (e.g. `/api/reports/<id>/pdf?dlt=...`).  `buildApiUrl` is designed to
  // prepend `apiBase` to RELATIVE paths, so passing an already-`/api/`-
  // prefixed string would double up to `/api/api/...` (broken — produces
  // an `AUTH_REQUIRED` 404 in the browser tab).  Strip the leading `/api`
  // first so the URL ends up correctly anchored at the configured base
  // whether that's the `/api` proxy or a fully-qualified backend origin.
  const relative = data.url.startsWith('/api/') ? data.url.slice(4) : data.url;
  return buildApiUrl(relative);
}

/**
 * Open an authenticated download endpoint via a signed download URL.
 *
 * Returns `null` on success or a human-readable error string the
 * caller can render in their UI on failure (no `alert(...)` popups).
 *
 * Why this is implemented the way it is:
 *
 *   - Minting the signed URL is async, so calling `window.open()`
 *     *after* the await loses the user-gesture flag and the browser
 *     silently blocks the tab.  We avoid that by SYNCHRONOUSLY opening
 *     a placeholder window inside the click handler and navigating it
 *     to the signed URL once the token is ready.
 *
 *   - We deliberately open with NO `noopener` flag.  Per spec
 *     `window.open(..., 'noopener')` returns `null`, which would leave
 *     us with no handle to redirect — exactly the bug that produced
 *     the "tab opens as about:blank" symptom.  We immediately neuter
 *     the opener relationship after we have the handle (`opener=null`)
 *     so the new tab cannot navigate us.
 *
 *   - We navigate the placeholder to the signed backend URL directly
 *     (instead of `fetch`-ing into a Blob first).  The backend serves
 *     PDFs with `Content-Type: application/pdf` and `Content-Disposition:
 *     inline`, so the browser renders the document natively in its
 *     built-in viewer.  This is far more reliable than blob-URL
 *     navigation in a popup, which Chrome/Firefox sometimes refuse to
 *     render as a PDF when the opener wrote any HTML into the window.
 *
 *   - If the popup is blocked outright (corporate browser, OS-level
 *     content blocker), we fall back to a synthetic `<a target="_blank">`
 *     click.  Anchor-initiated navigations are never popup-blocked.
 */
export async function openSignedDownload(
  path: string,
  opts: { expectMime?: 'application/pdf' | 'text/html'; filename?: string } = {},
): Promise<string | null> {
  const isHtml = opts.expectMime === 'text/html';
  const filename =
    opts.filename ??
    (opts.expectMime === 'application/pdf'
      ? 'report.pdf'
      : isHtml
        ? 'report.html'
        : 'report');

  // Explicit-download path — when the caller appends `?download=1`,
  // the backend responds with `Content-Disposition: attachment`.
  // Opening a placeholder window for that case produces an orphan
  // "Loading report…" tab, because the browser cancels the navigation
  // and triggers a save dialog instead of rendering anything.  Use a
  // pure anchor click in that scenario — no popup, no orphan.
  const wantsForcedDownload = /[?&]download=1(?:&|$)/.test(path);
  if (wantsForcedDownload) {
    try {
      const signedUrl = await buildSignedDownloadUrl(path);
      const a = document.createElement('a');
      a.href = signedUrl;
      a.rel = 'noopener noreferrer';
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : 'Failed to open download.';
    }
  }

  // Preview path — the browser renders the document inline in a new
  // tab.  Step 1: open the placeholder *immediately*, while the click
  // event is still active.  IMPORTANT: do not pass 'noopener' here —
  // that would force `window.open` to return `null` and we'd have no
  // handle to redirect.
  const placeholder = window.open('about:blank', '_blank');

  if (placeholder) {
    // Severs the opener relationship so the popup can't navigate us.
    try {
      placeholder.opener = null;
    } catch {
      /* ignore */
    }
    // Render a small "Loading report…" splash so the tab is not just
    // a blank page while the signed URL is being minted.
    try {
      placeholder.document.open();
      placeholder.document.write(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
          '<title>Loading report…</title>' +
          '<style>' +
          'html,body{margin:0;height:100%;background:#0f1115;color:#e2e8f0;' +
          'font-family:system-ui,-apple-system,Segoe UI,sans-serif;' +
          'display:flex;align-items:center;justify-content:center;flex-direction:column;gap:18px}' +
          '.spin{width:42px;height:42px;border-radius:50%;' +
          'border:3px solid rgba(142,81,223,0.25);border-top-color:#8e51df;' +
          'animation:s 0.9s linear infinite}' +
          '@keyframes s{to{transform:rotate(360deg)}}' +
          'p{margin:0;font-size:14px;color:#cbd5e1}' +
          'small{color:#94a3b8;font-size:12px}' +
          '</style></head><body>' +
          '<div class="spin"></div>' +
          '<p>Preparing report…</p>' +
          '<small>This tab will refresh automatically once the document is ready.</small>' +
          '</body></html>',
      );
      placeholder.document.close();
    } catch {
      /* document.write blocked — placeholder simply stays blank */
    }
  }

  const showErrorInPlaceholder = (message: string): void => {
    if (!placeholder || placeholder.closed) return;
    try {
      placeholder.document.open();
      placeholder.document.write(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
          '<title>Report error</title>' +
          '<style>html,body{margin:0;height:100%;background:#0f1115;color:#e2e8f0;' +
          'font-family:system-ui,-apple-system,Segoe UI,sans-serif;' +
          'display:flex;align-items:center;justify-content:center;padding:32px}' +
          '.box{max-width:520px;border:1px solid #2d333b;border-radius:12px;' +
          'background:#15181e;padding:24px;text-align:center}' +
          'h1{margin:0 0 12px;font-size:18px;color:#fda4af}' +
          'p{margin:0;color:#cbd5e1;font-size:14px;line-height:1.5}</style>' +
          '</head><body><div class="box">' +
          '<h1>Could not open report</h1><p>' +
          escapeHtml(message) +
          '</p></div></body></html>',
      );
      placeholder.document.close();
    } catch {
      try {
        placeholder.close();
      } catch {
        /* ignore */
      }
    }
  };

  try {
    const signedUrl = await buildSignedDownloadUrl(path);

    // Step 2: navigate the pre-opened placeholder directly to the
    //         signed backend URL.  The browser handles MIME / inline
    //         PDF rendering itself.
    if (placeholder && !placeholder.closed) {
      try {
        placeholder.location.replace(signedUrl);
        return null;
      } catch {
        /* fall through to anchor-click fallback */
      }
    }

    // Step 3: fallback — anchor click.  Never popup-blocked.
    const a = document.createElement('a');
    a.href = signedUrl;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    if (path.includes('download=1')) a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    return null;
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Failed to open download.';
    showErrorInPlaceholder(message);
    return message;
  }
}

/** Minimal HTML escape for messages we render into a popup window. */
function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
