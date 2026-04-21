import type { ScanFinding } from './scanTypes';

const HTTP_VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head']);

type Op = {
  description?: string;
  summary?: string;
  operationId?: string;
  tags?: string[];
};

async function fetchText(url: string, ms: number): Promise<{ ok: boolean; status: number; text: string }> {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try {
    const r = await fetch(url, {
      signal: c.signal,
      headers: {
        Accept: 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (compatible; AppSec-Assessment/1.0)',
      },
    });
    const text = await r.text();
    return { ok: r.ok, status: r.status, text };
  } finally {
    clearTimeout(t);
  }
}

/** Try common locations for OpenAPI 2/3 JSON (Nest, Spring, etc.). */
const SPEC_PATHS = ['/swagger-json', '/v2/api-docs', '/api/swagger-json', '/swagger/v1/swagger.json'];

function isOpenApiLike(obj: unknown): obj is Record<string, unknown> {
  if (!obj || typeof obj !== 'object') return false;
  const o = obj as Record<string, unknown>;
  return typeof o.paths === 'object' && o.paths !== null;
}

interface Classified {
  id: string;
  title: string;
  severity: ScanFinding['severity'];
  category: ScanFinding['category'];
  description: string;
  cwe?: string;
  evidenceLines: string[];
}

function classifyOperations(
  paths: Record<string, Record<string, unknown>>,
): Map<string, Classified> {
  const buckets = new Map<string, Classified>();

  function addBucket(
    key: string,
    partial: Omit<Classified, 'evidenceLines'> & { evidenceLines?: string[] },
    line: string,
  ) {
    const existing = buckets.get(key);
    if (existing) {
      if (!existing.evidenceLines.includes(line)) existing.evidenceLines.push(line);
      return;
    }
    buckets.set(key, {
      ...partial,
      evidenceLines: partial.evidenceLines ?? [line],
    });
  }

  for (const [pathKey, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    for (const [method, rawOp] of Object.entries(pathItem)) {
      const m = method.toLowerCase();
      if (!HTTP_VERBS.has(m)) continue;
      const op = rawOp as Op;
      const desc = `${pathKey} ${op.description ?? ''} ${op.summary ?? ''} ${op.operationId ?? ''}`.toLowerCase();
      const line = `${method.toUpperCase()} ${pathKey}`;

      if (pathKey.includes('/spawn') || /launches system command|getcommandresult/i.test(desc)) {
        addBucket(
          'os-command',
          {
            id: 'openapi-os-command',
            title: 'OS / shell command execution via API',
            severity: 'Critical',
            category: 'Web App',
            description:
              'OpenAPI documents an endpoint that executes system commands from user input — critical RCE/command-injection class exposure.',
            cwe: 'CWE-78: OS Command Injection',
          },
          line,
        );
      }

      if (pathKey.includes('/goto') || /redirects the user to the provided url/i.test(desc)) {
        addBucket(
          'open-redirect',
          {
            id: 'openapi-open-redirect',
            title: 'Unsafe redirect / forward (SSRF-prone surface)',
            severity: 'High',
            category: 'Web App',
            description:
              'Documented redirect endpoint accepting a URL parameter — open redirect and potential SSRF chaining.',
            cwe: 'CWE-601: URL Redirection to Untrusted Site',
          },
          line,
        );
      }

      if (
        pathKey.includes('/render') ||
        /template|dot\.|rendering/i.test(desc) ||
        /rendertemplate/i.test(op.operationId ?? '')
      ) {
        addBucket(
          'ssti',
          {
            id: 'openapi-ssti',
            title: 'Server-side template rendering with user-controlled input',
            severity: 'High',
            category: 'Web App',
            description:
              'Specification describes server-side template evaluation — typical SSTI / injection class risk.',
            cwe: 'CWE-1336: Template Injection',
          },
          line,
        );
      }

      if (pathKey.includes('/metadata') || /xml format|xxe|svg/i.test(desc)) {
        addBucket(
          'xxe',
          {
            id: 'openapi-xxe',
            title: 'XML processing / XXE-class exposure',
            severity: 'High',
            category: 'Web App',
            description:
              'Endpoint accepts XML/metadata in a way that often maps to XXE and unsafe XML parser usage.',
            cwe: 'CWE-611: Improper Restriction of XML External Entity Reference',
          },
          line,
        );
      }

      if (
        pathKey.includes('/process_numbers') ||
        /processing_expression|reduce\(/i.test(desc) ||
        /eval|expression/i.test(desc)
      ) {
        addBucket(
          'code-inject',
          {
            id: 'openapi-code-exec',
            title: 'User-influenced code / expression evaluation',
            severity: 'Critical',
            category: 'Web App',
            description:
              'API accepts expressions or script-like processing — arbitrary code execution class risk.',
            cwe: 'CWE-94: Improper Control of Generation of Code',
          },
          line,
        );
      }

      if (pathKey.includes('/secrets') || /server secrets|shhhh/i.test(desc)) {
        addBucket(
          'secrets',
          {
            id: 'openapi-secrets',
            title: 'Sensitive data / secrets exposure endpoint',
            severity: 'Critical',
            category: 'Misconfiguration',
            description: 'Specification advertises an endpoint returning secrets or sensitive configuration.',
            cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
          },
          line,
        );
      }

      if (pathKey.includes('/config') && /server configuration/i.test(desc)) {
        addBucket(
          'config-leak',
          {
            id: 'openapi-config',
            title: 'Server configuration disclosure',
            severity: 'High',
            category: 'Misconfiguration',
            description: 'Documented endpoint returns server/application configuration to clients.',
            cwe: 'CWE-497: Exposure of System Information to an Unauthorized Control Sphere',
          },
          line,
        );
      }

      if (/userinfo|\/users?\//i.test(pathKey) || /user info by email/i.test(desc)) {
        addBucket(
          'idor',
          {
            id: 'openapi-idor',
            title: 'User data / identifier-driven endpoints (IDOR class)',
            severity: 'Medium',
            category: 'Web App',
            description:
              'User or account identifiers in paths or parameters — review for IDOR and excessive data exposure.',
            cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
          },
          line,
        );
      }

      if (/\/file|\/upload|readfile/i.test(pathKey)) {
        addBucket(
          'file-surface',
          {
            id: 'openapi-file',
            title: 'File and cloud-storage integration endpoints',
            severity: 'High',
            category: 'Web App',
            description:
              'Documented file and object-storage oriented routes (local and cloud providers) — SSRF, credential misuse, and path abuse class risks.',
            cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
          },
          line,
        );
      }

      if (pathKey.includes('/api/auth/')) {
        addBucket(
          'auth-surface',
          {
            id: 'openapi-auth-lab',
            title: 'Authentication / JWT / session lab surface',
            severity: 'High',
            category: 'Web App',
            description:
              'Multiple auth and JWT validation flows documented — typical targets for algorithm confusion, weak keys, JKU/JWK/X5U abuse, CSRF flows, and OIDC misconfiguration.',
            cwe: 'CWE-287: Improper Authentication',
          },
          line,
        );
      }

      if (/\/users\//i.test(pathKey) || pathKey === '/api/users') {
        addBucket(
          'users-surface',
          {
            id: 'openapi-users',
            title: 'User directory / profile / LDAP endpoints',
            severity: 'High',
            category: 'Web App',
            description:
              'Rich user CRUD and search surface including LDAP and photo paths — IDOR, LDAP injection, and excessive exposure class issues.',
            cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
          },
          line,
        );
      }

      if (pathKey.includes('/email')) {
        addBucket(
          'email-surface',
          {
            id: 'openapi-email',
            title: 'Email send/read/delete endpoints',
            severity: 'Medium',
            category: 'Web App',
            description: 'Mailboxes and send flows exposed in API spec — spam, SSRF via SMTP, and data exposure risks.',
            cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
          },
          line,
        );
      }

      if (/\/chat|\/mcp|\/subscriptions|\/partners/i.test(pathKey)) {
        addBucket(
          'aux-surface',
          {
            id: 'openapi-aux',
            title: 'Partner, chat, MCP, or subscription integrations',
            severity: 'Medium',
            category: 'Web App',
            description:
              'Secondary business logic and integration endpoints — review for authz, injection, and prompt/tool abuse (e.g. MCP).',
            cwe: 'CWE-284: Improper Access Control',
          },
          line,
        );
      }
    }
  }

  return buckets;
}

function toFindings(classified: Map<string, Classified>, sourceUrl: string): ScanFinding[] {
  const out: ScanFinding[] = [];
  for (const c of classified.values()) {
    const evidence =
      `Source: ${sourceUrl}\n` +
      `Referenced operations:\n${c.evidenceLines.slice(0, 25).join('\n')}` +
      (c.evidenceLines.length > 25 ? `\n... (+${c.evidenceLines.length - 25} more)` : '');
    out.push({
      id: c.id,
      category: c.category,
      title: c.title,
      severity: c.severity,
      description: c.description,
      cwe: c.cwe,
      evidence,
      remediation:
        'Treat OpenAPI as attacker knowledge: restrict spec and UI to trusted operators, remediate or disable dangerous routes in production, enforce WAAP/API security policies.',
    });
  }
  return out;
}

/**
 * Fetches machine-readable API specs and derives evidence-backed findings (BrokenCrystals-style apps expose rich Swagger).
 */
export async function collectOpenApiFindings(originHttps: string): Promise<ScanFinding[]> {
  const base = originHttps.replace(/\/$/, '');
  const findings: ScanFinding[] = [];

  let spec: Record<string, unknown> | null = null;
  let specUrl = '';

  for (const p of SPEC_PATHS) {
    try {
      const { ok, text } = await fetchText(`${base}${p}`, 15000);
      if (!ok) continue;
      const json = JSON.parse(text);
      if (isOpenApiLike(json)) {
        spec = json;
        specUrl = `${base}${p}`;
        break;
      }
    } catch {
      /* try next */
    }
  }

  if (!spec || !spec.paths) {
    return findings;
  }

  const paths = spec.paths as Record<string, Record<string, unknown>>;
  const pathKeys = Object.keys(paths);
  let opCount = 0;
  for (const pk of pathKeys) {
    const item = paths[pk];
    if (!item) continue;
    for (const k of Object.keys(item)) {
      if (HTTP_VERBS.has(k.toLowerCase())) opCount++;
    }
  }

  findings.push({
    id: 'openapi-surface-summary',
    category: 'OSINT',
    title: `Machine-readable API surface documented (${opCount} operations, ${pathKeys.length} paths)`,
    severity: 'High',
    description:
      'A public OpenAPI/Swagger JSON document enumerates routes and behaviors — equivalent to handing attackers a structured map of the application (including intentionally vulnerable labs such as BrokenCrystals).',
    cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
    evidence: `Retrieved: ${specUrl}\nSample paths:\n${pathKeys.slice(0, 30).map((p) => `  ${p}`).join('\n')}${pathKeys.length > 30 ? `\n  ... (+${pathKeys.length - 30} paths)` : ''}`,
    remediation:
      'Disable or authenticate access to Swagger UI and raw JSON in production; scope WAAP/API policies to all documented routes.',
  });

  const classified = classifyOperations(paths);
  findings.push(...toFindings(classified, specUrl));

  try {
    const ui = await fetchText(`${base}/swagger`, 8000);
    if (ui.ok && /swagger-ui|SwaggerUIBundle/i.test(ui.text)) {
      findings.push({
        id: 'swagger-ui-html',
        category: 'Misconfiguration',
        title: 'Swagger UI HTML interface exposed',
        severity: 'Medium',
        description:
          'Interactive API documentation UI is reachable without indicating authentication — increases ease of exploitation for all listed operations.',
        cwe: 'CWE-425: Direct Request',
        evidence: `GET ${base}/swagger returned HTML containing Swagger UI assets.`,
        remediation: 'Protect with SSO/VPN or remove from external networks.',
      });
    }
  } catch {
    /* optional */
  }

  return findings;
}
