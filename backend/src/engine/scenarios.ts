import type { ExpectationSpec } from './expectation';

export type CampaignRequestBodyMode = 'json' | 'raw';

export interface CampaignScenarioRequestTemplate {
  id: string;
  label: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'HEAD' | 'PATCH';
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  bodyMode?: CampaignRequestBodyMode;
  repeatCount?: number;
  deliveryChannel: 'query' | 'body' | 'header' | 'mixed';
  rationale: string;
  requestTags?: string[];
  /** Structured expectation evaluated by the worker against runtime telemetry. */
  expected?: ExpectationSpec;
}

export interface CampaignScenarioDefinition {
  id: string;
  name: string;
  category: 'Injection' | 'API Abuse' | 'Identity & Session' | 'Header & Routing' | 'Automation & Bot';
  attackSurface: 'web' | 'api' | 'edge' | 'identity';
  severity: 'high' | 'medium' | 'low';
  summary: string;
  operatorGoal: string;
  currentSignals: string[];
  telemetryExpectations: string[];
  safetyNotes: string[];
  requests: CampaignScenarioRequestTemplate[];
}

const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
    }
  }
`.trim();

export const WAAP_SCENARIOS: CampaignScenarioDefinition[] = [
  {
    id: 'waap-sqli-01',
    name: 'SQL Injection Baseline',
    category: 'Injection',
    attackSurface: 'api',
    severity: 'high',
    summary: 'Baseline union/tautology-style request to validate SQLi signature coverage and operator telemetry.',
    operatorGoal: 'Measure whether common SQLi indicators are blocked, logged, or normalized before reaching the origin.',
    currentSignals: ['OWASP A03', 'query parameter abuse', 'database-oriented injection markers'],
    telemetryExpectations: [
      '403/406/4xx blocking or origin rejection',
      'Request-body and query-string preservation in evidence logs',
      'Clear scenario attribution in Campaign traces',
    ],
    safetyNotes: [
      'Fixed static payload only',
      'No adaptive tampering or payload mutation',
      'Approved-target execution only',
    ],
    requests: [
      {
        id: 'sqli-tautology',
        label: 'Tautology query-string probe',
        method: 'GET',
        path: "/api/users?query=1'%20OR%20'1'='1",
        deliveryChannel: 'query',
        rationale: 'Representative tautology-style probe for baseline SQL injection validation coverage.',
        requestTags: ['sqli', 'query-parameter', 'baseline'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'SQL injection markers should be blocked or rejected before reaching origin.',
        },
      },
      {
        id: 'sqli-union',
        label: 'Union-select style probe',
        method: 'GET',
        path: "/api/search?term='%20UNION%20SELECT%20NULL--",
        deliveryChannel: 'query',
        rationale: 'Union-select probe checks whether alternative SQLi markers are handled consistently.',
        requestTags: ['sqli', 'union-select', 'query-parameter'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Union-style SQLi markers should be filtered or rejected.',
        },
      },
    ],
  },
  {
    id: 'waap-xss-01',
    name: 'Cross Site Scripting (XSS)',
    category: 'Injection',
    attackSurface: 'web',
    severity: 'high',
    summary: 'Reflected XSS-style input to validate scriptable payload handling and response telemetry.',
    operatorGoal: 'Verify whether obvious reflective script payloads are blocked or sanitized consistently.',
    currentSignals: ['Reflected XSS', 'HTML/JS payload markers', 'unsafe output handling'],
    telemetryExpectations: [
      'Blocking or response sanitization',
      'Accurate request trace with preserved payload preview',
      'Operator-visible scenario naming',
    ],
    safetyNotes: ['Static string payload only', 'No DOM interaction', 'No browser automation'],
    requests: [
      {
        id: 'xss-reflected',
        label: 'Script-tag reflection probe',
        method: 'GET',
        path: '/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E',
        deliveryChannel: 'query',
        rationale: 'Classic reflected XSS marker used to test surface-level filtering and telemetry.',
        requestTags: ['xss', 'reflected', 'query'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Reflected script payloads should be blocked or sanitized.',
        },
      },
      {
        id: 'xss-svg',
        label: 'SVG/onload variant',
        method: 'GET',
        path: '/search?term=%3Csvg%2Fonload%3Dalert(1)%3E',
        deliveryChannel: 'query',
        rationale: 'Alternative XSS marker helps validate consistency across payload families.',
        requestTags: ['xss', 'svg', 'variant'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'SVG/onload XSS variants should be filtered.',
        },
      },
    ],
  },
  {
    id: 'waap-path-01',
    name: 'Path Traversal',
    category: 'Injection',
    attackSurface: 'api',
    severity: 'high',
    summary: 'Directory traversal markers to test path normalization, file access controls, and logging.',
    operatorGoal: 'Confirm traversal signatures are detected before filesystem-oriented behavior occurs.',
    currentSignals: ['LFI/path traversal', 'dot-dot-slash traversal', 'file parameter abuse'],
    telemetryExpectations: ['Blocked or rejected request', 'Clear file-path indicator in evidence'],
    safetyNotes: ['Static traversal markers only', 'No real file exfiltration logic'],
    requests: [
      {
        id: 'path-traversal',
        label: 'Unix path traversal probe',
        method: 'GET',
        path: '/api/files?file=../../../../etc/passwd',
        deliveryChannel: 'query',
        rationale: 'Common traversal marker to validate baseline path traversal filtering.',
        requestTags: ['path-traversal', 'lfi', 'filesystem'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Traversal markers should be rejected before filesystem access.',
        },
      },
    ],
  },
  {
    id: 'waap-cmdi-01',
    name: 'Command Injection Signature',
    category: 'Injection',
    attackSurface: 'api',
    severity: 'high',
    summary: 'Shell metacharacter probe for diagnostics-style endpoints and command-injection detection.',
    operatorGoal: 'Validate detection of shell metacharacters and command-execution signatures in request paths.',
    currentSignals: ['Command injection', 'shell metacharacters', 'diagnostic endpoint abuse'],
    telemetryExpectations: ['4xx or normalized rejection', 'Origin-independent request evidence'],
    safetyNotes: ['Static signature only', 'No adaptive chaining', 'No remote execution workflow'],
    requests: [
      {
        id: 'cmdi-query',
        label: 'Semicolon command-chain marker',
        method: 'GET',
        path: '/api/tools/ping?host=127.0.0.1%3Bid',
        deliveryChannel: 'query',
        rationale: 'Representative shell metacharacter pattern for command-injection signature coverage.',
        requestTags: ['command-injection', 'shell', 'query'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Shell metacharacters in query should be rejected.',
        },
      },
    ],
  },
  {
    id: 'waap-template-01',
    name: 'Template Injection Marker',
    category: 'Injection',
    attackSurface: 'api',
    severity: 'medium',
    summary: 'Server-side template injection marker to test payload handling in render-style inputs.',
    operatorGoal: 'Check whether server-side template expressions are recognized and logged on inbound requests.',
    currentSignals: ['SSTI', 'template rendering inputs', 'expression injection'],
    telemetryExpectations: ['Payload preview preserved', 'Blocked or safely rejected request'],
    safetyNotes: ['Static expression markers only', 'No gadget chaining'],
    requests: [
      {
        id: 'ssti-json',
        label: 'Template expression in JSON body',
        method: 'POST',
        path: '/api/render',
        headers: { 'Content-Type': 'application/json' },
        bodyMode: 'json',
        body: {
          template: '{{7*7}}',
          context: { invoiceId: 'operator-test' },
        },
        deliveryChannel: 'body',
        rationale: 'Bounded SSTI marker delivered through JSON body content.',
        requestTags: ['ssti', 'json-body', 'expression'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Template-injection markers should be rejected before render.',
        },
      },
    ],
  },
  {
    id: 'waap-ssrf-01',
    name: 'SSRF URL Fetch Probe',
    category: 'API Abuse',
    attackSurface: 'api',
    severity: 'high',
    summary: 'Bounded SSRF-style URL parameter probe using loopback-style targets rather than live external infrastructure.',
    operatorGoal: 'Measure whether server-side fetch semantics or proxy-style parameters are blocked or normalized.',
    currentSignals: ['SSRF', 'URL fetch abuse', 'proxy endpoint misuse'],
    telemetryExpectations: ['Blocked request or safe origin rejection', 'Clear URL parameter visibility in evidence'],
    safetyNotes: [
      'Uses loopback-style placeholder target',
      'No credential harvesting or external callback infrastructure',
      'Approved-target execution only',
    ],
    requests: [
      {
        id: 'ssrf-loopback',
        label: 'Loopback-style fetch parameter',
        method: 'GET',
        path: '/api/fetch?url=http%3A%2F%2F127.0.0.1%3A8080%2Fadmin',
        deliveryChannel: 'query',
        rationale: 'Representative SSRF signature using a bounded local-address target.',
        requestTags: ['ssrf', 'url-parameter', 'loopback'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'SSRF-style URL parameters should be rejected or normalized.',
        },
      },
    ],
  },
  {
    id: 'waap-open-redirect-01',
    name: 'Open Redirect Probe',
    category: 'API Abuse',
    attackSurface: 'web',
    severity: 'medium',
    summary: 'Redirect parameter probe to validate unsafe external destination handling.',
    operatorGoal: 'Observe whether open-redirect style destinations are rejected, normalized, or pass through the edge.',
    currentSignals: ['Open redirect', 'external destination abuse', 'navigation parameter handling'],
    telemetryExpectations: ['Blocked redirect parameter or origin-side rejection', 'Destination parameter retained in evidence'],
    safetyNotes: ['Static documentation-domain destination only', 'No dynamic redirect chaining'],
    requests: [
      {
        id: 'open-redirect-query',
        label: 'External destination redirect parameter',
        method: 'GET',
        path: '/redirect?next=https%3A%2F%2Fexample.com%2Fphish',
        deliveryChannel: 'query',
        rationale: 'Typical external-destination parameter used to validate open-redirect coverage.',
        requestTags: ['open-redirect', 'query', 'destination'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Redirect parameters with external destinations should be controlled.',
        },
      },
    ],
  },
  {
    id: 'waap-graphql-01',
    name: 'GraphQL Introspection Probe',
    category: 'API Abuse',
    attackSurface: 'api',
    severity: 'medium',
    summary: 'GraphQL introspection request to validate schema exposure controls and API telemetry.',
    operatorGoal: 'Check whether GraphQL schema discovery is permitted, blocked, or surfaced with useful operator evidence.',
    currentSignals: ['GraphQL introspection', 'schema discovery', 'API surface enumeration'],
    telemetryExpectations: ['Clear POST body capture', 'Consistent 2xx/4xx behavior and logging'],
    safetyNotes: ['Single bounded introspection query', 'No mutation or subscription execution'],
    requests: [
      {
        id: 'graphql-introspection',
        label: 'Schema introspection query',
        method: 'POST',
        path: '/graphql',
        headers: { 'Content-Type': 'application/json' },
        bodyMode: 'json',
        body: { query: INTROSPECTION_QUERY },
        deliveryChannel: 'body',
        rationale: 'Representative GraphQL introspection payload for schema exposure validation.',
        requestTags: ['graphql', 'introspection', 'api-surface'],
        expected: {
          verdicts: ['blocked', 'origin_rejected', 'allowed'],
          rationale: 'Introspection may be allowed or rejected; both outcomes need clear telemetry.',
        },
      },
    ],
  },
  {
    id: 'waap-api-schema-01',
    name: 'API Schema Validation (Malformed JSON)',
    category: 'API Abuse',
    attackSurface: 'api',
    severity: 'medium',
    summary: 'Actually malformed JSON body to validate parser and schema enforcement at the edge or origin.',
    operatorGoal: 'Confirm malformed payloads are preserved in evidence and handled consistently by upstream controls.',
    currentSignals: ['Malformed JSON', 'schema validation', 'parser hardening'],
    telemetryExpectations: ['Body preview retained verbatim', '4xx parsing rejection or controlled origin error'],
    safetyNotes: ['Single malformed body string', 'No oversized body or resource pressure'],
    requests: [
      {
        id: 'malformed-json',
        label: 'Broken JSON body',
        method: 'POST',
        path: '/api/login',
        headers: { 'Content-Type': 'application/json' },
        bodyMode: 'raw',
        body: '{"username":"demo","password":"broken"',
        deliveryChannel: 'body',
        rationale: 'Verifies schema enforcement with a truly malformed JSON document rather than valid serialized content.',
        requestTags: ['api-schema', 'malformed-json', 'parser'],
        expected: {
          verdicts: ['blocked', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Malformed bodies should be rejected by parser or schema validator.',
        },
      },
    ],
  },
  {
    id: 'waap-cors-01',
    name: 'Cross-Origin Policy Probe',
    category: 'API Abuse',
    attackSurface: 'edge',
    severity: 'medium',
    summary: 'Cross-origin preflight request to test permissive CORS behavior and visibility of preflight handling.',
    operatorGoal: 'Validate whether suspicious origins and requested headers are surfaced clearly in telemetry.',
    currentSignals: ['CORS misconfiguration', 'preflight handling', 'cross-origin trust'],
    telemetryExpectations: ['OPTIONS request visibility', 'Origin and requested headers preserved in evidence'],
    safetyNotes: ['Preflight only', 'No browser automation or cookie replay'],
    requests: [
      {
        id: 'cors-preflight',
        label: 'Suspicious origin preflight',
        method: 'OPTIONS',
        path: '/api/account',
        headers: {
          Origin: 'https://evil.example',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Authorization, Content-Type',
        },
        deliveryChannel: 'header',
        rationale: 'Preflight pattern used to test whether risky cross-origin intent is visible and controlled.',
        requestTags: ['cors', 'preflight', 'header-abuse'],
        expected: {
          verdicts: ['allowed', 'origin_rejected', 'blocked'],
          rationale: 'Preflight handling varies; visibility is what matters most.',
        },
      },
    ],
  },
  {
    id: 'waap-jwt-01',
    name: 'JWT / Auth Token Tampering',
    category: 'Identity & Session',
    attackSurface: 'identity',
    severity: 'high',
    summary: 'Tampered bearer token marker to test token parsing, auth telemetry, and invalid-token handling.',
    operatorGoal: 'Observe whether clearly untrusted or malformed bearer tokens are rejected with useful audit data.',
    currentSignals: ['JWT tampering', 'authentication abuse', 'invalid bearer token handling'],
    telemetryExpectations: ['401/403 or controlled rejection', 'Authorization header presence reflected in evidence'],
    safetyNotes: ['Static placeholder token only', 'No credential reuse', 'No brute-force logic'],
    requests: [
      {
        id: 'jwt-none-alg',
        label: 'Unsigned token marker',
        method: 'GET',
        path: '/api/account/profile',
        headers: {
          Authorization:
            'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJvcGVyYXRvci10ZXN0IiwiYWRtaW4iOnRydWV9.',
        },
        deliveryChannel: 'header',
        rationale: 'Representative invalid bearer token pattern to validate auth control telemetry.',
        requestTags: ['jwt', 'authorization-header', 'identity'],
        expected: {
          verdicts: ['blocked', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Invalid bearer tokens should be rejected with 401/403.',
        },
      },
    ],
  },
  {
    id: 'waap-method-override-01',
    name: 'HTTP Method Override Abuse',
    category: 'Header & Routing',
    attackSurface: 'edge',
    severity: 'medium',
    summary: 'Verb tunneling headers to validate method-override controls and routing-layer visibility.',
    operatorGoal: 'Check whether destructive verb intent hidden behind POST + override headers is surfaced or blocked.',
    currentSignals: ['Verb tunneling', 'method override', 'routing control confusion'],
    telemetryExpectations: ['Override headers preserved in logs', 'Controlled 4xx or origin handling'],
    safetyNotes: ['Single request', 'Static resource identifier', 'No stateful destructive workflow'],
    requests: [
      {
        id: 'method-override',
        label: 'DELETE override via POST',
        method: 'POST',
        path: '/api/files/1',
        headers: {
          'X-HTTP-Method-Override': 'DELETE',
          'Content-Type': 'application/json',
        },
        bodyMode: 'json',
        body: { operator: 'validation-campaign' },
        deliveryChannel: 'header',
        rationale: 'Representative verb-tunneling pattern for edge and origin method normalization checks.',
        requestTags: ['method-override', 'header-abuse', 'routing'],
        expected: {
          verdicts: ['blocked', 'origin_rejected'],
          rationale: 'Method override headers should not silently grant destructive verbs.',
        },
      },
    ],
  },
  {
    id: 'waap-host-header-01',
    name: 'Forwarded Host Manipulation',
    category: 'Header & Routing',
    attackSurface: 'edge',
    severity: 'medium',
    summary: 'Forwarded host and proto header manipulation for reverse-proxy and routing-layer validation.',
    operatorGoal: 'Validate whether upstream-trust headers are normalized, dropped, or surfaced in telemetry.',
    currentSignals: ['Host header abuse', 'proxy trust boundary', 'routing confusion'],
    telemetryExpectations: ['Suspicious forwarding headers preserved in evidence', '4xx or controlled origin response'],
    safetyNotes: ['Single bounded request', 'No DNS rebinding or dynamic host injection'],
    requests: [
      {
        id: 'forwarded-host',
        label: 'Forwarded host override',
        method: 'GET',
        path: '/',
        headers: {
          'X-Forwarded-Host': 'internal-admin.local',
          'X-Forwarded-Proto': 'http',
        },
        deliveryChannel: 'header',
        rationale: 'Tests how reverse-proxy trust headers are handled across the request path.',
        requestTags: ['host-header', 'forwarded-host', 'proxy'],
        expected: {
          verdicts: ['allowed', 'origin_rejected', 'blocked'],
          rationale: 'Forwarded host headers should be normalized; visibility is the goal.',
        },
      },
    ],
  },
  {
    id: 'waap-bot-01',
    name: 'Bot Volumetric Sweep',
    category: 'Automation & Bot',
    attackSurface: 'edge',
    severity: 'medium',
    summary: 'High-volume bot-like sweep to measure request-rate handling, telemetry quality, and worker resilience.',
    operatorGoal: 'Exercise volumetric defenses and confirm large request sets remain visible in Campaign traces.',
    currentSignals: ['Bot fingerprinting', 'automation heuristics', 'volumetric policy behavior'],
    telemetryExpectations: ['Consistent rate-oriented evidence rows', 'Queue and worker stability', 'Operator-visible batch outcomes'],
    safetyNotes: ['Fixed repeat count', 'Single path only', 'No distributed load behavior'],
    requests: [
      {
        id: 'bot-sweep',
        label: 'Bot user-agent volumetric sweep',
        method: 'GET',
        path: '/',
        headers: { 'User-Agent': 'python-urllib/3.8' },
        repeatCount: 40,
        deliveryChannel: 'header',
        rationale: 'Simulates repetitive bot-like request characteristics without broad crawling behavior.',
        requestTags: ['bot', 'volumetric', 'user-agent'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'allowed'],
          rationale: 'Volumetric bot traffic may trigger rate limiting, challenge, or pass-through.',
        },
      },
    ],
  },
  {
    id: 'waap-upload-01',
    name: 'Malicious file upload heuristics',
    category: 'API Abuse',
    attackSurface: 'api',
    severity: 'high',
    summary:
      'Probes upload endpoints with payloads that resemble executable scripts and double-extension filenames to test content inspection.',
    operatorGoal:
      'Validate that upload pipelines reject suspicious MIME types, double extensions, and embedded script content before reaching storage.',
    currentSignals: ['File-upload abuse', 'MIME spoofing', 'content-type mismatch'],
    telemetryExpectations: [
      'Block or sanitize on suspicious extensions',
      'MIME / Content-Type validation visible in evidence',
      'No silent acceptance of disguised executables',
    ],
    safetyNotes: [
      'Static, inert payload bytes only',
      'No real exploit payload is uploaded',
      'Approved-target execution only',
    ],
    requests: [
      {
        id: 'upload-double-extension',
        label: 'Double-extension PHP-shell-style upload probe',
        method: 'POST',
        path: '/api/upload',
        deliveryChannel: 'body',
        bodyMode: 'raw',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: 'GIF89a;<?php /* inert marker, not an exploit */ ?>',
        rationale:
          'Sends an inert byte sequence resembling a polyglot file to validate upload pipeline content inspection.',
        requestTags: ['upload', 'mime', 'polyglot'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          statusRanges: [{ from: 400, to: 499 }],
          rationale: 'Polyglot upload markers should be rejected by upload validators.',
        },
      },
    ],
  },
  {
    id: 'waap-mass-assign-01',
    name: 'Mass-assignment / privilege flag probe',
    category: 'API Abuse',
    attackSurface: 'api',
    severity: 'medium',
    summary:
      'Submits a benign object body with extra privileged-looking fields (isAdmin, role) to test whether servers strip unknown attributes.',
    operatorGoal:
      'Detect APIs that bind request bodies directly to entities without an allowlist of editable fields.',
    currentSignals: ['Mass-assignment', 'over-binding', 'unsafe deserialization markers'],
    telemetryExpectations: [
      '4xx rejection or silent stripping of unknown fields',
      'No 200 OK echoing back privileged fields as accepted',
      'Operator can see the body shape in evidence trace',
    ],
    safetyNotes: ['Inert body', 'No real account is modified', 'Approved-target execution only'],
    requests: [
      {
        id: 'mass-assign-isadmin',
        label: 'Privileged field injection in JSON body',
        method: 'POST',
        path: '/api/users/me',
        deliveryChannel: 'body',
        bodyMode: 'json',
        headers: { 'Content-Type': 'application/json' },
        body: { displayName: 'uasf-probe', isAdmin: true, role: 'superuser' },
        rationale:
          'Detects whether an API accepts arbitrary attributes such as isAdmin/role on a self-update endpoint.',
        requestTags: ['mass-assignment', 'authz', 'json-body'],
        expected: {
          verdicts: ['blocked', 'origin_rejected', 'allowed'],
          rationale:
            'Privileged fields should be stripped or rejected; allowed pass-through is acceptable only when the field is silently ignored.',
        },
      },
    ],
  },
  {
    id: 'waap-rate-limit-01',
    name: 'Login endpoint rate-limit probe',
    category: 'Identity & Session',
    attackSurface: 'identity',
    severity: 'medium',
    summary:
      'Repeated low-volume requests against an authentication endpoint to validate per-IP rate limiting and challenge surfaces.',
    operatorGoal:
      'Confirm that brute-force-style request patterns trigger rate limiting, lockout, or challenge — not silent allow.',
    currentSignals: ['Rate limiting', 'authentication abuse', 'edge throttling'],
    telemetryExpectations: [
      'Status 429 or challenge after a small burst',
      'No silent 200 OK on every attempt',
      'Operator-visible per-attempt verdicts',
    ],
    safetyNotes: ['Inert credentials', 'Bounded repeat count', 'Approved-target execution only'],
    requests: [
      {
        id: 'rate-login-burst',
        label: 'Authentication burst probe',
        method: 'POST',
        path: '/api/auth/login',
        deliveryChannel: 'body',
        bodyMode: 'json',
        headers: { 'Content-Type': 'application/json' },
        body: { username: 'uasf-test', password: 'invalid-uasf-probe' },
        repeatCount: 12,
        rationale:
          'Modest burst to a login endpoint to surface rate-limiting and challenge behavior on the identity surface.',
        requestTags: ['rate-limit', 'identity', 'burst'],
        expected: {
          verdicts: ['blocked', 'challenged', 'edge_mitigated', 'origin_rejected'],
          rationale:
            'Sustained authentication failures should trigger rate limiting, challenge, or origin rejection.',
        },
      },
    ],
  },
  {
    id: 'waap-error-leak-01',
    name: 'Error / stack-trace exposure probe',
    category: 'Header & Routing',
    attackSurface: 'web',
    severity: 'low',
    summary:
      'Issues malformed requests aimed at common framework endpoints to detect unhandled exceptions and verbose error pages.',
    operatorGoal:
      'Surface backends that leak stack traces, framework names, or environment details on bad input.',
    currentSignals: ['Verbose errors', 'stack-trace exposure', 'framework fingerprinting'],
    telemetryExpectations: [
      'Generic 4xx response with no stack trace',
      'No internal file paths or framework names in body',
      'Evidence captures response headers and snippet',
    ],
    safetyNotes: ['No exploit attempted', 'Inert malformed input', 'Approved-target execution only'],
    requests: [
      {
        id: 'error-malformed-content-type',
        label: 'Malformed Content-Type triggers framework error',
        method: 'POST',
        path: '/api/echo',
        deliveryChannel: 'header',
        headers: { 'Content-Type': 'application/json; charset=💥' },
        body: '{"trigger":"uasf-error-probe"}',
        bodyMode: 'raw',
        rationale:
          'Malformed Content-Type often elicits verbose framework errors that reveal stack traces or stack components.',
        requestTags: ['error', 'fingerprinting', 'header'],
        expected: {
          verdicts: ['blocked', 'origin_rejected', 'allowed'],
          rationale:
            'Either upstream rejection or a graceful 4xx without stack trace exposure is acceptable.',
        },
      },
    ],
  },
];

export function getCampaignScenarioById(scenarioId: string): CampaignScenarioDefinition | undefined {
  return WAAP_SCENARIOS.find((scenario) => scenario.id === scenarioId);
}

export function getCampaignScenarioJobCount(scenario: CampaignScenarioDefinition): number {
  return scenario.requests.reduce((sum, request) => sum + (request.repeatCount ?? 1), 0);
}

export function listCampaignScenarios(): Array<
  CampaignScenarioDefinition & {
    jobCount: number;
    requestCount: number;
  }
> {
  return WAAP_SCENARIOS.map((scenario) => ({
    ...scenario,
    jobCount: getCampaignScenarioJobCount(scenario),
    requestCount: scenario.requests.length,
  }));
}
