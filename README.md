# UASF — Universal Attack Simulation Framework

Vendor-agnostic, validation-first security validation, exposure management, and evidence-correlation platform. UASF orchestrates **policy-bound** validation campaigns and application assessments against **approved assets only**, with normalized telemetry that can correlate against multiple edge, WAAP, WAF, API gateway, CDN, and identity environments rather than being locked to a single vendor.

> The platform began as an AppTrana-inspired internal console and is being evolved into a generalized framework. Existing AppTrana-specific labels still resolve for backward compatibility.

## Verdict and expectation model

UASF avoids the historical "HTTP 200 means allowed" mistake. Every recorded request is classified by the UASF Verdict Engine into one of:

`blocked · challenged · edge_mitigated · origin_rejected · allowed · network_error · ambiguous`

Each scenario request also carries a structured expectation. The Expectation Evaluator compares the observed verdict against the declared expectation and surfaces one of:

`matched · partially_matched · mismatched · ambiguous`

This means a request that gets a Cloudflare interstitial or a managed-WAF challenge will not be silently rendered as "completed/allowed"; the mismatch is visible in operator traces.

**Reference web target:** `juiceshopnew.testapptrana.net`  
**AppTrana console label (metadata, not a socket host):** `juiceshopnew.testapptrana.net_API`

## Quick start

```bash
docker compose up -d --build
```

### URLs and ports

| Service | URL / endpoint |
|--------|------------------|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:3001/api (Compose frontend proxies `/api` to the backend) |
| Health | http://localhost:3001/api/health |
| Readiness | http://localhost:3001/api/ready |
| PostgreSQL | `localhost:5432` (credentials in `docker-compose.yml`) |
| Redis | `localhost:6379` |

The backend listens on **3000** inside the network; the host maps **3001→3000**.

### API smoke test

The backend may need **10–90 seconds** after the container starts (`ts-node` boot, DB, seed). The verify script **waits** for `/api/health` before asserting endpoints.

```bash
cd backend && API_BASE=http://127.0.0.1:3001 npm run verify
```

If you still see connection errors, wait until `docker compose ps` shows the backend as **healthy**, then re-run. You can also start the stack with `docker compose up -d --wait` (Compose v2+) so services wait on healthchecks.

On machines where `127.0.0.1` behaves oddly with Docker, try `API_BASE=http://localhost:3001`.

## Policy model (strict)

1. **Deployment allowlist** — `ALLOWED_TARGETS` lists normalized hostnames and AppTrana-style labels. URLs pasted in the UI are normalized to hostnames before checks.
2. **Asset registry** — When `REQUIRE_REGISTERED_ASSET=true` (default), executable workflows (WAAP campaigns, application assessment scan) also require a matching **approved** row in the asset registry (`targets` table). Labels are not used as network destinations; resolution maps labels to the asset’s hostname.
3. **Concurrency** — `SAFETY_MAX_CONCURRENCY` caps worker parallelism.

## Architecture

- **Frontend:** React, Vite, TypeScript, Tailwind CSS, Recharts  
- **Backend:** Node.js, Fastify, TypeScript, service/repository-style helpers  
- **Queue:** BullMQ (Redis)  
- **Database:** PostgreSQL (TypeORM; `synchronize` in development — use migrations for production)

## Implemented modules (current)

| Area | Status |
|------|--------|
| Approved asset registry (extended metadata, types, AppTrana alias field) | Implemented |
| Scenario template catalog (seeded) | Implemented |
| Campaigns & assessment runs (seeded) | Implemented |
| Security findings & discovered services (seeded) | Implemented |
| Dashboard summary API + WAAP evidence timeline | Implemented |
| WAAP validation campaigns + queue worker | Implemented |
| Application assessment (controlled scan path) | Implemented |
| Discovery, IOC/CTI, SAST, dependency, malware domains | Scaffolded UI + Phase 3 backend |

## Demonstration flow

1. Open http://localhost:5173 — review **Dashboard** (platform KPIs + WAAP traffic).  
2. **Targets** — approved registry rows and exposure row counts.  
3. **Scenario Catalog** — policy-bound templates.  
4. **Campaigns** — run a WAAP scenario against an **approved** hostname or label.  
5. **Evidence & Logs** — validation telemetry.  
6. Correlate in the AppTrana portal as needed.

## Roadmap

- **Phase 2:** Discovery ingestion adapters, richer run orchestration, evidence/report exports, repository layer hardening.  
- **Phase 3:** Code security, dependency/SBOM, IOC enrichment, malware/file risk, integration adapters (including optional UASF-style sources), PDF/report pipeline, dashboard depth.

## Production deployment

### Architectural reality

Only the **frontend** (Vite SPA under `frontend/`) is a natural fit for Vercel. The backend is **not** deployable to Vercel serverless functions because it:

- Is a long-running Fastify server with a pooled TypeORM connection to PostgreSQL.
- Runs a **BullMQ worker** backed by Redis (persistent process required).
- Schedules long-lived `setInterval` ingestion jobs (dependency CVEs, IOC feeds, news).
- Shells out to `nmap` via `execFile` for service fingerprinting.
- Streams multi-page PDF reports via `pdfkit` that can run well beyond serverless wall-clock limits.
- Runs assessment scans that routinely take 60–120 seconds.

The correct production topology is **split deployment**:

```
           +------------------+          +--------------------------+
  Browser  |  Vercel (SPA)    |  /api/*  |  Your backend host       |
  ─────── ▶| frontend/dist    |────────▶ |  (Fly.io / Render /      |
           |  vercel.json     |  rewrite |  Railway / Docker on VM) |
           +------------------+          |  + PostgreSQL + Redis    |
                                         +--------------------------+
```

### Deploying the frontend on Vercel

On the Vercel "Import Project" screen you must explicitly tell Vercel this is a single Vite app, **not** a multi-service monorepo. Vercel's "Services" auto-preset would otherwise try to build `backend/` too, which is not serverless-compatible (see "Architectural reality" above).

1. Import the repository into Vercel.
2. In the import UI:
   - **Application Preset** — change from `Services` to **`Vite`**.
   - **Root Directory** — set to **`frontend`**.
   - Leave build/install commands at their Vercel-provided defaults (the `frontend/vercel.json` in the repo handles the rest).
3. Choose **one** of the two API-routing modes:

   **Mode A — Same-origin via Vercel rewrite (recommended).** Edit `frontend/vercel.json` and replace the placeholder `BACKEND_PUBLIC_HOST_REPLACE_ME` in the `/api/:path*` rewrite destination with your backend's public hostname (e.g. `api.uasf.example.com`). Leave `VITE_API_URL` **unset** in Vercel. The browser sees same-origin traffic, so no CORS or cross-site-cookie gymnastics are needed.

   **Mode B — Direct cross-origin to the backend.** Remove (or leave un-edited) the rewrite and instead set the Vercel build env var `VITE_API_URL=https://api.example.com/api`. Then on the backend set `FRONTEND_ORIGIN=https://<your-vercel-domain>` (comma-separated list is supported for multiple origins) and `COOKIE_SECURE=true`.

4. Deploy. Vercel will run `npm ci && npm run build` inside `frontend/` and publish `frontend/dist`. The root-level `.vercelignore` excludes `backend/`, `shared/`, `docker-compose.yml`, and `.env*` from the deployment regardless of which Root Directory you pick.

### Deploying the backend

Deploy `backend/` to any host that can run a long-lived Node process with outbound network and access to Postgres + Redis. Example hosts: Fly.io, Render, Railway, Docker on any VM.

Minimum required env vars (full list in `backend/.env.example`):

| Variable                        | Required | Notes                                                                |
|---------------------------------|----------|----------------------------------------------------------------------|
| `NODE_ENV`                      | yes      | `production`                                                         |
| `DATABASE_URL`                  | yes      | Postgres connection URL                                              |
| `REDIS_HOST`, `REDIS_PORT`      | yes      | BullMQ needs Redis                                                   |
| `ALLOWED_TARGETS`               | yes      | Comma-separated allowlist of hostnames/labels                        |
| `FRONTEND_ORIGIN`               | yes      | Web origin(s); comma-separated list accepted (prod + preview URLs)   |
| `JWT_ACCESS_SECRET`             | yes      | 48 bytes hex — pin so tokens survive restarts                        |
| `REFRESH_TOKEN_PEPPER`          | yes      | 32 bytes hex — pepper for refresh-token hashes                       |
| `COOKIE_SECURE`                 | yes      | `true` in production (auto-upgrades refresh cookie to `SameSite=None`) |
| `COOKIE_SAMESITE`               | no       | `none` / `lax` / `strict` — override the automatic value             |
| `AUTH_REQUIRED`                 | no       | `true` (default). Never set to `false` in production.                |
| `REQUIRE_REGISTERED_ASSET`      | no       | `true` (default). Gates executable scans on the asset registry.      |
| `SAFETY_MAX_CONCURRENCY`        | no       | Cap worker parallelism                                               |
| `SAFETY_MAX_RPS`                | no       | Cap outbound request rate                                            |
| `DB_SYNCHRONIZE`                | no       | Leave unset / `false` in production; use TypeORM migrations          |
| `VIRUSTOTAL_API_KEY`            | no       | Optional intel provider                                              |
| `ABUSE_CH_AUTH_KEY`             | no       | Optional intel provider                                              |

The backend will **refuse to boot** in production if `FRONTEND_ORIGIN`, `DATABASE_URL`, `ALLOWED_TARGETS`, or any other flagged-required variable is missing. That is intentional — fail-fast beats silently booting a broken auth surface.

### Auth-aware reports (HTML/PDF)

Report preview/download URLs are **not opened as raw authenticated API calls**. The frontend mints a short-lived HMAC-signed download token via `POST /api/downloads/sign`, then navigates the browser tab to e.g. `/api/reports/<id>/pdf?dlt=<token>`. The `authPlugin` recognises the `dlt` query param and synthesises the request identity from the signed claims for a single read-only request.

Practical implications for deployment:
- **Signed download URLs are bearer-in-URL and work cross-origin.** They do not need the refresh cookie, so Mode A and Mode B both work identically for report previews.
- If an operator opens a protected URL directly (e.g. pastes an API link into a new tab **without** a valid `dlt` token), the backend now returns a **friendly HTML page** prompting them to sign in, not a raw `AUTH_REQUIRED` JSON body.

### Local development

The `docker compose up -d --build` flow in "Quick start" above still works and is the fastest path for local iteration. It wires up Postgres, Redis, the backend, and the Vite dev server with the correct internal networking.
