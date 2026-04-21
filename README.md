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
