import 'reflect-metadata';
import './config/env';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import { setupRoutes } from './api/routes';
import { setupAuthRoutes } from './api/authRoutes';
import { setupTechIntelRoutes } from './api/techIntelRoutes';
import { setupEasmRoutes } from './api/easmRoutes';
import { setupNewsRoutes } from './api/newsRoutes';
import { setupDownloadRoutes } from './api/downloadRoutes';
import { authPlugin } from './auth/authPlugin';
import { preHandlerSafetyGuard } from './safety/guard';
import { initDB } from './db/connection';
import { seedDatabase } from './db/seed';
import { bootstrapAdminUser } from './auth/bootstrapAdmin';
import { initWorker } from './engine/worker';
import { env } from './config/env';
import { startDependencyFeedSchedule } from './services/dependencyFeedService';
import { startIocFeedSchedule } from './services/iocFeedService';
import {
  bootstrapNewsSources,
  startNewsIngestionSchedule,
} from './services/news/newsService';

const server = Fastify({ logger: true, trustProxy: true });

async function main() {
  try {
    // CORS is restricted to the configured frontend origin and allows
    // credentials so the refresh-token cookie flows correctly. We do NOT
    // accept arbitrary origins because the API serves an auth-cookie that
    // must not be exfiltrated by other sites.
    // CORS is restricted to the configured frontend origin(s) and allows
    // credentials so the refresh-token cookie flows correctly. We do NOT
    // accept arbitrary origins because the API serves an auth-cookie that
    // must not be exfiltrated by other sites. `FRONTEND_ORIGIN` may be a
    // comma-separated list (e.g. production URL + Vercel preview URL).
    const allowedOrigins = new Set(env.frontendOrigins.map((o) => o.toLowerCase()));
    await server.register(cors, {
      origin: (origin, cb) => {
        // Same-origin / curl / server-to-server requests have no Origin header.
        if (!origin) return cb(null, true);
        const normalized = origin.toLowerCase().replace(/\/$/, '');
        if (allowedOrigins.has(normalized)) return cb(null, true);
        // In dev, also allow localhost on the standard Vite ports so
        // `npm run dev` from a different port still works.
        if (env.nodeEnv !== 'production' && /^http:\/\/localhost:\d+$/.test(normalized)) {
          return cb(null, true);
        }
        return cb(new Error('Origin not allowed by CORS policy.'), false);
      },
      credentials: true,
    });
    await server.register(cookie);
    // Global rate-limit guardrail. Auth-specific stricter limits are added
    // route-by-route inside setupAuthRoutes via Fastify's per-route config.
    await server.register(rateLimit, {
      global: false,
      max: 600,
      timeWindow: '1 minute',
    });
    await server.register(multipart, {
      limits: {
        fileSize: 10 * 1024 * 1024,
        files: 1,
      },
    });

    // Auth plugin must be registered BEFORE the safety guard / business
    // routes so `request.user` is populated everywhere.
    await server.register(authPlugin);

    // Register global safety middleware before any route logic
    server.addHook('preHandler', preHandlerSafetyGuard);

    await setupAuthRoutes(server);
    await setupDownloadRoutes(server);
    await setupRoutes(server);
    await setupTechIntelRoutes(server);
    await setupEasmRoutes(server);
    await setupNewsRoutes(server);

    await initDB();
    await seedDatabase();
    await bootstrapAdminUser();

    // News & Intelligence: upsert the curated source registry into the DB so
    // the source-health view is populated even before the first poll fires.
    // This is intentionally separate from `startNewsIngestionSchedule()`,
    // which delays its first tick by 90 seconds to keep the HTTP listener
    // responsive immediately after boot.
    await bootstrapNewsSources();

    initWorker();
    // Background feeds: dependency CVEs every 2h (mycve.com); IOC indicators
    // every 2h from three public sources — GitHub Advisory Database, OpenPhish
    // Community Feed, and abuse.ch ThreatFox (anonymous CSV export).
    // News & Intelligence: every 30 minutes from the curated cybersecurity
    // press / vendor / CERT registry. First tick of each scheduler is
    // delayed inside the scheduler itself so HTTP comes up fast.
    startDependencyFeedSchedule();
    startIocFeedSchedule();
    startNewsIngestionSchedule();

    await server.listen({ port: env.port, host: env.host });

    server.log.info(`${env.serviceName} listening on http://${env.host}:${env.port}`);
    server.log.info(`Allowed target keys (policy): ${env.allowedTargets}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

main();
