/**
 * UASF — News & Intelligence API
 *
 *   GET    /api/news/feed                 Paginated, filterable feed.
 *   GET    /api/news/summary              Counts + filter chips for dashboard.
 *   GET    /api/news/featured             Curated cross-type rail.
 *   GET    /api/news/article/:id          One article + cluster + related.
 *   GET    /api/news/sources              Source registry health view.
 *   GET    /api/news/runs                 Recent ingestion runs.
 *   POST   /api/news/refresh              Trigger an immediate refresh.
 *                                         Body: { source?: <slug> } to refresh
 *                                         a single feed; otherwise all.
 *                                         Admin role required.
 *   GET    /api/news/status               Cheap polling endpoint to check
 *                                         whether a refresh is in flight.
 *
 * Auth: every route is covered by the global auth plugin. The `/refresh`
 * endpoint additionally requires the `admin` role.
 */

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  buildFeedSummary,
  getArticleById,
  isIngestionRunning,
  listArticles,
  listFeaturedArticles,
  listIngestionRuns,
  listSources,
  refreshAllNewsSources,
  refreshSingleSource,
} from '../services/news/newsService';
import { ARTICLE_TYPES, type ArticleType } from '../services/news/types';

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

const feedQuerySchema = z.object({
  q: z.string().trim().max(200).optional(),
  source: z.string().trim().min(1).max(64).optional(),
  category: z.enum(['news', 'vendor', 'cert', 'research']).optional(),
  type: z.enum(ARTICLE_TYPES as unknown as [ArticleType, ...ArticleType[]]).optional(),
  tag: z.string().trim().min(1).max(40).optional(),
  cve: z
    .string()
    .trim()
    .regex(/^CVE-\d{4}-\d{4,7}$/i)
    .optional(),
  since: z.string().datetime().optional(),
  until: z.string().datetime().optional(),
  sort: z.enum(['recent', 'relevant']).optional(),
  take: z
    .string()
    .regex(/^\d+$/)
    .transform((s) => parseInt(s, 10))
    .optional(),
  skip: z
    .string()
    .regex(/^\d+$/)
    .transform((s) => parseInt(s, 10))
    .optional(),
});

const refreshBodySchema = z
  .object({
    source: z.string().trim().min(1).max(64).optional(),
  })
  .strict();

const idParamSchema = z.object({
  id: z.string().uuid('article id must be a UUID'),
});

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function setupNewsRoutes(server: FastifyInstance): Promise<void> {
  // -------------------------------------------------------------------------
  // Feed listing — paginated, server-filtered.
  // -------------------------------------------------------------------------
  server.get('/api/news/feed', async (request, reply) => {
    const parsed = feedQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({
        error: 'Invalid news feed query.',
        code: 'NEWS_FEED_QUERY_INVALID',
        issues: parsed.error.issues.map((i) => ({ path: i.path, message: i.message })),
      });
    }
    const q = parsed.data;
    try {
      const result = await listArticles({
        q: q.q,
        source: q.source,
        category: q.category,
        articleType: q.type,
        tag: q.tag,
        cve: q.cve,
        since: q.since ? new Date(q.since) : undefined,
        until: q.until ? new Date(q.until) : undefined,
        sort: q.sort,
        take: q.take,
        skip: q.skip,
      });
      return result;
    } catch (err) {
      request.log.error({ err }, 'news feed query failed');
      return reply.code(500).send({
        error: 'Failed to load news feed.',
        code: 'NEWS_FEED_FAILED',
      });
    }
  });

  // -------------------------------------------------------------------------
  // Feed summary — counts + chips.
  // -------------------------------------------------------------------------
  server.get('/api/news/summary', async (_request, reply) => {
    try {
      return await buildFeedSummary();
    } catch (err) {
      reply.log.error({ err }, 'news summary failed');
      return reply.code(500).send({
        error: 'Failed to compute news summary.',
        code: 'NEWS_SUMMARY_FAILED',
      });
    }
  });

  // -------------------------------------------------------------------------
  // Featured rail — small, type-diverse, recent picks.
  // -------------------------------------------------------------------------
  server.get('/api/news/featured', async (_request, reply) => {
    try {
      const items = await listFeaturedArticles();
      return { items };
    } catch (err) {
      reply.log.error({ err }, 'news featured failed');
      return reply.code(500).send({
        error: 'Failed to compute featured news.',
        code: 'NEWS_FEATURED_FAILED',
      });
    }
  });

  // -------------------------------------------------------------------------
  // Single article — UUID-only, returns 404 if not found.
  // -------------------------------------------------------------------------
  server.get('/api/news/article/:id', async (request, reply) => {
    const parsed = idParamSchema.safeParse(request.params);
    if (!parsed.success) {
      return reply.code(400).send({
        error: 'Invalid article id.',
        code: 'NEWS_ARTICLE_ID_INVALID',
      });
    }
    try {
      const result = await getArticleById(parsed.data.id);
      if (!result) {
        return reply.code(404).send({
          error: 'Article not found.',
          code: 'NEWS_ARTICLE_NOT_FOUND',
        });
      }
      return result;
    } catch (err) {
      request.log.error({ err }, 'news article query failed');
      return reply.code(500).send({
        error: 'Failed to load article.',
        code: 'NEWS_ARTICLE_FAILED',
      });
    }
  });

  // -------------------------------------------------------------------------
  // Source registry health.
  // -------------------------------------------------------------------------
  server.get('/api/news/sources', async (_request, reply) => {
    try {
      const items = await listSources();
      return { items };
    } catch (err) {
      reply.log.error({ err }, 'news sources query failed');
      return reply.code(500).send({
        error: 'Failed to load news sources.',
        code: 'NEWS_SOURCES_FAILED',
      });
    }
  });

  // -------------------------------------------------------------------------
  // Recent ingestion runs.
  // -------------------------------------------------------------------------
  server.get('/api/news/runs', async (request, reply) => {
    const limit = parseInt((request.query as { limit?: string }).limit ?? '20', 10);
    try {
      const items = await listIngestionRuns(Number.isFinite(limit) ? limit : 20);
      return { items };
    } catch (err) {
      request.log.error({ err }, 'news runs query failed');
      return reply.code(500).send({
        error: 'Failed to load ingestion runs.',
        code: 'NEWS_RUNS_FAILED',
      });
    }
  });

  // -------------------------------------------------------------------------
  // Cheap polling — has the user's "Refresh" click finished yet?
  // -------------------------------------------------------------------------
  server.get('/api/news/status', async () => {
    return { refreshing: isIngestionRunning() };
  });

  // -------------------------------------------------------------------------
  // Refresh — admin-gated, never throws to the operator UI.
  // -------------------------------------------------------------------------
  server.post(
    '/api/news/refresh',
    {
      preHandler: server.requireRole(['admin']),
    },
    async (request, reply) => {
      const parsed = refreshBodySchema.safeParse(request.body ?? {});
      if (!parsed.success) {
        return reply.code(400).send({
          error: 'Invalid refresh request.',
          code: 'NEWS_REFRESH_INVALID',
        });
      }
      try {
        const summary = parsed.data.source
          ? await refreshSingleSource(parsed.data.source)
          : await refreshAllNewsSources('manual');
        return summary;
      } catch (err) {
        request.log.error({ err }, 'news refresh failed');
        return reply.code(500).send({
          error: err instanceof Error ? err.message : 'Failed to refresh news.',
          code: 'NEWS_REFRESH_FAILED',
        });
      }
    },
  );
}
