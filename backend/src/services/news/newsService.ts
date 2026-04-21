/**
 * News & Intelligence service.
 *
 * Public surface (consumed by the route layer):
 *
 *   bootstrapNewsSources()      idempotent: upsert the registry into DB
 *   refreshAllNewsSources()     pull every enabled source, return summary
 *   refreshSingleSource(slug)   pull one source on demand
 *   listSources()               list NewsSource rows for the operator panel
 *   listIngestionRuns(limit)    history of refresh runs
 *   listArticles(filters)       paginated, filterable feed
 *   getArticleById(id)          single article + cluster siblings + neighbours
 *   listFeaturedArticles()      handful of recent, high-reputation, diverse picks
 *   buildFeedSummary()          counts for the dashboard tiles + filter chips
 *   startNewsIngestionSchedule() periodic refresh
 */

import { In, IsNull, Not } from 'typeorm';
import { AppDataSource } from '../../db/connection';
import { NewsSource } from '../../db/models/NewsSource';
import { NewsArticle } from '../../db/models/NewsArticle';
import { NewsIngestionRun } from '../../db/models/NewsIngestionRun';
import { NEWS_SOURCE_REGISTRY, type NewsSourceDefinition } from './sourceRegistry';
import { parseFeed } from './feedParser';
import { normalizeItem, type NormalizedArticle } from './normalize';
import { ARTICLE_TYPES, type ArticleType } from './types';

const REQUEST_TIMEOUT_MS = 25_000;
const PLATFORM_USER_AGENT =
  'UASF-NewsBot/1.0 (cybersecurity intelligence aggregation; +https://uasf.local/news)';
/** Cap one source per refresh so a single misbehaving feed can't fill the DB. */
const MAX_ITEMS_PER_SOURCE = 80;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/**
 * Upsert the static source registry into `news_sources`. Safe to call
 * on every boot: existing rows have their display attributes refreshed,
 * but operator-controlled fields (`enabled`, health counters) are left
 * alone.
 */
export async function bootstrapNewsSources(): Promise<void> {
  const repo = AppDataSource.getRepository(NewsSource);
  for (const def of NEWS_SOURCE_REGISTRY) {
    const existing = await repo.findOne({ where: { slug: def.slug } });
    if (existing) {
      // Refresh static metadata, keep operator fields.
      await repo.update(
        { id: existing.id },
        {
          name: def.name,
          description: def.description,
          category: def.category,
          reputation: def.reputation,
          defaultTags: def.defaultTags ?? null,
          feedUrl: def.feedUrl,
          homepageUrl: def.homepageUrl,
        },
      );
      continue;
    }
    await repo.save(
      repo.create({
        slug: def.slug,
        name: def.name,
        description: def.description,
        category: def.category,
        reputation: def.reputation,
        defaultTags: def.defaultTags ?? null,
        feedUrl: def.feedUrl,
        homepageUrl: def.homepageUrl,
        userAgent: null,
        enabled: def.enabled ?? true,
        lastFetchedAt: null,
        lastStatus: null,
        lastError: null,
        lastInsertedCount: 0,
        totalArticles: 0,
        consecutiveFailures: 0,
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// Fetch + persist
// ---------------------------------------------------------------------------

interface SourceRunSummary {
  slug: string;
  name: string;
  status: 'ok' | 'error';
  fetched: number;
  inserted: number;
  skipped: number;
  error: string | null;
  durationMs: number;
}

async function fetchFeedXml(source: NewsSource): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(source.feedUrl, {
      headers: {
        'User-Agent': source.userAgent ?? PLATFORM_USER_AGENT,
        Accept:
          'application/atom+xml, application/rss+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.1',
      },
      redirect: 'follow',
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`feed responded ${response.status}`);
    }
    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

async function persistArticle(
  source: NewsSource,
  item: NormalizedArticle,
): Promise<'inserted' | 'updated' | 'skipped'> {
  const repo = AppDataSource.getRepository(NewsArticle);

  // Already have THIS source's copy of the URL? Refresh metadata only.
  const existingForSource = await repo.findOne({
    where: { sourceSlug: item.sourceSlug, canonicalUrl: item.canonicalUrl },
  });
  if (existingForSource) {
    await repo.update(
      { id: existingForSource.id },
      {
        title: item.title,
        summary: item.summary,
        keyTakeaways: item.keyTakeaways,
        articleType: item.articleType,
        tags: item.tags,
        author: item.author,
        publishedAt: item.publishedAt,
        readingMinutes: item.readingMinutes,
        cveIds: item.cveIds.length > 0 ? item.cveIds : null,
        actorRefs: item.actorRefs.length > 0 ? item.actorRefs : null,
        imageUrl: item.imageUrl,
        reputation: item.reputation,
        searchBlob: item.searchBlob,
      },
    );
    return 'updated';
  }

  // Find an existing cluster for this dedupeKey so we can stamp the new row
  // with the same `clusterId`. If none exists, we'll use the new row's own
  // id as the cluster id (set after save).
  const clusterMember = await repo.findOne({
    where: { dedupeKey: item.dedupeKey, clusterId: Not(IsNull()) as unknown as string },
    select: ['clusterId'],
  });

  const created = repo.create({
    sourceSlug: item.sourceSlug,
    sourceName: item.sourceName,
    canonicalUrl: item.canonicalUrl,
    sourceUrl: item.sourceUrl,
    title: item.title,
    summary: item.summary,
    keyTakeaways: item.keyTakeaways,
    articleType: item.articleType,
    tags: item.tags,
    author: item.author,
    language: item.language,
    publishedAt: item.publishedAt,
    ingestedAt: new Date(),
    readingMinutes: item.readingMinutes,
    dedupeKey: item.dedupeKey,
    clusterId: clusterMember?.clusterId ?? null,
    cveIds: item.cveIds.length > 0 ? item.cveIds : null,
    actorRefs: item.actorRefs.length > 0 ? item.actorRefs : null,
    imageUrl: item.imageUrl,
    reputation: item.reputation,
    searchBlob: item.searchBlob,
  });
  const saved = await repo.save(created);
  if (!saved.clusterId) {
    saved.clusterId = saved.id;
    await repo.update({ id: saved.id }, { clusterId: saved.id });
  }
  // Bookkeeping on the source row.
  await AppDataSource.getRepository(NewsSource).increment(
    { id: source.id },
    'totalArticles',
    1,
  );
  return 'inserted';
}

async function refreshOneRow(source: NewsSource): Promise<SourceRunSummary> {
  const startedAt = Date.now();
  let xml = '';
  try {
    xml = await fetchFeedXml(source);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await AppDataSource.getRepository(NewsSource).update(
      { id: source.id },
      {
        lastFetchedAt: new Date(),
        lastStatus: 'error',
        lastError: message.slice(0, 1000),
        consecutiveFailures: source.consecutiveFailures + 1,
      },
    );
    return {
      slug: source.slug,
      name: source.name,
      status: 'error',
      fetched: 0,
      inserted: 0,
      skipped: 0,
      error: message,
      durationMs: Date.now() - startedAt,
    };
  }

  const def = NEWS_SOURCE_REGISTRY.find((d) => d.slug === source.slug);
  if (!def) {
    return {
      slug: source.slug,
      name: source.name,
      status: 'error',
      fetched: 0,
      inserted: 0,
      skipped: 0,
      error: 'source not in registry',
      durationMs: Date.now() - startedAt,
    };
  }

  const parsed = parseFeed(xml);
  let inserted = 0;
  let skipped = 0;
  const items = parsed.items.slice(0, MAX_ITEMS_PER_SOURCE);

  for (const raw of items) {
    const normalized = normalizeItem(def, raw);
    if (!normalized) {
      skipped += 1;
      continue;
    }
    try {
      const result = await persistArticle(source, normalized);
      if (result === 'inserted') inserted += 1;
      else skipped += 1;
    } catch {
      skipped += 1;
    }
  }

  await AppDataSource.getRepository(NewsSource).update(
    { id: source.id },
    {
      lastFetchedAt: new Date(),
      lastStatus: 'ok',
      lastError: null,
      lastInsertedCount: inserted,
      consecutiveFailures: 0,
    },
  );

  return {
    slug: source.slug,
    name: source.name,
    status: 'ok',
    fetched: items.length,
    inserted,
    skipped,
    error: null,
    durationMs: Date.now() - startedAt,
  };
}

// ---------------------------------------------------------------------------
// Public refresh entrypoints
// ---------------------------------------------------------------------------

export interface RefreshSummary {
  runId: string;
  triggeredBy: string;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  sourcesAttempted: number;
  sourcesSucceeded: number;
  sourcesFailed: number;
  articlesFetched: number;
  articlesInserted: number;
  articlesSkippedDuplicates: number;
  perSource: SourceRunSummary[];
}

async function recordRun(
  triggeredBy: 'scheduled' | 'manual' | 'boot',
  perSource: SourceRunSummary[],
  startedAt: Date,
): Promise<NewsIngestionRun> {
  const repo = AppDataSource.getRepository(NewsIngestionRun);
  const endedAt = new Date();
  const totals = perSource.reduce(
    (acc, s) => {
      acc.fetched += s.fetched;
      acc.inserted += s.inserted;
      acc.skipped += s.skipped;
      if (s.status === 'ok') acc.ok += 1;
      else acc.failed += 1;
      return acc;
    },
    { fetched: 0, inserted: 0, skipped: 0, ok: 0, failed: 0 },
  );
  const row = repo.create({
    triggeredBy,
    startedAt,
    endedAt,
    durationMs: endedAt.getTime() - startedAt.getTime(),
    sourcesAttempted: perSource.length,
    sourcesSucceeded: totals.ok,
    sourcesFailed: totals.failed,
    articlesFetched: totals.fetched,
    articlesInserted: totals.inserted,
    articlesSkippedDuplicates: totals.skipped,
    perSource: perSource.map((s) => ({
      slug: s.slug,
      name: s.name,
      status: s.status,
      fetched: s.fetched,
      inserted: s.inserted,
      skipped: s.skipped,
      error: s.error,
      durationMs: s.durationMs,
    })),
  });
  return repo.save(row);
}

export async function refreshAllNewsSources(
  triggeredBy: 'scheduled' | 'manual' | 'boot' = 'scheduled',
): Promise<RefreshSummary> {
  await bootstrapNewsSources();
  const startedAt = new Date();
  const sources = await AppDataSource.getRepository(NewsSource).find({
    where: { enabled: true },
    order: { name: 'ASC' },
  });

  const perSource: SourceRunSummary[] = [];
  for (const source of sources) {
    perSource.push(await refreshOneRow(source));
  }

  const stored = await recordRun(triggeredBy, perSource, startedAt);
  return summaryFromStored(stored, perSource);
}

export async function refreshSingleSource(slug: string): Promise<RefreshSummary> {
  await bootstrapNewsSources();
  const startedAt = new Date();
  const source = await AppDataSource.getRepository(NewsSource).findOne({
    where: { slug },
  });
  if (!source) throw new Error(`unknown source slug: ${slug}`);
  const perSource = [await refreshOneRow(source)];
  const stored = await recordRun('manual', perSource, startedAt);
  return summaryFromStored(stored, perSource);
}

function summaryFromStored(
  stored: NewsIngestionRun,
  perSource: SourceRunSummary[],
): RefreshSummary {
  return {
    runId: stored.id,
    triggeredBy: stored.triggeredBy,
    startedAt: stored.startedAt.toISOString(),
    endedAt: (stored.endedAt ?? new Date()).toISOString(),
    durationMs: stored.durationMs ?? 0,
    sourcesAttempted: stored.sourcesAttempted,
    sourcesSucceeded: stored.sourcesSucceeded,
    sourcesFailed: stored.sourcesFailed,
    articlesFetched: stored.articlesFetched,
    articlesInserted: stored.articlesInserted,
    articlesSkippedDuplicates: stored.articlesSkippedDuplicates,
    perSource,
  };
}

// ---------------------------------------------------------------------------
// Read-side queries
// ---------------------------------------------------------------------------

export interface FeedFilters {
  q?: string;
  source?: string;
  category?: 'news' | 'vendor' | 'cert' | 'research';
  articleType?: ArticleType;
  tag?: string;
  cve?: string;
  since?: Date;
  until?: Date;
  sort?: 'recent' | 'relevant';
  take?: number;
  skip?: number;
}

export interface FeedResult {
  total: number;
  take: number;
  skip: number;
  items: Array<NewsArticle & { clusterSize: number }>;
}

const DEFAULT_TAKE = 24;
const MAX_TAKE = 100;

export async function listArticles(filters: FeedFilters): Promise<FeedResult> {
  const repo = AppDataSource.getRepository(NewsArticle);
  const qb = repo.createQueryBuilder('a');

  if (filters.q && filters.q.trim().length > 0) {
    const q = `%${filters.q.trim().toLowerCase()}%`;
    qb.andWhere('a.searchBlob LIKE :q', { q });
  }
  if (filters.source) {
    qb.andWhere('a.sourceSlug = :source', { source: filters.source });
  }
  if (filters.articleType) {
    qb.andWhere('a.articleType = :articleType', { articleType: filters.articleType });
  }
  if (filters.tag) {
    // tags is `simple-array` (comma joined). Match the comma-bounded token
    // so e.g. `tag=apt` doesn't match `apt-credentials-leak`.
    qb.andWhere('(\',\' || a.tags || \',\') LIKE :tagToken', {
      tagToken: `%,${filters.tag.toLowerCase()},%`,
    });
  }
  if (filters.cve) {
    qb.andWhere('(\',\' || a.cveIds || \',\') LIKE :cveToken', {
      cveToken: `%,${filters.cve.toUpperCase()},%`,
    });
  }
  if (filters.since) {
    qb.andWhere('a.publishedAt >= :since', { since: filters.since });
  }
  if (filters.until) {
    qb.andWhere('a.publishedAt <= :until', { until: filters.until });
  }
  if (filters.category) {
    // category lives on the source, so join through source slugs.
    const sources = await AppDataSource.getRepository(NewsSource).find({
      where: { category: filters.category, enabled: true },
      select: ['slug'],
    });
    const slugs = sources.map((s) => s.slug);
    if (slugs.length === 0) {
      return { total: 0, take: filters.take ?? DEFAULT_TAKE, skip: filters.skip ?? 0, items: [] };
    }
    qb.andWhere('a.sourceSlug IN (:...categorySources)', { categorySources: slugs });
  }

  const take = Math.min(Math.max(filters.take ?? DEFAULT_TAKE, 1), MAX_TAKE);
  const skip = Math.max(filters.skip ?? 0, 0);
  qb.orderBy('a.publishedAt', 'DESC').addOrderBy('a.id', 'DESC').skip(skip).take(take);

  const [rows, total] = await qb.getManyAndCount();

  // Fetch cluster sizes in one query so the feed can show "Also covered by N".
  const clusterIds = rows.map((r) => r.clusterId).filter((c): c is string => !!c);
  let clusterSizeMap = new Map<string, number>();
  if (clusterIds.length > 0) {
    const counts: Array<{ clusterId: string; cnt: string }> = await repo
      .createQueryBuilder('a')
      .select('a.clusterId', 'clusterId')
      .addSelect('COUNT(*)', 'cnt')
      .where('a.clusterId IN (:...ids)', { ids: clusterIds })
      .groupBy('a.clusterId')
      .getRawMany();
    clusterSizeMap = new Map(counts.map((c) => [c.clusterId, parseInt(c.cnt, 10) || 1]));
  }

  return {
    total,
    take,
    skip,
    items: rows.map((r) => Object.assign(r, { clusterSize: clusterSizeMap.get(r.clusterId ?? '') ?? 1 })),
  };
}

export async function getArticleById(id: string): Promise<{
  article: NewsArticle;
  source: NewsSource | null;
  cluster: NewsArticle[];
  related: NewsArticle[];
} | null> {
  const repo = AppDataSource.getRepository(NewsArticle);
  const article = await repo.findOne({ where: { id } });
  if (!article) return null;

  const sourceRepo = AppDataSource.getRepository(NewsSource);
  const source = await sourceRepo.findOne({ where: { slug: article.sourceSlug } });

  const cluster = article.clusterId
    ? await repo.find({
        where: { clusterId: article.clusterId, id: Not(article.id) },
        order: { publishedAt: 'DESC' },
        take: 12,
      })
    : [];

  // Related: same articleType, recent, exclude self + cluster siblings.
  const excludeIds = [article.id, ...cluster.map((c) => c.id)];
  const related = await repo.find({
    where: {
      articleType: article.articleType,
      id: Not(In(excludeIds)),
    },
    order: { publishedAt: 'DESC' },
    take: 6,
  });

  return { article, source, cluster, related };
}

export async function listSources(): Promise<NewsSource[]> {
  return AppDataSource.getRepository(NewsSource).find({
    order: { category: 'ASC', name: 'ASC' },
  });
}

export async function listIngestionRuns(limit = 20): Promise<NewsIngestionRun[]> {
  return AppDataSource.getRepository(NewsIngestionRun).find({
    order: { startedAt: 'DESC' },
    take: Math.min(Math.max(limit, 1), 100),
  });
}

/**
 * A small set of recent, high-reputation, *type-diverse* articles for the
 * "Featured" rail at the top of the feed. We pick the most recent S/A
 * reputation article per articleType, then sort the picks by publishedAt.
 */
export async function listFeaturedArticles(): Promise<NewsArticle[]> {
  const repo = AppDataSource.getRepository(NewsArticle);
  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const candidates = await repo
    .createQueryBuilder('a')
    .where('a.publishedAt >= :since', { since })
    .andWhere('a.reputation IN (:...reps)', { reps: ['S', 'A'] })
    .orderBy('a.publishedAt', 'DESC')
    .limit(150)
    .getMany();

  const seenTypes = new Set<string>();
  const featured: NewsArticle[] = [];
  for (const article of candidates) {
    if (seenTypes.has(article.articleType)) continue;
    seenTypes.add(article.articleType);
    featured.push(article);
    if (featured.length >= 6) break;
  }
  return featured;
}

export interface FeedSummary {
  totalArticles: number;
  articlesLast24h: number;
  articlesLast7d: number;
  sources: { total: number; healthy: number; failing: number };
  byType: Record<ArticleType, number>;
  bySource: Array<{ slug: string; name: string; count: number; lastPublished: string | null }>;
  topTags: Array<{ tag: string; count: number }>;
  lastIngestionAt: string | null;
}

export async function buildFeedSummary(): Promise<FeedSummary> {
  const articleRepo = AppDataSource.getRepository(NewsArticle);
  const sourceRepo = AppDataSource.getRepository(NewsSource);

  const totalArticles = await articleRepo.count();
  const day = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const week = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const articlesLast24h = await articleRepo
    .createQueryBuilder('a')
    .where('a.publishedAt >= :d', { d: day })
    .getCount();
  const articlesLast7d = await articleRepo
    .createQueryBuilder('a')
    .where('a.publishedAt >= :w', { w: week })
    .getCount();

  const sources = await sourceRepo.find();
  const sourceHealth = sources.reduce(
    (acc, s) => {
      acc.total += 1;
      if (s.lastStatus === 'ok' || (s.lastStatus === null && s.enabled)) acc.healthy += 1;
      if (s.lastStatus === 'error') acc.failing += 1;
      return acc;
    },
    { total: 0, healthy: 0, failing: 0 },
  );

  const byTypeRows: Array<{ articleType: string; cnt: string }> = await articleRepo
    .createQueryBuilder('a')
    .select('a.articleType', 'articleType')
    .addSelect('COUNT(*)', 'cnt')
    .groupBy('a.articleType')
    .getRawMany();
  const byType = ARTICLE_TYPES.reduce(
    (acc, t) => {
      acc[t] = 0;
      return acc;
    },
    {} as Record<ArticleType, number>,
  );
  for (const row of byTypeRows) {
    if ((ARTICLE_TYPES as readonly string[]).includes(row.articleType)) {
      byType[row.articleType as ArticleType] = parseInt(row.cnt, 10) || 0;
    }
  }

  const bySourceRows: Array<{ sourceSlug: string; cnt: string; lastpub: Date | null }> =
    await articleRepo
      .createQueryBuilder('a')
      .select('a.sourceSlug', 'sourceSlug')
      .addSelect('COUNT(*)', 'cnt')
      .addSelect('MAX(a.publishedAt)', 'lastpub')
      .groupBy('a.sourceSlug')
      .orderBy('cnt', 'DESC')
      .getRawMany();
  const sourceMap = new Map(sources.map((s) => [s.slug, s]));
  const bySource = bySourceRows.map((r) => ({
    slug: r.sourceSlug,
    name: sourceMap.get(r.sourceSlug)?.name ?? r.sourceSlug,
    count: parseInt(r.cnt, 10) || 0,
    lastPublished: r.lastpub ? new Date(r.lastpub).toISOString() : null,
  }));

  // Top tags: pulled from rows-in-the-last-30-days only so noisy historical
  // tags don't dominate; we hand-roll because `simple-array` isn't queryable
  // as a real array in PG without a migration.
  const recent = await articleRepo
    .createQueryBuilder('a')
    .select('a.tags', 'tags')
    .where('a.publishedAt >= :w', { w: week })
    .limit(2000)
    .getRawMany();
  const tagCount = new Map<string, number>();
  for (const r of recent) {
    const raw = (r.tags ?? '') as string;
    if (!raw) continue;
    for (const t of raw.split(',')) {
      const tag = t.trim();
      if (!tag) continue;
      tagCount.set(tag, (tagCount.get(tag) ?? 0) + 1);
    }
  }
  const topTags = Array.from(tagCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 18)
    .map(([tag, count]) => ({ tag, count }));

  const lastRun = await AppDataSource.getRepository(NewsIngestionRun).findOne({
    where: {},
    order: { startedAt: 'DESC' },
  });

  return {
    totalArticles,
    articlesLast24h,
    articlesLast7d,
    sources: sourceHealth,
    byType,
    bySource,
    topTags,
    lastIngestionAt: lastRun?.startedAt.toISOString() ?? null,
  };
}

// ---------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------

let scheduleHandle: NodeJS.Timeout | null = null;
let bootTickHandle: NodeJS.Timeout | null = null;
let isRefreshing = false;

/**
 * Start the periodic news refresh. Default cadence: every 30 minutes, with
 * the first tick 90 seconds after startup so the platform is responsive
 * immediately on boot.
 *
 * Idempotent: re-calling cancels any previous schedule.
 *
 * If a refresh is still running when the next tick fires, the new tick is
 * silently dropped (`isRefreshing` guard) — we never run two ingestion
 * passes in parallel against the same DB.
 */
export function startNewsIngestionSchedule(everyMs = 30 * 60 * 1000): void {
  if (scheduleHandle) clearInterval(scheduleHandle);
  if (bootTickHandle) clearTimeout(bootTickHandle);

  bootTickHandle = setTimeout(() => {
    void runGuarded('boot');
  }, 90_000);

  scheduleHandle = setInterval(() => {
    void runGuarded('scheduled');
  }, everyMs);
}

async function runGuarded(triggeredBy: 'scheduled' | 'manual' | 'boot'): Promise<void> {
  if (isRefreshing) return;
  isRefreshing = true;
  try {
    await refreshAllNewsSources(triggeredBy);
  } catch {
    // Per-source failures are absorbed inside refreshOneRow; this only
    // catches truly catastrophic failures (DB outage etc.).
  } finally {
    isRefreshing = false;
  }
}

/**
 * Returns whether a refresh is currently in flight. Used by the API to
 * give honest answers when the operator presses "Refresh now" rapidly.
 */
export function isIngestionRunning(): boolean {
  return isRefreshing;
}
