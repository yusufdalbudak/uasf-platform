import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  Bug,
  Building2,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  Cloud,
  Clock,
  Database,
  ExternalLink,
  Filter,
  Flame,
  Globe2,
  Key,
  Layers,
  Loader2,
  Newspaper,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldAlert,
  Tag,
  TrendingUp,
  Users,
  X,
} from 'lucide-react';
import { ApiError, apiFetchJson } from '../lib/api';
import { useAuth } from '../auth/useAuth';

// ---------------------------------------------------------------------------
// Types — server contract
// ---------------------------------------------------------------------------

type ArticleType =
  | 'news'
  | 'advisory'
  | 'vendor-research'
  | 'breach'
  | 'malware'
  | 'threat-actor'
  | 'vulnerability'
  | 'cloud'
  | 'supply-chain'
  | 'identity'
  | 'appsec'
  | 'data-leak';

interface FeedItem {
  id: string;
  sourceSlug: string;
  sourceName: string;
  canonicalUrl: string;
  sourceUrl: string;
  title: string;
  summary: string | null;
  articleType: ArticleType;
  tags: string[] | null;
  author: string | null;
  publishedAt: string;
  ingestedAt: string;
  readingMinutes: number;
  reputation: string;
  cveIds: string[] | null;
  imageUrl: string | null;
  clusterSize: number;
}

interface FeedPayload {
  total: number;
  take: number;
  skip: number;
  items: FeedItem[];
}

interface SourceItem {
  slug: string;
  name: string;
  category: 'news' | 'vendor' | 'cert' | 'research';
  reputation: string;
  enabled: boolean;
  lastStatus: string | null;
  lastFetchedAt: string | null;
  consecutiveFailures: number;
  totalArticles: number;
}

interface SummaryPayload {
  totalArticles: number;
  articlesLast24h: number;
  articlesLast7d: number;
  sources: { total: number; healthy: number; failing: number };
  byType: Record<ArticleType, number>;
  bySource: Array<{ slug: string; name: string; count: number; lastPublished: string | null }>;
  topTags: Array<{ tag: string; count: number }>;
  lastIngestionAt: string | null;
}

interface RefreshSummary {
  runId: string;
  triggeredBy: string;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  sourcesAttempted: number;
  sourcesSucceeded: number;
  sourcesFailed: number;
  articlesInserted: number;
}

// ---------------------------------------------------------------------------
// Visual maps
// ---------------------------------------------------------------------------

const TYPE_LABELS: Record<ArticleType, string> = {
  news: 'News',
  advisory: 'Advisory',
  'vendor-research': 'Vendor Research',
  breach: 'Breach',
  malware: 'Malware',
  'threat-actor': 'Threat Actor',
  vulnerability: 'Vulnerability',
  cloud: 'Cloud',
  'supply-chain': 'Supply Chain',
  identity: 'Identity',
  appsec: 'AppSec',
  'data-leak': 'Data Leak',
};

const TYPE_TONE: Record<ArticleType, string> = {
  news: 'bg-slate-500/15 text-slate-200 border-slate-500/30',
  advisory: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  'vendor-research': 'bg-violet-500/15 text-violet-200 border-violet-500/30',
  breach: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  malware: 'bg-red-500/15 text-red-200 border-red-500/30',
  'threat-actor': 'bg-orange-500/15 text-orange-200 border-orange-500/30',
  vulnerability: 'bg-yellow-500/15 text-yellow-200 border-yellow-500/30',
  cloud: 'bg-sky-500/15 text-sky-200 border-sky-500/30',
  'supply-chain': 'bg-fuchsia-500/15 text-fuchsia-200 border-fuchsia-500/30',
  identity: 'bg-indigo-500/15 text-indigo-200 border-indigo-500/30',
  appsec: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  'data-leak': 'bg-pink-500/15 text-pink-200 border-pink-500/30',
};

const TYPE_ICON: Record<ArticleType, JSX.Element> = {
  news: <Newspaper size={12} />,
  advisory: <ShieldAlert size={12} />,
  'vendor-research': <Layers size={12} />,
  breach: <AlertTriangle size={12} />,
  malware: <Bug size={12} />,
  'threat-actor': <Users size={12} />,
  vulnerability: <Flame size={12} />,
  cloud: <Cloud size={12} />,
  'supply-chain': <Database size={12} />,
  identity: <Key size={12} />,
  appsec: <ShieldCheck size={12} />,
  'data-leak': <Database size={12} />,
};

const CATEGORY_LABEL: Record<SourceItem['category'], string> = {
  news: 'Press',
  vendor: 'Vendor',
  cert: 'CERT / Advisory',
  research: 'Research',
};

const CATEGORY_TONE: Record<SourceItem['category'], string> = {
  news: 'bg-slate-700/40 text-slate-200 border-slate-600',
  vendor: 'bg-violet-700/30 text-violet-200 border-violet-700/50',
  cert: 'bg-amber-700/30 text-amber-200 border-amber-700/50',
  research: 'bg-emerald-700/30 text-emerald-200 border-emerald-700/50',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function timeAgo(iso: string): string {
  const ts = new Date(iso).getTime();
  if (!Number.isFinite(ts)) return '—';
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'just now';
  const m = Math.floor(diff / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

const ALL_TYPES: ArticleType[] = [
  'advisory',
  'vulnerability',
  'breach',
  'malware',
  'threat-actor',
  'vendor-research',
  'supply-chain',
  'cloud',
  'identity',
  'appsec',
  'data-leak',
  'news',
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const News = () => {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [items, setItems] = useState<FeedItem[]>([]);
  const [total, setTotal] = useState(0);
  const [skip, setSkip] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [sources, setSources] = useState<SourceItem[]>([]);
  const [summary, setSummary] = useState<SummaryPayload | null>(null);
  const [featured, setFeatured] = useState<FeedItem[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<number | null>(null);

  // Filters
  const [searchInput, setSearchInput] = useState('');
  const [q, setQ] = useState('');
  const [type, setType] = useState<ArticleType | 'all'>('all');
  const [source, setSource] = useState<string>('all');
  const [category, setCategory] = useState<'all' | SourceItem['category']>('all');
  const [tag, setTag] = useState<string | null>(null);
  const [range, setRange] = useState<'24h' | '7d' | '30d' | 'all'>('7d');
  const [showFilters, setShowFilters] = useState(true);

  const TAKE = 18;

  // Debounce search input → q
  useEffect(() => {
    const t = window.setTimeout(() => setQ(searchInput.trim()), 350);
    return () => window.clearTimeout(t);
  }, [searchInput]);

  const buildQueryParams = useCallback(
    (nextSkip: number) => {
      const p = new URLSearchParams();
      p.set('take', String(TAKE));
      p.set('skip', String(nextSkip));
      if (q) p.set('q', q);
      if (type !== 'all') p.set('type', type);
      if (source !== 'all') p.set('source', source);
      if (category !== 'all') p.set('category', category);
      if (tag) p.set('tag', tag);
      if (range !== 'all') {
        const days = range === '24h' ? 1 : range === '7d' ? 7 : 30;
        p.set('since', new Date(Date.now() - days * 86_400_000).toISOString());
      }
      return p.toString();
    },
    [q, type, source, category, tag, range],
  );

  const loadFeed = useCallback(
    async (nextSkip: number, append: boolean) => {
      if (append) setLoadingMore(true);
      else setLoading(true);
      setError(null);
      try {
        const { data } = await apiFetchJson<FeedPayload>(
          `/news/feed?${buildQueryParams(nextSkip)}`,
        );
        setTotal(data.total);
        setSkip(nextSkip);
        setItems((prev) => (append ? [...prev, ...data.items] : data.items));
      } catch (e) {
        if (e instanceof ApiError) setError(e.message);
        else setError(e instanceof Error ? e.message : 'Failed to load news.');
        if (!append) setItems([]);
      } finally {
        setLoading(false);
        setLoadingMore(false);
      }
    },
    [buildQueryParams],
  );

  useEffect(() => {
    void loadFeed(0, false);
  }, [loadFeed]);

  // Sidecar metadata — loaded once, refreshed on manual ingestion success.
  const loadSideData = useCallback(async () => {
    try {
      const [sumRes, sourcesRes, featuredRes] = await Promise.all([
        apiFetchJson<SummaryPayload>('/news/summary'),
        apiFetchJson<{ items: SourceItem[] }>('/news/sources'),
        apiFetchJson<{ items: FeedItem[] }>('/news/featured'),
      ]);
      setSummary(sumRes.data);
      setSources(sourcesRes.data.items);
      setFeatured(featuredRes.data.items.map((i) => ({ ...i, clusterSize: 1 })));
    } catch {
      // sidecar load failures are non-fatal — the main feed has its own error path
    }
  }, []);

  useEffect(() => {
    void loadSideData();
  }, [loadSideData]);

  const showToast = (message: string) => {
    setToast(message);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 4500);
  };

  const onRefresh = async () => {
    if (!isAdmin || refreshing) return;
    setRefreshing(true);
    showToast('Refreshing intelligence sources… you will see fresh stories shortly.');
    try {
      const { data } = await apiFetchJson<RefreshSummary>('/news/refresh', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      showToast(
        `Refresh complete — ${data.articlesInserted} new article${
          data.articlesInserted === 1 ? '' : 's'
        } from ${data.sourcesSucceeded}/${data.sourcesAttempted} sources.`,
      );
      await Promise.all([loadFeed(0, false), loadSideData()]);
    } catch (e) {
      showToast(
        `Refresh failed: ${e instanceof Error ? e.message : 'unknown error'}.`,
      );
    } finally {
      setRefreshing(false);
    }
  };

  const clearAllFilters = () => {
    setSearchInput('');
    setQ('');
    setType('all');
    setSource('all');
    setCategory('all');
    setTag(null);
    setRange('7d');
  };

  const hasFilters =
    !!q || type !== 'all' || source !== 'all' || category !== 'all' || tag || range !== '7d';

  const sourceMap = useMemo(() => new Map(sources.map((s) => [s.slug, s])), [sources]);
  const summaryByType = summary?.byType ?? null;

  const canShowMore = items.length < total;

  // -------------------------------------------------------------------------
  return (
    <div className="space-y-6">
      {/* ============================== HEADER ============================ */}
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-md bg-gradient-to-br from-[#8e51df] to-[#4d1c8c] flex items-center justify-center shadow-lg">
              <Newspaper size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Cyber News & Intelligence
              </h1>
              <p className="text-sm text-[#94a3b8] mt-0.5">
                Curated feed across {summary?.sources.total ?? '—'} reputable sources, deduplicated and
                source-attributed. Updated every 30 minutes.
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {summary?.lastIngestionAt && (
            <span className="text-xs text-[#94a3b8] hidden sm:inline-flex items-center gap-1.5">
              <Clock size={12} />
              Updated {timeAgo(summary.lastIngestionAt)}
            </span>
          )}
          {isAdmin && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={refreshing}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-sm rounded-md bg-[#1a1d24] border border-[#2d333b] hover:border-[#6a2bba]/60 hover:bg-[#6a2bba]/10 text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {refreshing ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <RefreshCw size={14} />
              )}
              {refreshing ? 'Refreshing…' : 'Refresh'}
            </button>
          )}
        </div>
      </header>

      {/* ============================== SUMMARY TILES ===================== */}
      {summary && (
        <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Tile
            icon={<Newspaper size={16} className="text-[#8e51df]" />}
            label="Articles"
            value={summary.totalArticles}
            sublabel={`${summary.articlesLast24h} new today`}
          />
          <Tile
            icon={<TrendingUp size={16} className="text-emerald-400" />}
            label="Last 7 days"
            value={summary.articlesLast7d}
            sublabel="published"
          />
          <Tile
            icon={<Globe2 size={16} className="text-sky-400" />}
            label="Sources"
            value={summary.sources.total}
            sublabel={`${summary.sources.healthy} healthy · ${summary.sources.failing} failing`}
          />
          <Tile
            icon={<ShieldAlert size={16} className="text-amber-400" />}
            label="Advisories"
            value={(summaryByType?.advisory ?? 0) + (summaryByType?.vulnerability ?? 0)}
            sublabel="advisory + vulnerability"
          />
        </section>
      )}

      {/* ============================== FEATURED RAIL ===================== */}
      {featured.length > 0 && !hasFilters && (
        <section>
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm uppercase tracking-widest text-[#94a3b8] font-semibold flex items-center gap-2">
              <Flame size={14} className="text-[#8e51df]" /> Featured
            </h2>
            <span className="text-xs text-[#64748b]">type-diverse picks · 7d</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {featured.slice(0, 3).map((article) => (
              <FeaturedCard key={article.id} article={article} sourceMap={sourceMap} />
            ))}
          </div>
        </section>
      )}

      {/* ============================== TOOLBAR =========================== */}
      <section className="bg-[#161922] border border-[#2d333b] rounded-lg">
        <div className="px-4 py-3 flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[260px]">
            <Search
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]"
            />
            <input
              type="search"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search title or summary… (e.g. lockbit, CVE-2026-1234, supply chain)"
              className="w-full bg-[#0f1115] border border-[#2d333b] rounded-md pl-9 pr-3 py-2 text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#6a2bba]/60"
            />
          </div>
          <select
            value={range}
            onChange={(e) => setRange(e.target.value as typeof range)}
            className="bg-[#0f1115] border border-[#2d333b] rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-[#6a2bba]/60"
          >
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="all">All time</option>
          </select>
          <button
            type="button"
            onClick={() => setShowFilters((v) => !v)}
            className="inline-flex items-center gap-2 px-3 py-2 text-sm rounded-md bg-[#0f1115] border border-[#2d333b] text-white hover:border-[#6a2bba]/60"
          >
            <Filter size={14} />
            Filters
            <ChevronDown
              size={14}
              className={`transition-transform ${showFilters ? 'rotate-180' : ''}`}
            />
          </button>
          {hasFilters && (
            <button
              type="button"
              onClick={clearAllFilters}
              className="inline-flex items-center gap-1.5 text-xs text-[#94a3b8] hover:text-white"
            >
              <X size={12} /> Clear
            </button>
          )}
        </div>
        {showFilters && (
          <div className="border-t border-[#2d333b] px-4 py-3 grid gap-3 md:grid-cols-3">
            {/* Type filter */}
            <div>
              <label className="block text-[10px] uppercase tracking-widest text-[#94a3b8] mb-1.5 font-semibold">
                Article type
              </label>
              <div className="flex flex-wrap gap-1.5">
                <Chip
                  label="All"
                  active={type === 'all'}
                  onClick={() => setType('all')}
                />
                {ALL_TYPES.map((t) => {
                  const count = summaryByType?.[t] ?? 0;
                  if (count === 0 && type !== t) return null;
                  return (
                    <Chip
                      key={t}
                      label={`${TYPE_LABELS[t]}${count ? ` · ${count}` : ''}`}
                      icon={TYPE_ICON[t]}
                      active={type === t}
                      onClick={() => setType(type === t ? 'all' : t)}
                      tone={TYPE_TONE[t]}
                    />
                  );
                })}
              </div>
            </div>
            {/* Source category filter */}
            <div>
              <label className="block text-[10px] uppercase tracking-widest text-[#94a3b8] mb-1.5 font-semibold">
                Source category
              </label>
              <div className="flex flex-wrap gap-1.5">
                <Chip
                  label="All"
                  active={category === 'all'}
                  onClick={() => setCategory('all')}
                />
                {(['cert', 'news', 'vendor', 'research'] as const).map((c) => (
                  <Chip
                    key={c}
                    label={CATEGORY_LABEL[c]}
                    icon={
                      c === 'cert' ? <ShieldAlert size={12} /> :
                      c === 'news' ? <Newspaper size={12} /> :
                      c === 'vendor' ? <Building2 size={12} /> :
                      <Layers size={12} />
                    }
                    active={category === c}
                    onClick={() => setCategory(category === c ? 'all' : c)}
                    tone={CATEGORY_TONE[c]}
                  />
                ))}
              </div>
            </div>
            {/* Source picker */}
            <div>
              <label className="block text-[10px] uppercase tracking-widest text-[#94a3b8] mb-1.5 font-semibold">
                Source
              </label>
              <select
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="w-full bg-[#0f1115] border border-[#2d333b] rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-[#6a2bba]/60"
              >
                <option value="all">All sources</option>
                {sources.map((s) => (
                  <option key={s.slug} value={s.slug}>
                    {s.name} · {CATEGORY_LABEL[s.category]} ({s.totalArticles})
                  </option>
                ))}
              </select>
            </div>
            {/* Top tags */}
            {summary && summary.topTags.length > 0 && (
              <div className="md:col-span-3">
                <label className="block text-[10px] uppercase tracking-widest text-[#94a3b8] mb-1.5 font-semibold">
                  Trending tags (last 7d)
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {summary.topTags.slice(0, 14).map((t) => (
                    <Chip
                      key={t.tag}
                      label={`#${t.tag} · ${t.count}`}
                      icon={<Tag size={11} />}
                      active={tag === t.tag}
                      onClick={() => setTag(tag === t.tag ? null : t.tag)}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ============================== STATUS LINE ======================= */}
      <div className="text-xs text-[#64748b] flex items-center gap-2">
        {loading ? (
          <>
            <Loader2 size={12} className="animate-spin" /> Loading articles…
          </>
        ) : (
          <>
            <CircleDashed size={12} />
            Showing {items.length.toLocaleString()} of {total.toLocaleString()} articles
            {q && (
              <>
                {' '}for "<span className="text-white">{q}</span>"
              </>
            )}
            {tag && (
              <>
                {' '}tagged <span className="text-white">#{tag}</span>
              </>
            )}
          </>
        )}
      </div>

      {/* ============================== ERROR ============================= */}
      {error && (
        <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200 flex items-start gap-2">
          <AlertTriangle size={16} className="shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">Failed to load news.</div>
            <div className="text-xs mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {/* ============================== FEED ============================== */}
      {!loading && items.length === 0 && !error ? (
        <div className="rounded-lg border border-[#2d333b] bg-[#161922] px-6 py-12 text-center">
          <Search size={32} className="mx-auto text-[#475569] mb-3" />
          <div className="text-white font-semibold">No articles match your filters.</div>
          <div className="text-sm text-[#94a3b8] mt-1">
            Try widening the time range or clearing the active filters.
          </div>
          {hasFilters && (
            <button
              type="button"
              onClick={clearAllFilters}
              className="mt-4 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#6a2bba]/20 border border-[#6a2bba]/40 text-[#c8a8ff] text-sm hover:bg-[#6a2bba]/30"
            >
              <X size={12} /> Clear filters
            </button>
          )}
        </div>
      ) : (
        <ul className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {items.map((item) => (
            <ArticleCard key={item.id} article={item} sourceMap={sourceMap} />
          ))}
        </ul>
      )}

      {/* ============================== LOAD MORE ========================= */}
      {canShowMore && !loading && (
        <div className="flex justify-center pt-2">
          <button
            type="button"
            disabled={loadingMore}
            onClick={() => void loadFeed(skip + TAKE, true)}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm rounded-md bg-[#161922] border border-[#2d333b] text-white hover:border-[#6a2bba]/60 hover:bg-[#6a2bba]/10 disabled:opacity-60"
          >
            {loadingMore ? <Loader2 size={14} className="animate-spin" /> : <ChevronDown size={14} />}
            {loadingMore ? 'Loading…' : `Load ${Math.min(TAKE, total - items.length)} more`}
          </button>
        </div>
      )}

      {/* ============================== TOAST ============================= */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 max-w-sm rounded-md border border-[#6a2bba]/50 bg-[#161922] shadow-xl shadow-black/40 px-4 py-3 text-sm text-white animate-fadeIn flex items-start gap-2">
          <CheckCircle2 size={16} className="text-[#8e51df] mt-0.5 shrink-0" />
          <div className="flex-1">{toast}</div>
          <button
            type="button"
            className="text-[#94a3b8] hover:text-white"
            onClick={() => setToast(null)}
          >
            <X size={14} />
          </button>
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Sub-components (kept in-file: tightly coupled, no other consumers)
// ---------------------------------------------------------------------------

const Tile = ({
  icon,
  label,
  value,
  sublabel,
}: {
  icon: JSX.Element;
  label: string;
  value: number;
  sublabel: string;
}) => (
  <div className="bg-[#161922] border border-[#2d333b] rounded-lg p-4">
    <div className="flex items-center gap-2 text-xs text-[#94a3b8] uppercase tracking-widest font-semibold">
      {icon}
      {label}
    </div>
    <div className="mt-2 text-2xl font-bold text-white tabular-nums">
      {value.toLocaleString()}
    </div>
    <div className="text-xs text-[#64748b] mt-0.5">{sublabel}</div>
  </div>
);

const Chip = ({
  label,
  icon,
  active,
  onClick,
  tone,
}: {
  label: string;
  icon?: JSX.Element;
  active: boolean;
  onClick: () => void;
  tone?: string;
}) => (
  <button
    type="button"
    onClick={onClick}
    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border transition-colors ${
      active
        ? 'bg-[#6a2bba]/30 border-[#8e51df] text-white'
        : tone ?? 'bg-[#0f1115] border-[#2d333b] text-[#cbd5e1] hover:border-[#475569]'
    }`}
  >
    {icon}
    {label}
  </button>
);

const ArticleCard = ({
  article,
  sourceMap,
}: {
  article: FeedItem;
  sourceMap: Map<string, SourceItem>;
}) => {
  const src = sourceMap.get(article.sourceSlug);
  return (
    <li className="group bg-[#161922] border border-[#2d333b] rounded-lg p-4 hover:border-[#6a2bba]/60 transition-colors flex flex-col">
      <div className="flex items-center justify-between gap-2 text-xs text-[#94a3b8] mb-2">
        <span className="inline-flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-[#8e51df]" />
          <span className="font-semibold text-white">{article.sourceName}</span>
          {src && (
            <span
              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] ${
                CATEGORY_TONE[src.category]
              }`}
            >
              {CATEGORY_LABEL[src.category]}
            </span>
          )}
          <span className="text-[#64748b]">·</span>
          <span>{timeAgo(article.publishedAt)}</span>
        </span>
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] uppercase tracking-wide font-semibold ${
            TYPE_TONE[article.articleType]
          }`}
        >
          {TYPE_ICON[article.articleType]}
          {TYPE_LABELS[article.articleType]}
        </span>
      </div>

      <Link
        to={`/news/${article.id}`}
        className="text-base font-semibold text-white leading-snug group-hover:text-[#c8a8ff]"
      >
        {article.title}
      </Link>

      {article.summary && (
        <p className="mt-2 text-sm text-[#cbd5e1] line-clamp-3 leading-relaxed">
          {article.summary}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        {(article.cveIds ?? []).slice(0, 3).map((cve) => (
          <span
            key={cve}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-200 text-[10px] font-mono"
          >
            <Bug size={10} /> {cve}
          </span>
        ))}
        {(article.tags ?? []).slice(0, 4).map((t) => (
          <span
            key={t}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] text-[#94a3b8] bg-[#0f1115] border border-[#2d333b]"
          >
            #{t}
          </span>
        ))}
      </div>

      <div className="mt-auto pt-3 flex items-center justify-between text-xs text-[#94a3b8]">
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1">
            <Clock size={11} /> {article.readingMinutes}m read
          </span>
          {article.clusterSize > 1 && (
            <span className="inline-flex items-center gap-1 text-[#c8a8ff]">
              <Layers size={11} /> Also covered by {article.clusterSize - 1}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Link
            to={`/news/${article.id}`}
            className="inline-flex items-center gap-1 text-white hover:text-[#c8a8ff]"
          >
            Read details <ChevronRight size={12} />
          </Link>
          <a
            href={article.canonicalUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-[#94a3b8] hover:text-white"
            title={`Open original on ${hostOf(article.canonicalUrl)}`}
          >
            <ExternalLink size={11} /> Source
          </a>
        </div>
      </div>
    </li>
  );
};

const FeaturedCard = ({
  article,
  sourceMap,
}: {
  article: FeedItem;
  sourceMap: Map<string, SourceItem>;
}) => {
  const src = sourceMap.get(article.sourceSlug);
  return (
    <Link
      to={`/news/${article.id}`}
      className="group block bg-gradient-to-br from-[#1a1d24] to-[#161922] border border-[#2d333b] rounded-lg p-4 hover:border-[#6a2bba]/60 transition-colors"
    >
      <div className="flex items-center justify-between text-xs text-[#94a3b8] mb-2">
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] uppercase tracking-wide font-semibold ${
            TYPE_TONE[article.articleType]
          }`}
        >
          {TYPE_ICON[article.articleType]}
          {TYPE_LABELS[article.articleType]}
        </span>
        <span>{timeAgo(article.publishedAt)}</span>
      </div>
      <h3 className="text-sm font-semibold text-white group-hover:text-[#c8a8ff] leading-snug line-clamp-3">
        {article.title}
      </h3>
      <div className="mt-3 text-[11px] text-[#94a3b8] flex items-center gap-1.5">
        <span className="font-semibold text-white">{article.sourceName}</span>
        {src && (
          <span
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] ${
              CATEGORY_TONE[src.category]
            }`}
          >
            {CATEGORY_LABEL[src.category]}
          </span>
        )}
      </div>
    </Link>
  );
};

export default News;
