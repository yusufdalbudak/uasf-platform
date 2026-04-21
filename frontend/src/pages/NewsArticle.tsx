import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Bug,
  Calendar,
  ChevronRight,
  Clock,
  ExternalLink,
  Layers,
  Loader2,
  Newspaper,
  Quote,
  ShieldAlert,
  Sparkles,
  Target,
  User,
  Users,
} from 'lucide-react';
import { ApiError, apiFetchJson } from '../lib/api';

// ---------------------------------------------------------------------------
// Server contract (mirrors backend services/news/*)
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

interface Article {
  id: string;
  sourceSlug: string;
  sourceName: string;
  canonicalUrl: string;
  sourceUrl: string;
  title: string;
  summary: string | null;
  keyTakeaways: string[] | null;
  articleType: ArticleType;
  tags: string[] | null;
  author: string | null;
  language: string;
  publishedAt: string;
  ingestedAt: string;
  readingMinutes: number;
  cveIds: string[] | null;
  actorRefs: string[] | null;
  imageUrl: string | null;
  reputation: string;
}

interface ArticleSource {
  slug: string;
  name: string;
  description: string | null;
  category: 'news' | 'vendor' | 'cert' | 'research';
  reputation: string;
  homepageUrl: string | null;
  feedUrl: string;
}

interface DetailPayload {
  article: Article;
  source: ArticleSource | null;
  cluster: Article[];
  related: Article[];
}

// ---------------------------------------------------------------------------
// Visual maps (kept in sync with News.tsx — duplicated intentionally so the
// detail page can be read in isolation without import gymnastics)
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

const CATEGORY_LABEL: Record<ArticleSource['category'], string> = {
  news: 'Press',
  vendor: 'Vendor',
  cert: 'CERT / Advisory',
  research: 'Research',
};

const TYPE_NARRATIVE: Record<ArticleType, { why: string; relevance: string }> = {
  news: {
    why: 'General security news. Useful as situational awareness; not always tied to a defensive action.',
    relevance: 'Skim for context. Escalate if it intersects an asset you operate or a vendor you depend on.',
  },
  advisory: {
    why: 'Authoritative advisory from a CERT/CSIRT or vendor security team. Often correlates to active exploitation.',
    relevance: 'Cross-reference UASF Targets and Tech Intelligence — if affected products are detected on your surface, prioritize the patch window.',
  },
  'vendor-research': {
    why: 'Original threat-research publication. Tradecraft, IOCs, and detections live here first.',
    relevance: 'Mine for IOCs to feed into UASF IOC & Threat Context, and for detections you can replay against your assets.',
  },
  breach: {
    why: 'Confirmed compromise of an identifiable organization. Useful for posture benchmarking and supply-chain risk.',
    relevance: 'If the breached party is a vendor or partner, walk the integration trust boundaries before the next assessment cycle.',
  },
  malware: {
    why: 'New or evolved malware family — payload behavior, persistence, lateral movement.',
    relevance: 'Translate the tradecraft into UASF Scenario Catalog and WAAP Validation cases relevant to your control set.',
  },
  'threat-actor': {
    why: 'Activity attributed to a specific group/cluster. Often comes with TTP-mapping to MITRE ATT&CK.',
    relevance: 'Compare against your detection coverage map; if the actor targets your sector, treat as a planning input.',
  },
  vulnerability: {
    why: 'Specific CVE / weakness disclosed. Severity, exploitability, and exposure are the questions.',
    relevance: 'Pivot through UASF CVE Intelligence to verify whether any tracked dependency or fingerprint is affected.',
  },
  cloud: {
    why: 'Cloud-platform misconfiguration or platform-level vulnerability.',
    relevance: 'Correlate against your cloud baseline. Most issues here are configuration drift, not patch-driven.',
  },
  'supply-chain': {
    why: 'Compromise via a third-party component, package, or vendor.',
    relevance: 'Walk the SBOM. UASF CVE Intelligence + dependency fingerprints will flag the affected install footprint.',
  },
  identity: {
    why: 'Identity / authentication weakness — MFA, OAuth, session, federation.',
    relevance: 'Likely impacts more than the disclosing vendor. Check identity-provider posture and recent reset/recovery flows.',
  },
  appsec: {
    why: 'Web/app vulnerability class — OWASP-style flaw with concrete payload examples.',
    relevance: 'Translate the payload into a UASF WAAP Validation scenario and replay against the in-scope app.',
  },
  'data-leak': {
    why: 'Exposed data store / scraped corpus / inadvertent disclosure.',
    relevance: 'Check whether your domains, customers, or staff appear in the dataset; rotate secrets if applicable.',
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fullDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

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
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const NewsArticleDetail = () => {
  const { id = '' } = useParams<{ id: string }>();
  const [data, setData] = useState<DetailPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setData(null);
    void (async () => {
      try {
        const result = await apiFetchJson<DetailPayload>(`/news/article/${id}`);
        if (!cancelled) setData(result.data);
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 404) {
          setError('This article is no longer available. It may have rolled off the feed.');
        } else if (e instanceof ApiError) {
          setError(e.message);
        } else {
          setError(e instanceof Error ? e.message : 'Failed to load article.');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  // -------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-[#94a3b8]">
        <Loader2 size={28} className="animate-spin text-[#8e51df] mb-3" />
        <p className="text-sm">Loading article…</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="space-y-4">
        <Link
          to="/news"
          className="inline-flex items-center gap-1.5 text-sm text-[#94a3b8] hover:text-white"
        >
          <ArrowLeft size={14} /> Back to feed
        </Link>
        <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-4 py-6 text-center">
          <ShieldAlert size={28} className="mx-auto text-rose-300 mb-2" />
          <div className="text-rose-100 font-semibold">Article unavailable</div>
          <div className="text-sm text-rose-200/80 mt-1">{error}</div>
        </div>
      </div>
    );
  }

  const { article, source, cluster, related } = data;
  const narrative = TYPE_NARRATIVE[article.articleType];

  return (
    <article className="space-y-6 max-w-[1200px]">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-1 text-xs text-[#94a3b8]">
        <Link to="/news" className="inline-flex items-center gap-1 hover:text-white">
          <ArrowLeft size={12} /> News & Intelligence
        </Link>
        <ChevronRight size={12} />
        <span className="text-[#cbd5e1]">{article.sourceName}</span>
        <ChevronRight size={12} />
        <span className="text-white truncate max-w-[420px]">{article.title}</span>
      </nav>

      {/* HERO */}
      <header className="rounded-xl border border-[#2d333b] bg-gradient-to-br from-[#1a1d24] via-[#161922] to-[#0f1115] overflow-hidden">
        <div className="px-6 py-6 sm:px-8 sm:py-8 space-y-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] uppercase tracking-wider font-semibold ${
                  TYPE_TONE[article.articleType]
                }`}
              >
                {TYPE_LABELS[article.articleType]}
              </span>
              {source && (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-[#2d333b] bg-[#0f1115] text-[10px] uppercase tracking-wider font-semibold text-[#cbd5e1]">
                  {CATEGORY_LABEL[source.category]} · {source.reputation}-tier
                </span>
              )}
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-[#2d333b] bg-[#0f1115] text-[10px] uppercase tracking-wider font-semibold text-[#cbd5e1]">
                <Clock size={10} /> {article.readingMinutes}m read
              </span>
            </div>
            {cluster.length > 0 && (
              <span className="inline-flex items-center gap-1.5 text-xs text-[#c8a8ff]">
                <Layers size={12} /> Also covered by {cluster.length} other{' '}
                {cluster.length === 1 ? 'source' : 'sources'}
              </span>
            )}
          </div>

          <h1 className="text-2xl sm:text-3xl font-bold text-white leading-tight">
            {article.title}
          </h1>

          <div className="flex items-center justify-between gap-3 flex-wrap text-xs text-[#94a3b8]">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="inline-flex items-center gap-1.5">
                <Newspaper size={12} className="text-[#8e51df]" />
                <span className="font-semibold text-white">{article.sourceName}</span>
              </span>
              {article.author && (
                <span className="inline-flex items-center gap-1.5">
                  <User size={12} /> {article.author}
                </span>
              )}
              <span className="inline-flex items-center gap-1.5">
                <Calendar size={12} />
                {fullDate(article.publishedAt)} · {timeAgo(article.publishedAt)}
              </span>
            </div>
            <a
              href={article.canonicalUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#6a2bba] text-white text-xs font-semibold hover:bg-[#7c39d2]"
            >
              <ExternalLink size={12} /> Read on {hostOf(article.canonicalUrl)}
            </a>
          </div>
        </div>
      </header>

      {/* TWO COLUMN BODY */}
      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* MAIN COLUMN */}
        <div className="space-y-4 min-w-0">
          {/* Summary */}
          {article.summary && (
            <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-5">
              <h2 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-2 flex items-center gap-2">
                <Quote size={12} /> Normalized summary
              </h2>
              <p className="text-[15px] text-[#e2e8f0] leading-relaxed">{article.summary}</p>
              <p className="mt-3 text-[11px] text-[#64748b]">
                Internal normalization for fast triage. Full article is on{' '}
                <a
                  href={article.canonicalUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#c8a8ff] hover:text-white underline underline-offset-2"
                >
                  {hostOf(article.canonicalUrl)}
                </a>
                .
              </p>
            </section>
          )}

          {/* Key takeaways */}
          {article.keyTakeaways && article.keyTakeaways.length > 0 && (
            <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-5">
              <h2 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-3 flex items-center gap-2">
                <Sparkles size={12} className="text-[#8e51df]" /> Key takeaways
              </h2>
              <ul className="space-y-2">
                {article.keyTakeaways.map((t, idx) => (
                  <li key={idx} className="flex gap-2 text-sm text-[#cbd5e1]">
                    <span className="shrink-0 w-5 h-5 rounded-full bg-[#6a2bba]/20 border border-[#6a2bba]/40 text-[#c8a8ff] text-xs font-bold flex items-center justify-center mt-0.5">
                      {idx + 1}
                    </span>
                    <span>{t}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Why this matters */}
          <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-5">
            <h2 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-3 flex items-center gap-2">
              <Target size={12} className="text-[#8e51df]" /> Why this matters / Operator relevance
            </h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <div className="text-[10px] uppercase tracking-widest text-[#94a3b8] font-semibold mb-1">
                  Why this matters
                </div>
                <p className="text-sm text-[#cbd5e1] leading-relaxed">{narrative.why}</p>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-widest text-[#94a3b8] font-semibold mb-1">
                  Operator relevance
                </div>
                <p className="text-sm text-[#cbd5e1] leading-relaxed">{narrative.relevance}</p>
              </div>
            </div>
          </section>

          {/* Cluster (other coverage) */}
          {cluster.length > 0 && (
            <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-5">
              <h2 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-3 flex items-center gap-2">
                <Layers size={12} className="text-[#8e51df]" /> Other coverage of this story
              </h2>
              <ul className="divide-y divide-[#2d333b]">
                {cluster.map((c) => (
                  <li key={c.id} className="py-2 first:pt-0 last:pb-0">
                    <Link
                      to={`/news/${c.id}`}
                      className="flex items-start justify-between gap-3 group"
                    >
                      <div className="min-w-0">
                        <div className="text-sm text-white group-hover:text-[#c8a8ff] line-clamp-2">
                          {c.title}
                        </div>
                        <div className="text-[11px] text-[#94a3b8] mt-0.5">
                          {c.sourceName} · {timeAgo(c.publishedAt)}
                        </div>
                      </div>
                      <ChevronRight size={14} className="text-[#475569] shrink-0 mt-1" />
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Related */}
          {related.length > 0 && (
            <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-5">
              <h2 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-3 flex items-center gap-2">
                <Newspaper size={12} className="text-[#8e51df]" /> Related — same theme
              </h2>
              <ul className="grid gap-3 sm:grid-cols-2">
                {related.map((r) => (
                  <li key={r.id}>
                    <Link
                      to={`/news/${r.id}`}
                      className="block bg-[#0f1115] border border-[#2d333b] rounded-md p-3 hover:border-[#6a2bba]/60 transition-colors"
                    >
                      <div className="text-[10px] text-[#94a3b8] mb-1.5 flex items-center gap-2">
                        <span
                          className={`inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] uppercase tracking-wide font-semibold ${
                            TYPE_TONE[r.articleType]
                          }`}
                        >
                          {TYPE_LABELS[r.articleType]}
                        </span>
                        <span>{timeAgo(r.publishedAt)}</span>
                      </div>
                      <div className="text-sm text-white line-clamp-2 leading-snug">{r.title}</div>
                      <div className="mt-1.5 text-[11px] text-[#94a3b8]">{r.sourceName}</div>
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>

        {/* SIDEBAR */}
        <aside className="space-y-4">
          {/* Source attribution */}
          {source && (
            <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-4">
              <h3 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-2">
                Source attribution
              </h3>
              <div className="text-sm font-semibold text-white">{source.name}</div>
              {source.description && (
                <p className="text-xs text-[#cbd5e1] mt-1.5 leading-relaxed">
                  {source.description}
                </p>
              )}
              <div className="mt-3 flex items-center justify-between text-[11px] text-[#94a3b8]">
                <span>
                  {CATEGORY_LABEL[source.category]} · {source.reputation}-tier
                </span>
                {source.homepageUrl && (
                  <a
                    href={source.homepageUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 hover:text-white"
                  >
                    <ExternalLink size={11} /> Publisher
                  </a>
                )}
              </div>
            </section>
          )}

          {/* CVE references */}
          {article.cveIds && article.cveIds.length > 0 && (
            <section className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
              <h3 className="text-xs uppercase tracking-widest text-amber-200 font-semibold mb-2 flex items-center gap-1.5">
                <Bug size={12} /> Referenced CVEs
              </h3>
              <ul className="space-y-1.5">
                {article.cveIds.map((cve) => (
                  <li
                    key={cve}
                    className="flex items-center justify-between text-sm font-mono text-amber-100"
                  >
                    <span>{cve}</span>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] text-amber-200 hover:text-white inline-flex items-center gap-1"
                    >
                      NVD <ExternalLink size={10} />
                    </a>
                  </li>
                ))}
              </ul>
              <Link
                to={`/dependency-risk?q=${encodeURIComponent(article.cveIds[0])}`}
                className="mt-3 inline-flex items-center gap-1 text-xs text-amber-200 hover:text-white"
              >
                Open in CVE Intelligence <ChevronRight size={11} />
              </Link>
            </section>
          )}

          {/* Threat actor refs */}
          {article.actorRefs && article.actorRefs.length > 0 && (
            <section className="rounded-lg border border-orange-500/30 bg-orange-500/5 p-4">
              <h3 className="text-xs uppercase tracking-widest text-orange-200 font-semibold mb-2 flex items-center gap-1.5">
                <Users size={12} /> Threat references
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {article.actorRefs.map((a) => (
                  <span
                    key={a}
                    className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] bg-orange-500/15 border border-orange-500/30 text-orange-100 capitalize"
                  >
                    {a}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Tags */}
          {article.tags && article.tags.length > 0 && (
            <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-4">
              <h3 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-2">
                Tags
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {article.tags.map((t) => (
                  <Link
                    key={t}
                    to={`/news?tag=${encodeURIComponent(t)}`}
                    className="inline-flex items-center px-2 py-0.5 rounded text-[11px] text-[#cbd5e1] bg-[#0f1115] border border-[#2d333b] hover:border-[#6a2bba]/60 hover:text-white"
                  >
                    #{t}
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* Provenance */}
          <section className="rounded-lg border border-[#2d333b] bg-[#161922] p-4 text-xs text-[#94a3b8] space-y-1.5">
            <h3 className="text-xs uppercase tracking-widest text-[#94a3b8] font-semibold mb-1">
              Provenance
            </h3>
            <div>
              <span className="text-[#64748b]">Published</span>{' '}
              <span className="text-[#cbd5e1]">{fullDate(article.publishedAt)}</span>
            </div>
            <div>
              <span className="text-[#64748b]">Ingested</span>{' '}
              <span className="text-[#cbd5e1]">{fullDate(article.ingestedAt)}</span>
            </div>
            <div>
              <span className="text-[#64748b]">Language</span>{' '}
              <span className="text-[#cbd5e1] uppercase">{article.language}</span>
            </div>
            <div className="pt-1 break-words">
              <span className="text-[#64748b]">Canonical</span>{' '}
              <a
                href={article.canonicalUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#c8a8ff] hover:text-white underline underline-offset-2"
              >
                {article.canonicalUrl}
              </a>
            </div>
          </section>
        </aside>
      </div>
    </article>
  );
};

export default NewsArticleDetail;
