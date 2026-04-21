import { useEffect, useMemo, useState } from 'react';
import {
  ShieldAlert,
  RefreshCw,
  Loader2,
  ExternalLink,
  Search,
  ChevronDown,
  AlertTriangle,
} from 'lucide-react';
import { ApiError, apiFetchJson } from '../lib/api';

type Vulnerability = {
  id: string;
  ecosystem: string;
  packageName: string;
  advisoryId: string;
  severityLabel: string;
  severityScore: number | null;
  summary: string;
  details: string | null;
  // The backend stores these as `;`/`,`-joined strings inside a single
  // varchar column, so the wire shape is `string | null`.  The frontend
  // splits on render.  We accept `string[]` defensively in case a future
  // backend version starts returning arrays directly.
  affectedRanges: string | string[] | null;
  fixedVersions: string | string[] | null;
  source: string;
  sourceUrl: string;
  publishedAt: string | null;
  modifiedAt: string | null;
  updatedAt: string;
};

type Summary = {
  total: number;
  bySeverity: Record<string, number>;
  byEcosystem: Record<string, number>;
  lastIngestAt: string | null;
  source?: { name: string; url: string };
};

const severityTone: Record<string, string> = {
  Critical: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  High: 'bg-orange-500/15 text-orange-200 border-orange-500/30',
  Medium: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  Low: 'bg-sky-500/15 text-sky-200 border-sky-500/30',
  Unknown: 'bg-slate-500/15 text-slate-200 border-slate-500/30',
};

const DependencyRisk = () => {
  const [items, setItems] = useState<Vulnerability[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [ecosystem, setEcosystem] = useState<string>('all');
  const [severity, setSeverity] = useState<string>('all');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, sum] = await Promise.all([
        apiFetchJson<{ items: Vulnerability[]; total: number }>('/dependency/vulnerabilities?take=200'),
        apiFetchJson<Summary>('/dependency/summary'),
      ]);
      setItems(Array.isArray(list.data.items) ? list.data.items : []);
      setSummary(sum.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load dependency vulnerabilities.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!cancelled) await load();
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const refresh = async () => {
    setRefreshing(true);
    setError(null);
    try {
      await apiFetchJson('/dependency/refresh', { method: 'POST' });
      await load();
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`Refresh failed: ${e.message}`);
      } else {
        setError(e instanceof Error ? e.message : 'Refresh failed.');
      }
    } finally {
      setRefreshing(false);
    }
  };

  const ecosystems = useMemo(
    () => Array.from(new Set(items.map((i) => i.ecosystem))).sort(),
    [items],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((v) => {
      if (ecosystem !== 'all' && v.ecosystem !== ecosystem) return false;
      if (severity !== 'all' && v.severityLabel !== severity) return false;
      if (!q) return true;
      const hay = `${v.packageName} ${v.advisoryId} ${v.summary} ${v.details ?? ''}`.toLowerCase();
      return hay.includes(q);
    });
  }, [items, search, ecosystem, severity]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <ShieldAlert className="text-[#8e51df]" size={28} />
            Newest CVE intelligence
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Continuously refreshed feed of the most recently disclosed CVEs, sourced from the
            community-maintained{' '}
            <a
              href="https://mycve.com/"
              target="_blank"
              rel="noreferrer"
              className="text-[#a78bfa] hover:underline"
            >
              mycve.com
            </a>{' '}
            tracker. The cache refreshes automatically every 2 hours; click{' '}
            <span className="font-mono">Refresh now</span> to pull the latest batch on demand.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-lg border border-[#8e51df]/40 bg-[#8e51df]/10 px-3 py-2 text-sm text-white hover:bg-[#8e51df]/20 disabled:opacity-50"
        >
          {refreshing ? <Loader2 className="animate-spin" size={16} /> : <RefreshCw size={16} />}
          Refresh now
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <KpiCard label="Total CVEs" value={summary?.total ?? 0} tone="text-white" />
        <KpiCard label="Critical" value={summary?.bySeverity?.Critical ?? 0} tone="text-rose-200" />
        <KpiCard label="High" value={summary?.bySeverity?.High ?? 0} tone="text-orange-200" />
        <KpiCard label="Medium" value={summary?.bySeverity?.Medium ?? 0} tone="text-amber-200" />
        <KpiCard label="Low" value={summary?.bySeverity?.Low ?? 0} tone="text-sky-200" />
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[#2d333b] bg-[#15181e] p-3">
        <div className="relative flex-1 min-w-[260px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by CVE ID, summary…"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#8e51df]/60"
          />
        </div>
        {ecosystems.length > 1 && (
          <FilterSelect
            value={ecosystem}
            onChange={setEcosystem}
            options={[
              { value: 'all', label: 'All ecosystems' },
              ...ecosystems.map((e) => ({ value: e, label: e })),
            ]}
          />
        )}
        <FilterSelect
          value={severity}
          onChange={setSeverity}
          options={[
            { value: 'all', label: 'All severities' },
            { value: 'Critical', label: 'Critical' },
            { value: 'High', label: 'High' },
            { value: 'Medium', label: 'Medium' },
            { value: 'Low', label: 'Low' },
          ]}
        />
        <div className="text-xs text-[#94a3b8] ml-auto">
          {filtered.length} of {items.length}
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100 flex items-start gap-2">
          <AlertTriangle size={16} className="mt-0.5" /> {error}
        </div>
      )}

      {summary?.lastIngestAt && (
        <div className="text-xs text-[#94a3b8]">
          Last refreshed: {new Date(summary.lastIngestAt).toLocaleString()}
        </div>
      )}

      {loading ? (
        <p className="text-[#94a3b8]">Loading vulnerability cache…</p>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-10 text-center text-[#94a3b8]">
          {items.length === 0 ? (
            <>
              <p className="font-semibold text-white">No CVEs cached yet</p>
              <p className="text-sm mt-2 max-w-2xl mx-auto">
                The background scheduler will populate this table automatically every 2 hours. You can
                also click<span className="font-mono"> Refresh now </span>
                to pull the latest batch from the mycve.com feed.
              </p>
            </>
          ) : (
            <p>No CVEs match the current filters.</p>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((v) => (
            <article
              key={v.id}
              className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4 hover:border-[#8e51df]/40"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`text-[10px] uppercase tracking-wider font-bold px-2 py-0.5 rounded-full border ${severityTone[v.severityLabel] ?? severityTone.Unknown}`}
                >
                  {v.severityLabel}
                  {typeof v.severityScore === 'number' ? ` · ${v.severityScore.toFixed(1)}` : ''}
                </span>
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-[#cbd5e1]">
                  {v.ecosystem}
                </span>
                {v.packageName && v.packageName !== v.advisoryId && (
                  <span className="font-bold text-white text-sm">{v.packageName}</span>
                )}
                <a
                  href={v.sourceUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="ml-auto inline-flex items-center gap-1 text-xs text-[#8e51df] hover:text-[#a372eb]"
                >
                  {v.source} <ExternalLink size={12} />
                </a>
              </div>
              <h3 className="text-sm font-semibold text-white mt-2">
                <span className="font-mono text-[#94a3b8] mr-2">{v.advisoryId}</span>
                {v.summary}
              </h3>
              {v.details && (
                <p className="text-xs text-[#94a3b8] mt-2 line-clamp-3">{v.details}</p>
              )}
              {(() => {
                const ranges = toRangeList(v.affectedRanges);
                const fixes = toRangeList(v.fixedVersions);
                if (ranges.length === 0 && fixes.length === 0) return null;
                return (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3 text-[11px]">
                    {ranges.length > 0 && (
                      <KvBlock label="Affected">
                        {ranges.map((r) => (
                          <code
                            key={r}
                            className="block font-mono text-[#fda4af] truncate"
                          >
                            {r}
                          </code>
                        ))}
                      </KvBlock>
                    )}
                    {fixes.length > 0 && (
                      <KvBlock label="Fixed in">
                        {fixes.map((r) => (
                          <code
                            key={r}
                            className="block font-mono text-emerald-300 truncate"
                          >
                            {r}
                          </code>
                        ))}
                      </KvBlock>
                    )}
                  </div>
                );
              })()}
              <div className="flex items-center justify-between text-[10px] text-[#64748b] mt-3 pt-2 border-t border-[#2d333b]">
                <span>
                  Published:{' '}
                  {v.publishedAt ? new Date(v.publishedAt).toLocaleDateString() : '—'} · Modified:{' '}
                  {v.modifiedAt ? new Date(v.modifiedAt).toLocaleDateString() : '—'}
                </span>
                <a
                  href={v.sourceUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 text-[#8e51df] hover:text-[#a372eb]"
                >
                  Learn more <ExternalLink size={12} />
                </a>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
};

/**
 * The backend stores `affectedRanges` / `fixedVersions` as a single
 * varchar containing tokens joined with `;`, `,`, or whitespace.  We
 * normalise to a clean array on render.  If a future API version starts
 * sending real arrays, we accept that too.
 */
function toRangeList(value: string | string[] | null | undefined): string[] {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map((s) => String(s).trim()).filter(Boolean);
  }
  return String(value)
    .split(/[;,]/g)
    .map((s) => s.trim())
    .filter(Boolean);
}

function KpiCard({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
      <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">{label}</div>
      <div className={`text-2xl font-extrabold mt-1 ${tone}`}>{value}</div>
    </div>
  );
}

function KvBlock({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-[#2d333b] bg-[#0b0c10] p-2">
      <div className="text-[10px] uppercase tracking-wider text-[#64748b]">{label}</div>
      <div className="mt-1 space-y-0.5 text-xs">{children}</div>
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <label className="relative">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none pl-3 pr-8 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white focus:outline-none focus:border-[#8e51df]/60"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown
        size={14}
        className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-[#64748b]"
      />
    </label>
  );
}

export default DependencyRisk;
