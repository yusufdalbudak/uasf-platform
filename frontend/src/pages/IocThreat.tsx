import { useEffect, useMemo, useState } from 'react';
import {
  Globe2,
  Loader2,
  RefreshCw,
  Search,
  ChevronDown,
  ExternalLink,
  AlertTriangle,
} from 'lucide-react';
import { ApiError, apiFetchJson } from '../lib/api';
import MultiLookupCard from '../components/MultiLookupCard';

type Indicator = {
  id: string;
  indicator: string;
  indicatorType: string;
  threatLabel: string | null;
  confidence: string | null;
  source: string;
  sourceName: string | null;
  sourceUrl: string | null;
  notes: string | null;
  occurrences: number;
  firstSeen: string;
  lastSeen: string;
};

type Summary = {
  total: number;
  byType: Record<string, number>;
  bySource: Record<string, number>;
  lastIngestAt: string | null;
  source?: { name: string; url: string };
};

const SOURCE_LABELS: Record<string, string> = {
  github_advisories: 'GitHub Advisory',
  openphish: 'OpenPhish',
  threatfox: 'abuse.ch ThreatFox',
};

const TYPE_LABELS: Record<string, string> = {
  ghsa: 'GHSA',
  cve: 'CVE',
  url: 'URL',
  domain: 'Domain',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  sha256: 'SHA-256',
  sha1: 'SHA-1',
  md5: 'MD5',
  email: 'Email',
};

const labelForSource = (item: Indicator | undefined, sourceId: string): string =>
  SOURCE_LABELS[sourceId] ?? item?.sourceName ?? sourceId;

const labelForType = (typeId: string): string =>
  TYPE_LABELS[typeId.toLowerCase()] ?? typeId.toUpperCase();

const confidenceTone = (confidence: string | null): string => {
  switch ((confidence ?? '').toLowerCase()) {
    case 'high':
      return 'bg-rose-500/20 text-rose-200 border-rose-500/30';
    case 'medium':
      return 'bg-amber-500/20 text-amber-200 border-amber-500/30';
    case 'low':
      return 'bg-sky-500/20 text-sky-200 border-sky-500/30';
    default:
      return 'bg-slate-500/20 text-slate-200 border-slate-500/30';
  }
};

const IocThreat = () => {
  const [items, setItems] = useState<Indicator[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [type, setType] = useState<string>('all');
  const [source, setSource] = useState<string>('all');

  const loadList = async (opts: { source: string; type: string }) => {
    const params = new URLSearchParams({ take: '500' });
    if (opts.source !== 'all') params.set('source', opts.source);
    if (opts.type !== 'all') params.set('type', opts.type);
    const list = await apiFetchJson<{ items: Indicator[]; total: number }>(
      `/ioc/indicators?${params.toString()}`,
    );
    return Array.isArray(list.data.items) ? list.data.items : [];
  };

  const load = async (opts?: { source?: string; type?: string }) => {
    setLoading(true);
    setError(null);
    try {
      const [rows, sum] = await Promise.all([
        loadList({ source: opts?.source ?? source, type: opts?.type ?? type }),
        apiFetchJson<Summary>('/ioc/summary'),
      ]);
      setItems(rows);
      setSummary(sum.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load IOC indicators.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!cancelled) await load({ source, type });
    })();
    return () => {
      cancelled = true;
    };
    // Re-fetch whenever the server-side filters change so picking a source
    // pulls rows for that source even when the unfiltered page is dominated
    // by another (e.g. 300 OpenPhish rows vs 129 GitHub Advisory rows).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, type]);

  const refresh = async () => {
    setRefreshing(true);
    setError(null);
    try {
      await apiFetchJson('/ioc/refresh', { method: 'POST' });
      await load();
    } catch (e) {
      if (e instanceof ApiError) setError(`Refresh failed: ${e.message}`);
      else setError(e instanceof Error ? e.message : 'Refresh failed.');
    } finally {
      setRefreshing(false);
    }
  };

  // Dropdown options come from the summary (which always reflects every row in
  // the database) rather than the currently-rendered page, so every known
  // source/type stays selectable regardless of pagination.
  const typeOptions = useMemo(() => {
    const ids = Object.keys(summary?.byType ?? {});
    if (ids.length === 0) {
      return Array.from(new Set(items.map((i) => i.indicatorType))).map((id) => ({
        value: id,
        label: labelForType(id),
      }));
    }
    return ids
      .map((id) => ({ value: id, label: labelForType(id) }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [summary, items]);

  const sourceOptions = useMemo(() => {
    const ids = Object.keys(summary?.bySource ?? {});
    if (ids.length === 0) {
      const seen = new Map<string, string>();
      for (const i of items) {
        if (!seen.has(i.source)) seen.set(i.source, labelForSource(i, i.source));
      }
      return Array.from(seen.entries()).map(([value, label]) => ({ value, label }));
    }
    return ids
      .map((id) => {
        const sample = items.find((i) => i.source === id);
        return { value: id, label: labelForSource(sample, id) };
      })
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [summary, items]);

  // Server already applies source/type filters, so the client-side pass only
  // needs the free-text search.
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((i) => {
      const hay = `${i.indicator} ${i.threatLabel ?? ''} ${i.notes ?? ''}`.toLowerCase();
      return hay.includes(q);
    });
  }, [items, search]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Globe2 className="text-[#8e51df]" size={28} />
            IOC &amp; threat context
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Indicators normalized from three public sources, refreshed every 2h:{' '}
            <a
              href="https://github.com/advisories"
              target="_blank"
              rel="noreferrer"
              className="text-[#a78bfa] hover:underline"
            >
              GitHub Advisory Database
            </a>{' '}
            (GHSA / CVE identifiers),{' '}
            <a
              href="https://openphish.com/"
              target="_blank"
              rel="noreferrer"
              className="text-[#a78bfa] hover:underline"
            >
              OpenPhish Community Feed
            </a>{' '}
            (active phishing URLs), and{' '}
            <a
              href="https://threatfox.abuse.ch/browse/"
              target="_blank"
              rel="noreferrer"
              className="text-[#a78bfa] hover:underline"
            >
              abuse.ch ThreatFox
            </a>{' '}
            (malware-attributed URLs / domains / hashes). Each row links back to the upstream
            record so operators can review the family attribution, affected ecosystems, severity,
            hosting, and remediation.
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

      <MultiLookupCard />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
          <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">
            Total indicators
          </div>
          <div className="text-2xl font-extrabold text-white mt-1">{summary?.total ?? 0}</div>
        </div>
        <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
          <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">Indicator types</div>
          <div className="text-2xl font-extrabold text-violet-200 mt-1">
            {Object.keys(summary?.byType ?? {}).length}
          </div>
        </div>
        <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
          <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">Sources</div>
          <div className="text-2xl font-extrabold text-sky-200 mt-1">
            {Object.keys(summary?.bySource ?? {}).length}
          </div>
        </div>
        <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
          <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">Last refresh</div>
          <div className="text-sm font-mono text-white mt-2">
            {summary?.lastIngestAt
              ? new Date(summary.lastIngestAt).toLocaleString()
              : '—'}
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[#2d333b] bg-[#15181e] p-3">
        <div className="relative flex-1 min-w-[260px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search indicator, threat, notes…"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#8e51df]/60"
          />
        </div>
        <FilterSelect
          value={type}
          onChange={setType}
          options={[{ value: 'all', label: 'All indicator types' }, ...typeOptions]}
        />
        <FilterSelect
          value={source}
          onChange={setSource}
          options={[{ value: 'all', label: 'All sources' }, ...sourceOptions]}
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

      {loading ? (
        <p className="text-[#94a3b8]">Loading indicator feed…</p>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-10 text-center text-[#94a3b8]">
          {items.length === 0 ? (
            <>
              <p className="font-semibold text-white">No IOC indicators ingested yet</p>
              <p className="text-sm mt-2 max-w-2xl mx-auto">
                The background scheduler ingests the GitHub Advisory Database, OpenPhish Community
                Feed, and abuse.ch ThreatFox every 2 hours. Click
                <span className="font-mono"> Refresh now </span>
                to pull the latest snapshot immediately.
              </p>
            </>
          ) : (
            <p>No indicators match the current filters.</p>
          )}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
          <table className="w-full text-sm">
            <thead className="border-b border-[#2d333b] text-[#94a3b8] uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3 text-left">Indicator</th>
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Threat</th>
                <th className="px-4 py-3 text-left">Confidence</th>
                <th className="px-4 py-3 text-left">Source</th>
                <th className="px-4 py-3 text-left">Seen</th>
                <th className="px-4 py-3 text-left">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d333b]">
              {filtered.map((i) => (
                <tr key={i.id} className="hover:bg-[#1a1d24]/80">
                  <td className="px-4 py-3 max-w-[28rem]">
                    <code className="font-mono text-emerald-300 text-xs break-all">
                      {i.indicator}
                    </code>
                    {i.notes && (
                      <div className="text-[10px] text-[#94a3b8] mt-1 truncate">{i.notes}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    <span className="font-mono px-2 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-[#cbd5e1]">
                      {labelForType(i.indicatorType)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#cbd5e1]">{i.threatLabel ?? '—'}</td>
                  <td className="px-4 py-3 text-xs">
                    {i.confidence ? (
                      <span className={`px-2 py-0.5 rounded border text-[10px] ${confidenceTone(i.confidence)}`}>
                        {i.confidence}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {i.sourceUrl ? (
                      <a
                        href={i.sourceUrl}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 text-[#8e51df] hover:text-[#a372eb]"
                      >
                        {labelForSource(i, i.source)} <ExternalLink size={12} />
                      </a>
                    ) : (
                      <span className="text-[#cbd5e1]">{labelForSource(i, i.source)}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-[#cbd5e1] font-mono">{i.occurrences}</td>
                  <td className="px-4 py-3 text-xs text-[#94a3b8] whitespace-nowrap">
                    {new Date(i.lastSeen).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

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

export default IocThreat;
