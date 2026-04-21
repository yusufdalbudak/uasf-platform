import { Fragment, useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, History, RefreshCcw } from 'lucide-react';
import { apiFetchJson } from '../lib/api';

type RunSummary = Record<string, unknown> | null;

type Run = {
  id: string;
  externalRunId: string | null;
  label: string;
  status: string;
  startedAt: string | null;
  completedAt: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  campaign?: { id: string; name: string } | null;
  asset?: { id: string; hostname: string; displayName?: string | null } | null;
  scenario?: { id: string; name: string; category: string | null } | null;
  targetHostname?: string | null;
  summary?: RunSummary;
};

const STATUS_TONE: Record<string, string> = {
  queued: 'bg-sky-500/10 text-sky-300 border-sky-500/30',
  running: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  completed: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  partial: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30',
  failed: 'bg-red-500/10 text-red-300 border-red-500/30',
};

const Runs = () => {
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const loadRuns = async (silent = false) => {
    if (silent) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);
    try {
      const { data } = await apiFetchJson<{ runs?: Run[] }>('/runs');
      setRuns(data.runs ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load runs.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void loadRuns(false);
    const intervalId = window.setInterval(() => void loadRuns(true), 15000);
    return () => window.clearInterval(intervalId);
  }, []);

  const stats = useMemo(() => {
    const total = runs.length;
    const completed = runs.filter((r) => r.status === 'completed').length;
    const running = runs.filter((r) => r.status === 'running' || r.status === 'queued').length;
    const partial = runs.filter((r) => r.status === 'partial' || r.status === 'failed').length;
    return { total, completed, running, partial };
  }, [runs]);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <History className="text-[#8e51df]" size={28} />
            Assessment runs
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Every campaign launch creates an assessment run. Each row links the originating
            scenario, the target asset, and the live execution summary captured by the worker.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadRuns(true)}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-lg border border-[#2d333b] bg-[#15181e] px-3 py-2 text-sm text-[#cbd5e1] hover:border-[#8e51df]/50 disabled:opacity-50"
        >
          <RefreshCcw size={14} className={refreshing ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatTile label="Total runs" value={stats.total} tone="text-white" />
        <StatTile label="Completed" value={stats.completed} tone="text-emerald-300" />
        <StatTile label="In progress" value={stats.running} tone="text-amber-300" />
        <StatTile label="Partial / failed" value={stats.partial} tone="text-rose-300" />
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-[#94a3b8]">Loading…</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
          <table className="w-full text-sm">
            <thead className="border-b border-[#2d333b] text-[#94a3b8] text-xs uppercase tracking-[0.16em]">
              <tr>
                <th className="px-4 py-3 text-left w-8" />
                <th className="px-4 py-3 text-left">Run</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Asset</th>
                <th className="px-4 py-3 text-left">Campaign / Scenario</th>
                <th className="px-4 py-3 text-left">Started</th>
                <th className="px-4 py-3 text-left">Completed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d333b]">
              {runs.map((r) => {
                const scenarioLabel =
                  r.campaign?.name ??
                  r.scenario?.name ??
                  (typeof r.summary?.scenarioName === 'string'
                    ? (r.summary.scenarioName as string)
                    : null);
                const scenarioCategory = r.scenario?.category ?? null;
                const assetLabel =
                  r.asset?.hostname ?? r.targetHostname ?? r.asset?.displayName ?? null;
                const tone = STATUS_TONE[r.status] ?? 'bg-[#2d333b] text-[#cbd5e1] border-[#3b4451]';
                const isOpen = !!expanded[r.id];
                return (
                  <Fragment key={r.id}>
                    <tr
                      className="hover:bg-[#1a1d24]/80 cursor-pointer"
                      onClick={() => setExpanded((c) => ({ ...c, [r.id]: !c[r.id] }))}
                    >
                      <td className="px-4 py-3 text-[#94a3b8]">
                        {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td className="px-4 py-3 text-white font-medium">
                        <div className="truncate max-w-[280px]" title={r.label}>
                          {r.label}
                        </div>
                        {r.externalRunId && (
                          <div className="text-[10px] text-[#64748b] font-mono mt-0.5">
                            {r.externalRunId}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.14em] ${tone}`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-[#cbd5e1]">
                        {assetLabel ?? '—'}
                      </td>
                      <td className="px-4 py-3">
                        {scenarioLabel ? (
                          <div>
                            <div className="text-white font-medium">{scenarioLabel}</div>
                            {scenarioCategory && (
                              <div className="text-[10px] text-[#64748b] uppercase tracking-[0.14em] mt-0.5">
                                {scenarioCategory}
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-[#64748b]">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-[#94a3b8] text-xs">
                        {r.startedAt ? new Date(r.startedAt).toLocaleString() : '—'}
                      </td>
                      <td className="px-4 py-3 text-[#94a3b8] text-xs">
                        {r.completedAt ? new Date(r.completedAt).toLocaleString() : '—'}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="bg-[#10131a]">
                        <td colSpan={7} className="px-4 py-4">
                          <RunDetailPanel run={r} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          {runs.length === 0 && (
            <p className="p-8 text-center text-[#64748b]">No runs yet.</p>
          )}
        </div>
      )}
    </div>
  );
};

function StatTile(props: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
      <div className="text-[10px] uppercase tracking-[0.16em] text-[#94a3b8]">{props.label}</div>
      <div className={`text-2xl font-bold mt-1 ${props.tone}`}>{props.value}</div>
    </div>
  );
}

function RunDetailPanel({ run }: { run: Run }) {
  const summary = (run.summary ?? {}) as Record<string, unknown>;
  const num = (k: string) => (typeof summary[k] === 'number' ? (summary[k] as number) : null);
  const str = (k: string) => (typeof summary[k] === 'string' ? (summary[k] as string) : null);
  const arr = (k: string) => (Array.isArray(summary[k]) ? (summary[k] as unknown[]) : []);
  const verdictCounts = (summary.verdictCounts ?? {}) as Record<string, number>;
  const expectationCounts = (summary.expectationCounts ?? {}) as Record<string, number>;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs">
      <div className="space-y-2">
        <div className="text-[10px] uppercase tracking-[0.16em] text-[#64748b]">Execution</div>
        <KV k="Requested jobs" v={num('requestedJobs')} />
        <KV k="Completed jobs" v={num('completedJobs')} />
        <KV k="Blocked jobs" v={num('blockedJobs')} />
        <KV k="Allowed jobs" v={num('allowedJobs')} />
        <KV k="Error jobs" v={num('errorJobs')} />
        <KV k="Latest status" v={num('latestStatusCode')} />
        <KV k="Latest verdict" v={str('latestVerdict')} />
      </div>
      <div className="space-y-2">
        <div className="text-[10px] uppercase tracking-[0.16em] text-[#64748b]">Verdict mix</div>
        {Object.entries(verdictCounts).map(([k, v]) => (
          <KV key={k} k={k} v={v} />
        ))}
        {Object.keys(verdictCounts).length === 0 && (
          <div className="text-[#64748b]">No verdicts recorded yet.</div>
        )}
      </div>
      <div className="space-y-2">
        <div className="text-[10px] uppercase tracking-[0.16em] text-[#64748b]">
          Expectation mix
        </div>
        {Object.entries(expectationCounts).map(([k, v]) => (
          <KV key={k} k={k} v={v} />
        ))}
        {Object.keys(expectationCounts).length === 0 && (
          <div className="text-[#64748b]">No expectation evaluations recorded yet.</div>
        )}
        <div className="pt-3 mt-3 border-t border-[#2d333b]">
          <div className="text-[10px] uppercase tracking-[0.16em] text-[#64748b]">
            Queued job ids ({arr('queuedJobIds').length})
          </div>
          <div className="font-mono text-[10px] text-[#94a3b8] break-all mt-1 leading-relaxed">
            {arr('queuedJobIds')
              .slice(0, 12)
              .map((id) => String(id))
              .join(', ') || '—'}
          </div>
        </div>
      </div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: unknown }) {
  return (
    <div className="flex justify-between items-baseline gap-3">
      <span className="text-[#94a3b8] capitalize">{k.replace(/_/g, ' ')}</span>
      <span className="text-white font-mono">{v == null ? '—' : String(v)}</span>
    </div>
  );
}

export default Runs;
