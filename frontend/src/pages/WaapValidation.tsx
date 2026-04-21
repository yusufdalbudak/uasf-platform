import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  RefreshCw,
  ArrowRight,
} from 'lucide-react';
import { apiFetchJson } from '../lib/api';

type Verdict =
  | 'blocked'
  | 'challenged'
  | 'edge_mitigated'
  | 'origin_rejected'
  | 'allowed'
  | 'network_error'
  | 'ambiguous';

type ExpectationOutcome = 'matched' | 'partially_matched' | 'mismatched' | 'ambiguous';

type ActivityRun = {
  runId: string;
  externalRunId: string;
  status: string;
  targetHostname: string;
  scenarioId: string;
  scenarioName: string;
  scenarioCategory: string;
  requestedJobs: number;
  completedJobs: number;
  blockedJobs: number;
  allowedJobs: number;
  errorJobs: number;
  verdictCounts?: Partial<Record<Verdict, number>>;
  expectationCounts?: Partial<Record<ExpectationOutcome, number>>;
  startedAt: string | null;
  completedAt: string | null;
  events: Array<{ verdict?: string; expectationOutcome?: string }>;
};

const verdictTone: Record<Verdict, string> = {
  blocked: 'text-rose-300 bg-rose-500/10 border-rose-500/30',
  challenged: 'text-amber-200 bg-amber-500/10 border-amber-500/30',
  edge_mitigated: 'text-violet-200 bg-violet-500/10 border-violet-500/30',
  origin_rejected: 'text-rose-200 bg-rose-500/10 border-rose-500/30',
  allowed: 'text-emerald-200 bg-emerald-500/10 border-emerald-500/30',
  network_error: 'text-orange-200 bg-orange-500/10 border-orange-500/30',
  ambiguous: 'text-slate-200 bg-slate-500/10 border-slate-500/30',
};

const expectationTone: Record<ExpectationOutcome, { label: string; tone: string }> = {
  matched: { label: 'Matched', tone: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30' },
  partially_matched: {
    label: 'Partially matched',
    tone: 'text-amber-200 bg-amber-500/10 border-amber-500/30',
  },
  mismatched: { label: 'Mismatched', tone: 'text-rose-200 bg-rose-500/10 border-rose-500/30' },
  ambiguous: { label: 'Ambiguous', tone: 'text-slate-200 bg-slate-500/10 border-slate-500/30' },
};

const formatLabel = (value: string) => value.replace(/_/g, ' ');

const WaapValidation = () => {
  const [runs, setRuns] = useState<ActivityRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const { data } = await apiFetchJson<{ runs?: ActivityRun[] }>(
        '/campaigns/activity?take=12',
      );
      setRuns(Array.isArray(data.runs) ? data.runs : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load WAAP validation telemetry.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!cancelled) await load();
    })();
    const id = window.setInterval(() => void load(true), 8000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const aggregate = useMemo(() => {
    const verdicts: Record<Verdict, number> = {
      blocked: 0,
      challenged: 0,
      edge_mitigated: 0,
      origin_rejected: 0,
      allowed: 0,
      network_error: 0,
      ambiguous: 0,
    };
    const expectations: Record<ExpectationOutcome, number> = {
      matched: 0,
      partially_matched: 0,
      mismatched: 0,
      ambiguous: 0,
    };
    for (const run of runs) {
      for (const event of run.events ?? []) {
        const v = (event.verdict ?? '') as Verdict;
        if (v in verdicts) verdicts[v] += 1;
        const e = (event.expectationOutcome ?? '') as ExpectationOutcome;
        if (e in expectations) expectations[e] += 1;
      }
    }
    const totalEvents = Object.values(verdicts).reduce((a, b) => a + b, 0);
    const protectiveEvents =
      verdicts.blocked + verdicts.challenged + verdicts.edge_mitigated + verdicts.origin_rejected;
    const protectionRatio = totalEvents === 0 ? 0 : Math.round((protectiveEvents / totalEvents) * 100);
    const expectationTotal = Object.values(expectations).reduce((a, b) => a + b, 0);
    const expectationMatched = expectations.matched + expectations.partially_matched;
    const expectationRatio =
      expectationTotal === 0 ? 0 : Math.round((expectationMatched / expectationTotal) * 100);
    return { verdicts, expectations, protectionRatio, expectationRatio, totalEvents };
  }, [runs]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Shield className="text-[#8e51df]" size={28} />
            WAAP validation
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Cross-campaign view of how upstream WAF / WAAP / edge controls are responding to UASF
            scenario traffic. Verdicts are computed by the UASF verdict engine — never by HTTP
            status alone — so challenge, edge mitigation, and origin rejection are visible
            independently of pass-through allows.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void load(true)}
            disabled={refreshing}
            className="inline-flex items-center gap-2 rounded-lg border border-[#2d333b] bg-[#15181e] px-3 py-2 text-sm text-[#cbd5e1] hover:bg-[#1e232b] disabled:opacity-50"
          >
            {refreshing ? <Loader2 className="animate-spin" size={16} /> : <RefreshCw size={16} />}
            Refresh
          </button>
          <Link
            to="/campaigns"
            className="inline-flex items-center gap-2 rounded-lg border border-[#8e51df]/40 bg-[#8e51df]/10 px-3 py-2 text-sm text-[#cbd5e1] hover:bg-[#8e51df]/20"
          >
            Launch validation campaign
            <ArrowRight size={14} />
          </Link>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-[#2d333b] bg-[#15181e] p-5">
          <div className="flex items-center gap-2 text-[#8e51df] mb-3">
            <ShieldCheck size={18} />
            <h2 className="font-bold text-white">Upstream protection ratio</h2>
          </div>
          <div className="flex items-baseline gap-3">
            <div className="text-5xl font-extrabold text-emerald-300">
              {aggregate.protectionRatio}%
            </div>
            <div className="text-xs text-[#94a3b8] uppercase tracking-wider">
              of {aggregate.totalEvents} events
            </div>
          </div>
          <div className="mt-2 h-2 rounded-full bg-[#0b0c10] overflow-hidden border border-[#2d333b]">
            <div
              className="h-full bg-gradient-to-r from-emerald-500 to-emerald-300"
              style={{ width: `${aggregate.protectionRatio}%` }}
            />
          </div>
          <p className="text-xs text-[#94a3b8] mt-3">
            Counts events whose verdict is blocked, challenged, edge-mitigated, or origin-rejected.
            Pass-through allows are excluded.
          </p>
        </div>
        <div className="rounded-2xl border border-[#2d333b] bg-[#15181e] p-5">
          <div className="flex items-center gap-2 text-[#8e51df] mb-3">
            <CheckCircle2 size={18} />
            <h2 className="font-bold text-white">Expectation conformance</h2>
          </div>
          <div className="flex items-baseline gap-3">
            <div className="text-5xl font-extrabold text-sky-300">
              {aggregate.expectationRatio}%
            </div>
            <div className="text-xs text-[#94a3b8] uppercase tracking-wider">
              of evaluated events
            </div>
          </div>
          <div className="mt-2 h-2 rounded-full bg-[#0b0c10] overflow-hidden border border-[#2d333b]">
            <div
              className="h-full bg-gradient-to-r from-sky-500 to-sky-300"
              style={{ width: `${aggregate.expectationRatio}%` }}
            />
          </div>
          <p className="text-xs text-[#94a3b8] mt-3">
            Share of events whose observed verdict satisfied the scenario expectation
            (fully or partially).
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-7 gap-2">
        {(Object.keys(aggregate.verdicts) as Verdict[]).map((verdict) => (
          <div
            key={verdict}
            className={`rounded-xl border px-3 py-3 ${verdictTone[verdict]}`}
          >
            <div className="text-[10px] uppercase tracking-wider opacity-80">
              {formatLabel(verdict)}
            </div>
            <div className="text-2xl font-extrabold mt-1">{aggregate.verdicts[verdict]}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {(Object.keys(aggregate.expectations) as ExpectationOutcome[]).map((outcome) => (
          <div
            key={outcome}
            className={`rounded-xl border px-3 py-3 ${expectationTone[outcome].tone}`}
          >
            <div className="text-[10px] uppercase tracking-wider opacity-80">
              {expectationTone[outcome].label}
            </div>
            <div className="text-2xl font-extrabold mt-1">
              {aggregate.expectations[outcome]}
            </div>
          </div>
        ))}
      </div>

      <h2 className="text-xl font-bold text-white mt-2">Recent campaign runs</h2>
      {loading ? (
        <p className="text-[#94a3b8]">Loading campaign telemetry…</p>
      ) : runs.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-10 text-center text-[#94a3b8]">
          No validation campaigns have been executed yet. Launch one from the Campaigns page to
          populate this view.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
          <table className="w-full text-sm">
            <thead className="border-b border-[#2d333b] text-[#94a3b8] uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3 text-left">Scenario</th>
                <th className="px-4 py-3 text-left">Target</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Jobs</th>
                <th className="px-4 py-3 text-left">Verdict mix</th>
                <th className="px-4 py-3 text-left">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d333b]">
              {runs.map((run) => (
                <tr key={run.externalRunId} className="hover:bg-[#1a1d24]/80">
                  <td className="px-4 py-3">
                    <div className="font-bold text-white">{run.scenarioName}</div>
                    <div className="text-xs text-[#64748b] font-mono">{run.scenarioId}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[#cbd5e1]">{run.targetHostname}</td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1 text-xs font-bold uppercase tracking-wider">
                      {run.status === 'completed' ? (
                        <CheckCircle2 size={14} className="text-emerald-400" />
                      ) : run.status === 'partial' ? (
                        <AlertTriangle size={14} className="text-amber-300" />
                      ) : run.status === 'running' || run.status === 'queued' ? (
                        <Loader2 size={14} className="text-sky-300 animate-spin" />
                      ) : (
                        <XCircle size={14} className="text-rose-300" />
                      )}
                      {run.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#cbd5e1]">
                    {run.completedJobs}/{run.requestedJobs}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(run.verdictCounts ?? {})
                        .filter(([, count]) => (count ?? 0) > 0)
                        .map(([verdict, count]) => (
                          <span
                            key={verdict}
                            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase border ${verdictTone[verdict as Verdict] ?? ''}`}
                          >
                            {formatLabel(verdict)} <span className="font-mono">{count}</span>
                          </span>
                        ))}
                      {Object.values(run.verdictCounts ?? {}).every((v) => !v) && (
                        <span className="text-[10px] text-[#64748b]">No verdicts yet</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#94a3b8]">
                    {run.startedAt ? new Date(run.startedAt).toLocaleString() : '—'}
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

export default WaapValidation;
