import { Fragment, useEffect, useMemo, useState } from 'react';
import {
  Play,
  ShieldAlert,
  Cpu,
  AlertTriangle,
  CheckCircle2,
  Bot,
  Zap,
  Loader2,
  TerminalSquare,
  ChevronDown,
  ChevronRight,
  Clock3,
  Globe2,
  Search,
  Filter,
  Network,
  ShieldCheck,
} from 'lucide-react';
import { normalizeOperatorTargetInput } from '../../../shared/scanContract';
import { apiFetchJson } from '../lib/api';

type CampaignMessage = { kind: 'ok' | 'err'; text: string } | null;

type CampaignScenarioRequest = {
  id: string;
  label: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'HEAD' | 'PATCH';
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  bodyMode?: 'json' | 'raw';
  repeatCount?: number;
  deliveryChannel: 'query' | 'body' | 'header' | 'mixed';
  rationale: string;
  requestTags?: string[];
};

type CampaignScenario = {
  id: string;
  name: string;
  category: 'Injection' | 'API Abuse' | 'Identity & Session' | 'Header & Routing' | 'Automation & Bot';
  attackSurface: 'web' | 'api' | 'edge' | 'identity';
  severity: 'high' | 'medium' | 'low';
  summary: string;
  operatorGoal: string;
  currentSignals: string[];
  telemetryExpectations: string[];
  safetyNotes: string[];
  requests: CampaignScenarioRequest[];
  jobCount: number;
  requestCount: number;
};

type CampaignScenarioResponse = {
  scenarios: CampaignScenario[];
};

type Verdict =
  | 'blocked'
  | 'challenged'
  | 'edge_mitigated'
  | 'origin_rejected'
  | 'allowed'
  | 'network_error'
  | 'ambiguous';

type ExpectationOutcome = 'matched' | 'partially_matched' | 'mismatched' | 'ambiguous';

type ActivityEvent = {
  id: string;
  timestamp: string;
  executionStatus: string;
  responseStatusCode: number;
  latencyMs: number;
  attemptedUrl: string | null;
  requestLabel: string | null;
  deliveryChannel: string | null;
  method: string;
  path: string;
  requestHeaders: Record<string, string> | null;
  requestBodyPreview: string | null;
  payloadHash: string | null;
  responseHeaders: Record<string, string> | null;
  responseBodyPreview: string | null;
  errorMessage: string | null;
  workerJobId: string | null;
  attemptNumber: number;
  verdict?: Verdict | string;
  verdictConfidence?: number;
  verdictReason?: string | null;
  verdictSignals?: Array<{ source: string; name: string; detail?: string }> | null;
  expectationOutcome?: ExpectationOutcome | string;
  expectationDetails?: Record<string, unknown> | null;
};

type ActivityRun = {
  runId: string;
  externalRunId: string;
  label: string;
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
  queuedJobIds: string[];
  startedAt: string | null;
  completedAt: string | null;
  updatedAt: string;
  events: ActivityEvent[];
};

type CampaignActivityResponse = {
  runs: ActivityRun[];
};

function statusBadge(status: string): string {
  switch (status) {
    case 'completed':
      return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/25';
    case 'running':
      return 'bg-sky-500/15 text-sky-200 border border-sky-500/25';
    case 'queued':
      return 'bg-amber-500/15 text-amber-200 border border-amber-500/25';
    case 'partial':
      return 'bg-orange-500/15 text-orange-200 border border-orange-500/25';
    default:
      return 'bg-rose-500/15 text-rose-200 border border-rose-500/25';
  }
}

function eventBadge(status: string): string {
  switch (status) {
    case 'completed':
    case 'allowed':
      return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/25';
    case 'blocked':
    case 'origin_rejected':
      return 'bg-rose-500/15 text-rose-200 border border-rose-500/25';
    case 'challenged':
      return 'bg-amber-500/15 text-amber-200 border border-amber-500/25';
    case 'edge_mitigated':
      return 'bg-violet-500/15 text-violet-200 border border-violet-500/25';
    case 'network_error':
      return 'bg-orange-500/15 text-orange-200 border border-orange-500/25';
    case 'ambiguous':
      return 'bg-slate-500/15 text-slate-200 border border-slate-500/25';
    default:
      return 'bg-[#2d333b] text-[#cbd5e1] border border-[#3b4451]';
  }
}

function expectationBadge(outcome: string): string {
  switch (outcome) {
    case 'matched':
      return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/25';
    case 'partially_matched':
      return 'bg-amber-500/15 text-amber-200 border border-amber-500/25';
    case 'mismatched':
      return 'bg-rose-500/15 text-rose-200 border border-rose-500/25';
    case 'ambiguous':
    default:
      return 'bg-slate-500/15 text-slate-200 border border-slate-500/25';
  }
}

function formatVerdictLabel(verdict: string): string {
  return verdict.replace(/_/g, ' ');
}

function severityBadge(severity: CampaignScenario['severity']): string {
  switch (severity) {
    case 'high':
      return 'bg-rose-500/15 text-rose-200 border border-rose-500/25';
    case 'medium':
      return 'bg-amber-500/15 text-amber-200 border border-amber-500/25';
    default:
      return 'bg-sky-500/15 text-sky-200 border border-sky-500/25';
  }
}

function scenarioIcon(scenario: CampaignScenario) {
  if (scenario.category === 'Injection') {
    return scenario.severity === 'high' ? (
      <Cpu size={18} className="text-rose-400" />
    ) : (
      <AlertTriangle size={18} className="text-yellow-400" />
    );
  }
  if (scenario.category === 'API Abuse') {
    return <Zap size={18} className="text-emerald-400" />;
  }
  if (scenario.category === 'Identity & Session') {
    return <ShieldCheck size={18} className="text-orange-400" />;
  }
  if (scenario.category === 'Header & Routing') {
    return <Network size={18} className="text-cyan-300" />;
  }
  return <Bot size={18} className="text-blue-400" />;
}

function formatJsonBlock(value: Record<string, string> | null): string {
  if (!value || Object.keys(value).length === 0) {
    return 'No data recorded.';
  }
  return JSON.stringify(value, null, 2);
}

function requestBodyPreview(request: CampaignScenarioRequest): string {
  if (request.body === undefined || request.body === null) {
    return 'No body';
  }
  if (typeof request.body === 'string') {
    return request.body;
  }
  try {
    return JSON.stringify(request.body, null, 2);
  } catch {
    return String(request.body);
  }
}

function MetricCard(props: { title: string; value: number; tone: 'neutral' | 'blocked' | 'ok' | 'warn' }) {
  const toneClass =
    props.tone === 'blocked'
      ? 'text-rose-300 border-rose-500/25 bg-rose-500/10'
      : props.tone === 'ok'
        ? 'text-emerald-200 border-emerald-500/25 bg-emerald-500/10'
        : props.tone === 'warn'
          ? 'text-amber-200 border-amber-500/25 bg-amber-500/10'
          : 'text-white border-[#2d333b] bg-[#15181e]';

  return (
    <div className={`rounded-xl px-4 py-3 border ${toneClass}`}>
      <p className="text-[11px] uppercase tracking-[0.18em] text-[#94a3b8]">{props.title}</p>
      <p className="mt-2 text-2xl font-bold">{props.value}</p>
    </div>
  );
}

const Campaigns = () => {
  // Track which scenario is currently being launched. A single shared
  // boolean caused every Launch button to disable on a click; using the
  // scenario id makes each button independent and prevents the perception
  // that one click triggers multiple scenarios.
  // Per-scenario launching state. Each scenario can be launched independently
  // and concurrently; clicking Launch on scenario A no longer disables the
  // Launch buttons on scenarios B, C, D… The set tracks which scenarios are
  // currently in-flight.
  const [launchingScenarios, setLaunchingScenarios] = useState<Set<string>>(() => new Set());
  const [target, setTarget] = useState('vulnhub.com');
  const [message, setMessage] = useState<CampaignMessage>(null);
  const [scenarios, setScenarios] = useState<CampaignScenario[]>([]);
  const [scenarioLoading, setScenarioLoading] = useState(true);
  const [scenarioError, setScenarioError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedScenarios, setExpandedScenarios] = useState<Record<string, boolean>>({});
  const [activityRuns, setActivityRuns] = useState<ActivityRun[]>([]);
  const [activityLoading, setActivityLoading] = useState(true);
  const [activityError, setActivityError] = useState<string | null>(null);
  const [expandedRuns, setExpandedRuns] = useState<Record<string, boolean>>({});
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});

  const loadActivity = async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) {
      setActivityLoading(true);
      setActivityError(null);
    }

    try {
      const { data } = await apiFetchJson<CampaignActivityResponse>('/campaigns/activity?take=8');
      setActivityRuns(data.runs ?? []);
      setExpandedRuns((current) => {
        if ((data.runs?.length ?? 0) === 0) {
          return current;
        }
        const next = { ...current };
        const mostRecentRun = data.runs[0];
        if (!(mostRecentRun.externalRunId in next)) {
          next[mostRecentRun.externalRunId] = true;
        }
        return next;
      });
    } catch (error) {
      setActivityError(error instanceof Error ? error.message : 'Failed to load campaign activity.');
    } finally {
      if (!opts?.silent) {
        setActivityLoading(false);
      }
    }
  };

  useEffect(() => {
    let cancelled = false;

    const initialize = async () => {
      try {
        const { data } = await apiFetchJson<CampaignScenarioResponse>('/campaign-scenarios');
        if (!cancelled) {
          setScenarios(data.scenarios ?? []);
          setExpandedScenarios((current) => {
            if ((data.scenarios?.length ?? 0) === 0) {
              return current;
            }
            const next = { ...current };
            const firstHighSeverity =
              data.scenarios.find((scenario) => scenario.severity === 'high') ?? data.scenarios[0];
            if (!(firstHighSeverity.id in next)) {
              next[firstHighSeverity.id] = true;
            }
            return next;
          });
        }
      } catch (error) {
        if (!cancelled) {
          setScenarioError(error instanceof Error ? error.message : 'Failed to load campaign scenarios.');
        }
      } finally {
        if (!cancelled) {
          setScenarioLoading(false);
        }
      }

      try {
        const { data } = await apiFetchJson<CampaignActivityResponse>('/campaigns/activity?take=8');
        if (!cancelled) {
          setActivityRuns(data.runs ?? []);
          setExpandedRuns((current) => {
            if ((data.runs?.length ?? 0) === 0) {
              return current;
            }
            const next = { ...current };
            const mostRecentRun = data.runs[0];
            if (!(mostRecentRun.externalRunId in next)) {
              next[mostRecentRun.externalRunId] = true;
            }
            return next;
          });
        }
      } catch (error) {
        if (!cancelled) {
          setActivityError(error instanceof Error ? error.message : 'Failed to load campaign activity.');
        }
      } finally {
        if (!cancelled) {
          setActivityLoading(false);
        }
      }
    };

    void initialize();
    const intervalId = window.setInterval(() => {
      void loadActivity({ silent: true });
    }, 4000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  const categories = useMemo(
    () => ['All', ...new Set(scenarios.map((scenario) => scenario.category))],
    [scenarios],
  );

  const filteredScenarios = useMemo(() => {
    const normalizedSearch = searchTerm.trim().toLowerCase();
    return scenarios.filter((scenario) => {
      const categoryMatch = selectedCategory === 'All' || scenario.category === selectedCategory;
      if (!categoryMatch) {
        return false;
      }
      if (!normalizedSearch) {
        return true;
      }
      return [
        scenario.name,
        scenario.summary,
        scenario.operatorGoal,
        scenario.category,
        scenario.attackSurface,
        ...scenario.currentSignals,
        ...scenario.telemetryExpectations,
      ]
        .join(' ')
        .toLowerCase()
        .includes(normalizedSearch);
    });
  }, [scenarios, searchTerm, selectedCategory]);

  const coverageSummary = useMemo(() => {
    const categoryCount = new Set(scenarios.map((scenario) => scenario.category)).size;
    const totalJobs = scenarios.reduce((sum, scenario) => sum + scenario.jobCount, 0);
    const highSeverity = scenarios.filter((scenario) => scenario.severity === 'high').length;
    const surfaces = new Set(scenarios.map((scenario) => scenario.attackSurface)).size;
    return { categoryCount, totalJobs, highSeverity, surfaces };
  }, [scenarios]);

  const handleLaunch = async (
    scenarioId: string,
    event?: React.MouseEvent<HTMLButtonElement>,
  ) => {
    // Strict isolation: only the scenario the operator explicitly clicked
    // is launched. No bubbling, no implicit fan-out into other scenarios.
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }
    // Re-entrancy guard: if THIS scenario is already in flight, ignore the
    // duplicate click. Other scenarios remain freely launchable in parallel.
    if (launchingScenarios.has(scenarioId)) {
      return;
    }
    const normalizedTarget = normalizeOperatorTargetInput(target);
    if (!normalizedTarget) {
      setMessage({ kind: 'err', text: 'Enter a valid authorized hostname or label.' });
      return;
    }

    setLaunchingScenarios((prev) => {
      const next = new Set(prev);
      next.add(scenarioId);
      return next;
    });
    setMessage(null);
    try {
      const { data } = await apiFetchJson<{
        campaignRunId: string;
        jobsQueued: number;
        scenario: { id: string; name: string; category: string };
      }>('/campaigns/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetHostname: normalizedTarget, scenarioType: scenarioId }),
      });

      setTarget(normalizedTarget);
      setExpandedRuns((current) => ({ ...current, [data.campaignRunId]: true }));
      setMessage({
        kind: 'ok',
        text: `${data.scenario.name} queued for ${normalizedTarget}. ${data.jobsQueued} request job(s) were scheduled with trace persistence enabled.`,
      });
      await loadActivity({ silent: true });
    } catch (error) {
      setMessage({
        kind: 'err',
        text: error instanceof Error ? error.message : 'Error launching campaign.',
      });
    } finally {
      setLaunchingScenarios((prev) => {
        const next = new Set(prev);
        next.delete(scenarioId);
        return next;
      });
    }
  };

  const aggregated = activityRuns.reduce(
    (acc, run) => {
      acc.runs += 1;
      acc.blocked += run.blockedJobs;
      acc.allowed += run.allowedJobs;
      acc.errors += run.errorJobs;
      return acc;
    },
    { runs: 0, blocked: 0, allowed: 0, errors: 0 },
  );

  return (
    <div className="space-y-8 max-w-7xl pb-10">
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-3 text-white">
          <div className="p-2 bg-gradient-to-br from-[#8e51df] to-[#6a2bba] rounded-lg shadow-[0_0_15px_rgba(142,81,223,0.4)]">
            <Zap size={24} className="text-white" />
          </div>
          Validation Campaigns
        </h1>
        <p className="text-[#94a3b8] mt-3 tracking-wide max-w-4xl">
          Execute bounded, operator-auditable validation scenarios aligned to current web, API, identity,
          header-routing, and automation attack vectors. Every launch preserves exact request intent and
          resulting telemetry.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-[#15181e] border border-[#2d333b] rounded-2xl p-6 shadow-xl relative overflow-hidden">
            <h3 className="font-extrabold text-lg flex items-center space-x-2 border-b border-[#2d333b] pb-4 mb-5 text-white tracking-wide">
              <span>Target Configuration</span>
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-bold tracking-wide text-[#a1a1aa] mb-2 uppercase">
                  Authorized Hostname
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full bg-[#0b0c10] border border-[#2d333b] rounded-lg focus:border-[#8e51df] focus:ring-1 focus:ring-[#8e51df] outline-none text-white font-medium px-4 py-3.5 transition-all shadow-[inset_0_2px_4px_rgba(0,0,0,0.2)]"
                />
                <p className="text-xs text-emerald-400 mt-3 flex items-center font-semibold bg-emerald-400/10 inline-flex px-2.5 py-1 rounded border border-emerald-400/20">
                  <CheckCircle2 size={14} className="mr-1.5" />
                  Validated internal allowlist
                </p>
                {message && (
                  <div
                    className={`mt-4 rounded-lg px-3 py-2 text-sm border ${
                      message.kind === 'ok'
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100'
                        : 'border-rose-500/30 bg-rose-500/10 text-rose-100'
                    }`}
                  >
                    {message.text}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-b from-[#1a0f14] to-[#0f1115] border border-rose-900/50 rounded-2xl relative overflow-hidden shadow-[0_0_20px_rgba(225,29,72,0.1)]">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-gradient-to-b from-rose-500 to-rose-800" />
            <div className="p-6 pl-8">
              <h3 className="font-extrabold text-white mb-4 flex items-center gap-2">
                <ShieldAlert size={18} className="text-rose-500" />
                Safety Limits Active
              </h3>
              <ul className="text-[13px] text-[#cbd5e1] space-y-3 font-mono font-medium">
                <li className="flex justify-between border-b border-rose-900/30 pb-2">
                  <span>Max Concurrency</span> <span className="text-emerald-400">5 reqs</span>
                </li>
                <li className="flex justify-between border-b border-rose-900/30 pb-2">
                  <span>Worker Timeout</span> <span className="text-emerald-400">5000ms</span>
                </li>
                <li className="flex justify-between border-b border-rose-900/30 pb-2">
                  <span>Trace Persistence</span> <span className="text-[#8e51df]">Enabled</span>
                </li>
                <li className="flex justify-between">
                  <span>Scenario Library</span> <span className="text-emerald-400">{scenarios.length} vectors</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 space-y-5">
          <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
            <div>
              <h3 className="font-extrabold text-xl pb-1 text-white tracking-wide">Scenario Library</h3>
              <p className="text-sm text-[#94a3b8]">
                Backend-driven coverage across current request abuse patterns, with accurate execution semantics.
              </p>
            </div>
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-2 min-w-[320px]">
              <MetricCard title="Vector Families" value={coverageSummary.categoryCount} tone="neutral" />
              <MetricCard title="Scenarios" value={scenarios.length} tone="neutral" />
              <MetricCard title="High Severity" value={coverageSummary.highSeverity} tone="blocked" />
              <MetricCard title="Jobs / Full Sweep" value={coverageSummary.totalJobs} tone="ok" />
            </div>
          </div>

          <div className="rounded-2xl border border-[#2d333b] bg-[#15181e] p-4 space-y-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
              <div className="relative flex-1">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
                <input
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search by vector, surface, or signal"
                  className="w-full rounded-lg border border-[#2d333b] bg-[#0b0c10] pl-9 pr-3 py-3 text-sm text-white outline-none focus:border-[#8e51df] focus:ring-1 focus:ring-[#8e51df]"
                />
              </div>
              <div className="flex items-center gap-2 overflow-x-auto">
                <span className="inline-flex items-center gap-1 text-xs uppercase tracking-[0.18em] text-[#64748b] whitespace-nowrap">
                  <Filter size={14} />
                  Category
                </span>
                {categories.map((category) => (
                  <button
                    key={category}
                    type="button"
                    onClick={() => setSelectedCategory(category)}
                    className={`rounded-full px-3 py-1.5 text-xs font-semibold whitespace-nowrap transition-colors ${
                      selectedCategory === category
                        ? 'bg-[#8e51df] text-white'
                        : 'bg-[#11141a] text-[#94a3b8] border border-[#2d333b] hover:text-white hover:border-[#8e51df]/40'
                    }`}
                  >
                    {category}
                  </button>
                ))}
              </div>
            </div>

            {scenarioError && (
              <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
                {scenarioError}
              </div>
            )}

            {scenarioLoading ? (
              <div className="rounded-xl border border-dashed border-[#2d333b] px-5 py-8 text-[#94a3b8]">
                Loading scenario coverage…
              </div>
            ) : (
              <div className="grid gap-4">
                {filteredScenarios.map((scenario) => {
                  const isExpanded = expandedScenarios[scenario.id] ?? false;

                  return (
                    <div
                      key={scenario.id}
                      className="bg-[#11141a] border border-[#2d333b] hover:border-[#8e51df]/40 rounded-2xl overflow-hidden transition-all duration-300"
                    >
                      <div className="p-5 flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                        <div className="flex gap-4 min-w-0">
                          <div className="w-12 h-12 rounded-xl bg-[#0b0c10] border border-[#2d333b] flex items-center justify-center shrink-0 shadow-inner">
                            {scenarioIcon(scenario)}
                          </div>
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <h4 className="font-bold text-white text-xl leading-tight">{scenario.name}</h4>
                              <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] ${severityBadge(scenario.severity)}`}>
                                {scenario.severity}
                              </span>
                              <span className="inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] bg-[#2d333b] text-[#cbd5e1] border border-[#3b4451]">
                                {scenario.category}
                              </span>
                              <span className="inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] bg-sky-500/10 text-sky-200 border border-sky-500/20">
                                {scenario.attackSurface}
                              </span>
                            </div>
                            <p className="mt-2 text-sm text-[#cbd5e1]">{scenario.summary}</p>
                            <p className="mt-2 text-sm text-[#94a3b8]">
                              <span className="text-white font-medium">Operator goal:</span> {scenario.operatorGoal}
                            </p>
                            <div className="mt-3 flex flex-wrap gap-2">
                              {scenario.currentSignals.slice(0, 4).map((signal) => (
                                <span
                                  key={signal}
                                  className="inline-flex rounded-full px-2.5 py-1 text-[11px] font-semibold bg-[#0b0c10] text-[#94a3b8] border border-[#2d333b]"
                                >
                                  {signal}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="flex flex-col gap-3 xl:items-end shrink-0">
                          <div className="grid grid-cols-3 gap-2">
                            <MetricCard title="Requests" value={scenario.requestCount} tone="neutral" />
                            <MetricCard title="Jobs" value={scenario.jobCount} tone="neutral" />
                            <MetricCard title="Signals" value={scenario.currentSignals.length} tone="ok" />
                          </div>
                          <div className="flex gap-2 xl:justify-end">
                            <button
                              type="button"
                              className="h-11 px-4 rounded-lg border border-[#2d333b] text-sm font-semibold text-[#cbd5e1] hover:border-[#8e51df]/50 hover:text-white flex items-center gap-2"
                              onClick={() =>
                                setExpandedScenarios((current) => ({
                                  ...current,
                                  [scenario.id]: !isExpanded,
                                }))
                              }
                            >
                              {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                              Details
                            </button>
                            <button
                              type="button"
                              className="h-11 px-6 rounded-lg bg-gradient-to-r from-[#6a2bba] to-[#8e51df] hover:from-[#8e51df] hover:to-[#a372eb] font-extrabold text-sm tracking-wide transition-all duration-300 shadow-[0_0_15px_rgba(106,43,186,0.3)] hover:shadow-[0_0_25px_rgba(106,43,186,0.5)] flex items-center space-x-2 text-white disabled:opacity-50 disabled:grayscale uppercase"
                              onClick={(e) => handleLaunch(scenario.id, e)}
                              disabled={launchingScenarios.has(scenario.id)}
                            >
                              {launchingScenarios.has(scenario.id) ? (
                                <>
                                  <span className="animate-pulse">Launching...</span>
                                  <Loader2 size={16} className="animate-spin ml-1" />
                                </>
                              ) : (
                                <>
                                  <span>Launch</span>
                                  <Play size={16} fill="currentColor" />
                                </>
                              )}
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="px-5 pb-5">
                        <div className="rounded-xl border border-[#2d333b] bg-[#0d1016] p-4">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b] mb-3">
                            Request Preview
                          </p>
                          <div className="grid gap-3">
                            {scenario.requests.slice(0, 3).map((request) => (
                              <div
                                key={request.id}
                                className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between rounded-lg border border-[#2d333b] bg-[#15181e] px-3 py-3"
                              >
                                <div className="min-w-0">
                                  <div className="font-medium text-white">{request.label}</div>
                                  <div className="mt-2 inline-flex items-center gap-2 rounded-lg border border-[#2d333b] bg-[#0b0c10] px-3 py-2 font-mono text-[12px] text-[#dbe4f0] max-w-full">
                                    <span className="text-emerald-300 shrink-0">{request.method}</span>
                                    <span className="truncate">{request.path}</span>
                                  </div>
                                  <p className="mt-2 text-xs text-[#94a3b8]">{request.rationale}</p>
                                </div>
                                <div className="flex flex-wrap gap-2 lg:justify-end">
                                  <span className="inline-flex rounded-full px-2 py-1 text-[11px] font-semibold bg-[#11141a] text-[#cbd5e1] border border-[#2d333b]">
                                    {request.deliveryChannel}
                                  </span>
                                  <span className="inline-flex rounded-full px-2 py-1 text-[11px] font-semibold bg-[#11141a] text-[#cbd5e1] border border-[#2d333b]">
                                    {request.repeatCount ?? 1} job(s)
                                  </span>
                                  {request.bodyMode && (
                                    <span className="inline-flex rounded-full px-2 py-1 text-[11px] font-semibold bg-[#11141a] text-[#cbd5e1] border border-[#2d333b]">
                                      {request.bodyMode}
                                    </span>
                                  )}
                                </div>
                              </div>
                            ))}
                            {scenario.requests.length > 3 && (
                              <div className="text-xs text-[#64748b]">
                                + {scenario.requests.length - 3} additional request template(s) in this scenario
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="border-t border-[#2d333b] bg-[#0f1218] px-5 py-5 space-y-5">
                          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                            <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Current Signals</p>
                              <div className="mt-3 flex flex-wrap gap-2">
                                {scenario.currentSignals.map((signal) => (
                                  <span
                                    key={signal}
                                    className="inline-flex rounded-full px-2.5 py-1 text-[11px] font-semibold bg-[#0b0c10] text-[#94a3b8] border border-[#2d333b]"
                                  >
                                    {signal}
                                  </span>
                                ))}
                              </div>
                            </div>
                            <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Expected Telemetry</p>
                              <ul className="mt-3 space-y-2 text-sm text-[#cbd5e1]">
                                {scenario.telemetryExpectations.map((item) => (
                                  <li key={item} className="flex items-start gap-2">
                                    <CheckCircle2 size={14} className="mt-0.5 text-emerald-400 shrink-0" />
                                    <span>{item}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                            <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Safety Boundaries</p>
                              <ul className="mt-3 space-y-2 text-sm text-[#cbd5e1]">
                                {scenario.safetyNotes.map((item) => (
                                  <li key={item} className="flex items-start gap-2">
                                    <ShieldCheck size={14} className="mt-0.5 text-sky-300 shrink-0" />
                                    <span>{item}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          </div>

                          <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
                            <table className="w-full text-sm">
                              <thead className="border-b border-[#2d333b] text-[#94a3b8] text-xs uppercase tracking-[0.18em]">
                                <tr>
                                  <th className="px-3 py-3 text-left">Request Label</th>
                                  <th className="px-3 py-3 text-left">Method</th>
                                  <th className="px-3 py-3 text-left">Path</th>
                                  <th className="px-3 py-3 text-left">Delivery</th>
                                  <th className="px-3 py-3 text-left">Repeat</th>
                                  <th className="px-3 py-3 text-left">Body Preview</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-[#2d333b]">
                                {scenario.requests.map((request) => (
                                  <tr key={request.id} className="hover:bg-[#11141a]">
                                    <td className="px-3 py-3 text-white font-medium">{request.label}</td>
                                    <td className="px-3 py-3 text-emerald-300 font-mono">{request.method}</td>
                                    <td className="px-3 py-3 text-[#cbd5e1] font-mono break-all">{request.path}</td>
                                    <td className="px-3 py-3 text-[#94a3b8]">{request.deliveryChannel}</td>
                                    <td className="px-3 py-3 text-[#94a3b8]">{request.repeatCount ?? 1}</td>
                                    <td className="px-3 py-3">
                                      <pre className="max-w-[360px] overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-[#2d333b] bg-[#0b0c10] p-2 text-[11px] text-[#94a3b8]">
                                        {requestBodyPreview(request)}
                                      </pre>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}

                {filteredScenarios.length === 0 && (
                  <div className="rounded-xl border border-dashed border-[#2d333b] px-5 py-8 text-center text-[#94a3b8]">
                    No scenarios matched the current filter.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      <section className="space-y-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h2 className="text-2xl font-extrabold text-white flex items-center gap-3">
              <TerminalSquare className="text-[#8e51df]" size={24} />
              Execution Trace & Outputs
            </h2>
            <p className="mt-2 text-[#94a3b8] max-w-3xl">
              Every recent campaign run below includes the exact attempted request, the resolved destination,
              worker metadata, and the recorded outcome.
            </p>
          </div>
          <div className="text-xs uppercase tracking-[0.22em] text-[#64748b]">
            Showing the latest 8 campaign runs
          </div>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <MetricCard title="Recent Runs" value={aggregated.runs} tone="neutral" />
          <MetricCard title="Blocked Outcomes" value={aggregated.blocked} tone="blocked" />
          <MetricCard title="Allowed Outcomes" value={aggregated.allowed} tone="ok" />
          <MetricCard title="Network Errors" value={aggregated.errors} tone="warn" />
        </div>

        {activityError && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
            {activityError}
          </div>
        )}

        {activityLoading && activityRuns.length === 0 ? (
          <div className="rounded-2xl border border-[#2d333b] bg-[#15181e] px-6 py-8 text-[#94a3b8]">
            Loading campaign execution traces…
          </div>
        ) : activityRuns.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-[#2d333b] bg-[#15181e] px-6 py-10 text-center text-[#94a3b8]">
            No campaign activity has been recorded yet.
          </div>
        ) : (
          <div className="space-y-4">
            {activityRuns.map((run) => {
              const isExpanded = expandedRuns[run.externalRunId] ?? false;

              return (
                <div key={run.externalRunId} className="rounded-2xl border border-[#2d333b] bg-[#15181e] overflow-hidden">
                  <button
                    type="button"
                    className="w-full px-5 py-4 text-left hover:bg-[#1a1d24]/70 transition-colors"
                    onClick={() =>
                      setExpandedRuns((current) => ({
                        ...current,
                        [run.externalRunId]: !isExpanded,
                      }))
                    }
                  >
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="flex items-start gap-3 min-w-0">
                        <div className="pt-1 text-[#8e51df]">{isExpanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}</div>
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="text-lg font-bold text-white">{run.scenarioName}</h3>
                            <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] ${statusBadge(run.status)}`}>
                              {run.status}
                            </span>
                          </div>
                          <div className="mt-2 flex flex-wrap items-center gap-4 text-sm text-[#94a3b8]">
                            <span className="inline-flex items-center gap-1.5">
                              <Globe2 size={14} className="text-[#8e51df]" />
                              {run.targetHostname}
                            </span>
                            <span className="inline-flex items-center gap-1.5">
                              <Clock3 size={14} className="text-[#8e51df]" />
                              {run.startedAt ? new Date(run.startedAt).toLocaleString() : 'Pending'}
                            </span>
                            <span className="font-mono text-xs text-[#64748b]">{run.externalRunId}</span>
                          </div>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 min-w-[280px]">
                        <MetricCard title="Requested" value={run.requestedJobs} tone="neutral" />
                        <MetricCard title="Completed" value={run.completedJobs} tone="ok" />
                        <MetricCard title="Blocked" value={run.blockedJobs} tone="blocked" />
                        <MetricCard title="Errors" value={run.errorJobs} tone="warn" />
                      </div>
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="border-t border-[#2d333b] px-5 py-5 space-y-5">
                      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
                        <div className="rounded-xl border border-[#2d333b] bg-[#11141a] px-4 py-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Scenario</p>
                          <p className="mt-2 font-semibold text-white">{run.scenarioCategory}</p>
                          <p className="mt-1 text-xs text-[#94a3b8]">{run.scenarioId}</p>
                        </div>
                        <div className="rounded-xl border border-[#2d333b] bg-[#11141a] px-4 py-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Job Queue</p>
                          <p className="mt-2 font-semibold text-white">{run.queuedJobIds.length} job IDs captured</p>
                          <p className="mt-1 text-xs text-[#94a3b8] break-all">
                            {run.queuedJobIds.length > 0 ? run.queuedJobIds.join(', ') : 'No job IDs recorded'}
                          </p>
                        </div>
                        <div className="rounded-xl border border-[#2d333b] bg-[#11141a] px-4 py-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Run Completion</p>
                          <p className="mt-2 font-semibold text-white">
                            {run.completedAt ? new Date(run.completedAt).toLocaleString() : 'Still in progress'}
                          </p>
                          <p className="mt-1 text-xs text-[#94a3b8]">Last update {new Date(run.updatedAt).toLocaleString()}</p>
                        </div>
                        <div className="rounded-xl border border-[#2d333b] bg-[#11141a] px-4 py-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Outcome Mix</p>
                          <p className="mt-2 font-semibold text-white">
                            {run.allowedJobs} allowed / {run.blockedJobs} controlled / {run.errorJobs} errors
                          </p>
                          <p className="mt-1 text-xs text-[#94a3b8]">{run.events.length} event rows captured</p>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                        <div className="rounded-xl border border-[#2d333b] bg-[#11141a] px-4 py-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">UASF Verdict Mix</p>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {run.verdictCounts && Object.entries(run.verdictCounts).filter(([, count]) => (count ?? 0) > 0).length > 0 ? (
                              Object.entries(run.verdictCounts)
                                .filter(([, count]) => (count ?? 0) > 0)
                                .map(([verdict, count]) => (
                                  <span
                                    key={verdict}
                                    className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.14em] ${eventBadge(verdict)}`}
                                  >
                                    <span>{formatVerdictLabel(verdict)}</span>
                                    <span className="font-mono">{count}</span>
                                  </span>
                                ))
                            ) : (
                              <span className="text-xs text-[#64748b]">No verdict data yet.</span>
                            )}
                          </div>
                        </div>
                        <div className="rounded-xl border border-[#2d333b] bg-[#11141a] px-4 py-3">
                          <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Expected vs Observed</p>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {run.expectationCounts && Object.entries(run.expectationCounts).filter(([, count]) => (count ?? 0) > 0).length > 0 ? (
                              Object.entries(run.expectationCounts)
                                .filter(([, count]) => (count ?? 0) > 0)
                                .map(([outcome, count]) => (
                                  <span
                                    key={outcome}
                                    className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.14em] ${expectationBadge(outcome)}`}
                                  >
                                    <span>{formatVerdictLabel(outcome)}</span>
                                    <span className="font-mono">{count}</span>
                                  </span>
                                ))
                            ) : (
                              <span className="text-xs text-[#64748b]">No expectation data yet.</span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#11141a]">
                        <table className="w-full text-sm">
                          <thead className="border-b border-[#2d333b] text-[#94a3b8] text-xs uppercase tracking-[0.18em]">
                            <tr>
                              <th className="px-3 py-3 text-left">Time</th>
                              <th className="px-3 py-3 text-left">Attempt</th>
                              <th className="px-3 py-3 text-left">Request</th>
                              <th className="px-3 py-3 text-left">Result</th>
                              <th className="px-3 py-3 text-left">Latency</th>
                              <th className="px-3 py-3 text-left">Details</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[#2d333b]">
                            {run.events.map((event) => {
                              const eventKey = `${run.externalRunId}:${event.id}`;
                              const eventExpanded = expandedEvents[eventKey] ?? false;
                              return (
                                <Fragment key={event.id}>
                                  <tr className="align-top hover:bg-[#171b23]/70">
                                    <td className="px-3 py-3 whitespace-nowrap text-[#94a3b8]">
                                      {new Date(event.timestamp).toLocaleString()}
                                    </td>
                                    <td className="px-3 py-3 text-white font-medium">#{event.attemptNumber}</td>
                                    <td className="px-3 py-3 font-mono text-xs text-[#dbe4f0]">
                                      <div className="text-white font-semibold mb-1">{event.requestLabel ?? 'Unnamed request'}</div>
                                      <div className="text-emerald-300">{event.method}</div>
                                      <div className="break-all text-[#cbd5e1]">{event.path}</div>
                                    </td>
                                    <td className="px-3 py-3">
                                      <div className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] ${eventBadge(event.verdict ?? event.executionStatus)}`}>
                                        {formatVerdictLabel(String(event.verdict ?? event.executionStatus))}
                                      </div>
                                      {event.expectationOutcome && (
                                        <div className={`mt-2 inline-flex rounded-full px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.14em] ${expectationBadge(String(event.expectationOutcome))}`}>
                                          {formatVerdictLabel(String(event.expectationOutcome))}
                                        </div>
                                      )}
                                      <div className="mt-2 text-xs text-[#94a3b8]">
                                        HTTP {event.responseStatusCode}
                                        {typeof event.verdictConfidence === 'number' && event.verdictConfidence > 0
                                          ? ` · CF ${event.verdictConfidence}%`
                                          : ''}
                                        {event.errorMessage ? ` · ${event.errorMessage}` : ''}
                                      </div>
                                    </td>
                                    <td className="px-3 py-3 text-[#94a3b8]">{event.latencyMs} ms</td>
                                    <td className="px-3 py-3">
                                      <button
                                        type="button"
                                        className="inline-flex items-center gap-1 rounded-lg border border-[#2d333b] px-2.5 py-1.5 text-xs text-[#cbd5e1] hover:border-[#8e51df]/50 hover:text-white"
                                        onClick={() =>
                                          setExpandedEvents((current) => ({
                                            ...current,
                                            [eventKey]: !eventExpanded,
                                          }))
                                        }
                                      >
                                        {eventExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                        Details
                                      </button>
                                    </td>
                                  </tr>
                                  {eventExpanded && (
                                    <tr>
                                      <td colSpan={6} className="px-3 pb-4">
                                        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 rounded-xl border border-[#2d333b] bg-[#0d1016] p-4">
                                          <div className="space-y-3">
                                            <div>
                                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Attempted URL</p>
                                              <p className="mt-2 break-all font-mono text-xs text-[#dbe4f0]">
                                                {event.attemptedUrl ?? 'Not recorded'}
                                              </p>
                                            </div>
                                            <div>
                                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Request Headers</p>
                                              <pre className="mt-2 overflow-x-auto rounded-lg border border-[#2d333b] bg-[#15181e] p-3 text-[11px] text-[#cbd5e1]">
                                                {formatJsonBlock(event.requestHeaders)}
                                              </pre>
                                            </div>
                                            <div>
                                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Request Body / Payload</p>
                                              <pre className="mt-2 overflow-x-auto rounded-lg border border-[#2d333b] bg-[#15181e] p-3 text-[11px] text-[#cbd5e1] whitespace-pre-wrap break-words">
                                                {event.requestBodyPreview ?? 'No request body recorded.'}
                                              </pre>
                                              {event.payloadHash && (
                                                <p className="mt-2 font-mono text-[11px] text-[#64748b]">SHA-256 {event.payloadHash}</p>
                                              )}
                                            </div>
                                          </div>
                                          <div className="space-y-3">
                                            <div>
                                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">UASF Verdict</p>
                                              <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
                                                <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] ${eventBadge(event.verdict ?? event.executionStatus)}`}>
                                                  {formatVerdictLabel(String(event.verdict ?? event.executionStatus))}
                                                </span>
                                                {typeof event.verdictConfidence === 'number' && (
                                                  <span className="font-mono text-xs text-emerald-300">
                                                    CF {event.verdictConfidence}%
                                                  </span>
                                                )}
                                                <span className="font-mono text-xs text-[#cbd5e1]">HTTP {event.responseStatusCode}</span>
                                                {event.deliveryChannel && (
                                                  <span className="font-mono text-xs text-[#94a3b8]">{event.deliveryChannel}</span>
                                                )}
                                                {event.workerJobId && (
                                                  <span className="font-mono text-xs text-[#64748b]">Job {event.workerJobId}</span>
                                                )}
                                              </div>
                                              {event.verdictReason && (
                                                <p className="mt-2 text-xs text-[#94a3b8]">{event.verdictReason}</p>
                                              )}
                                              {Array.isArray(event.verdictSignals) && event.verdictSignals.length > 0 && (
                                                <div className="mt-2 flex flex-wrap gap-1.5">
                                                  {event.verdictSignals.map((signal, index) => (
                                                    <span
                                                      key={`${signal.name}-${index}`}
                                                      className="inline-flex rounded-md border border-[#2d333b] bg-[#0b0c10] px-2 py-1 text-[10px] font-mono text-[#cbd5e1]"
                                                      title={signal.detail ?? signal.source}
                                                    >
                                                      {signal.source}:{signal.name}
                                                    </span>
                                                  ))}
                                                </div>
                                              )}
                                            </div>
                                            {event.expectationOutcome && (
                                              <div>
                                                <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Expected vs Observed</p>
                                                <div className="mt-2 flex items-center gap-2">
                                                  <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] ${expectationBadge(String(event.expectationOutcome))}`}>
                                                    {formatVerdictLabel(String(event.expectationOutcome))}
                                                  </span>
                                                </div>
                                                {event.expectationDetails &&
                                                  Array.isArray((event.expectationDetails as { reasons?: unknown }).reasons) && (
                                                    <ul className="mt-2 space-y-1 text-xs text-[#94a3b8]">
                                                      {((event.expectationDetails as { reasons: string[] }).reasons).map(
                                                        (reason, index) => (
                                                          <li key={`${reason}-${index}`}>· {reason}</li>
                                                        ),
                                                      )}
                                                    </ul>
                                                  )}
                                              </div>
                                            )}
                                            <div>
                                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Response Headers</p>
                                              <pre className="mt-2 overflow-x-auto rounded-lg border border-[#2d333b] bg-[#15181e] p-3 text-[11px] text-[#cbd5e1]">
                                                {formatJsonBlock(event.responseHeaders)}
                                              </pre>
                                            </div>
                                            <div>
                                              <p className="text-[11px] uppercase tracking-[0.18em] text-[#64748b]">Response Output</p>
                                              <pre className="mt-2 overflow-x-auto rounded-lg border border-[#2d333b] bg-[#15181e] p-3 text-[11px] text-[#cbd5e1] whitespace-pre-wrap break-words">
                                                {event.responseBodyPreview ?? event.errorMessage ?? 'No response body captured.'}
                                              </pre>
                                            </div>
                                          </div>
                                        </div>
                                      </td>
                                    </tr>
                                  )}
                                </Fragment>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>

                      {run.events.length === 0 && (
                        <div className="rounded-xl border border-dashed border-[#2d333b] px-4 py-6 text-sm text-[#94a3b8]">
                          This run has been queued, but no evidence rows have been recorded yet.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
};

export default Campaigns;
