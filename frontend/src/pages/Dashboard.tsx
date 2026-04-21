import { useEffect, useState } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import {
  ShieldAlert,
  Activity,
  CheckCircle,
  Clock,
  AlertTriangle,
  Layers3,
  Boxes,
} from 'lucide-react';
import AddTargetForm from '../components/AddTargetForm';
import { apiFetchJson } from '../lib/api';

type WindowKey = 'daily' | 'weekly' | 'monthly' | 'yearly';

type TimelineBucket = {
  label: string;
  blocked: number;
  allowed: number;
  errors: number;
};

type WindowSummary = {
  key: WindowKey;
  label: string;
  from: string;
  to: string;
  requests: number;
  blocked: number;
  allowed: number;
  errors: number;
  blockRate: number;
  runs: number;
  findings: number;
  newAssets: number;
  uniqueTargets: number;
  timeline: TimelineBucket[];
};

type StatusCard = {
  name: string;
  route: string;
  status: 'healthy' | 'ready' | 'attention' | 'scaffolded';
  detail: string;
  metric: string;
};

type ModuleStatus = {
  name: string;
  domain: string;
  status: 'healthy' | 'ready' | 'attention' | 'scaffolded';
  detail: string;
  metric: string;
};

type DashboardOverview = {
  generatedAt: string;
  selectedWindow: WindowKey;
  windows: Record<WindowKey, WindowSummary>;
  platformSummary: {
    approvedAssets: number;
    findingsTotal: number;
    campaignsTotal: number;
    evidenceEvents: number;
    runsTotal: number;
    exposureSignals: number;
    scenarioTemplates: number;
    waapScenarioCount: number;
    assessmentModuleCount: number;
    queueCounts: Record<string, number>;
  };
  traffic: WindowSummary;
  sectionStatus: StatusCard[];
  moduleStatus: ModuleStatus[];
};

const WINDOW_OPTIONS: { key: WindowKey; label: string }[] = [
  { key: 'daily', label: 'Daily' },
  { key: 'weekly', label: 'Weekly' },
  { key: 'monthly', label: 'Monthly' },
  { key: 'yearly', label: 'Yearly' },
];

const STATUS_STYLES: Record<StatusCard['status'], string> = {
  healthy: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/25',
  ready: 'bg-sky-500/15 text-sky-200 border border-sky-500/25',
  attention: 'bg-amber-500/15 text-amber-200 border border-amber-500/25',
  scaffolded: 'bg-[#2d333b] text-[#cbd5e1] border border-[#3b4451]',
};

const PIE_COLORS = ['#e11d48', '#22c55e', '#f59e0b'];

function KpiCard(props: { title: string; value: string | number; subtitle?: string }) {
  return (
    <div className="hud-panel p-4 border border-[#2d333b] hover:border-[#6a2bba]/30 transition-colors">
      <h3 className="text-[11px] text-[#94a3b8] font-medium uppercase tracking-wide">{props.title}</h3>
      <p className="text-2xl font-bold mt-1 text-white">{props.value}</p>
      {props.subtitle && <p className="mt-2 text-xs text-[#64748b]">{props.subtitle}</p>}
    </div>
  );
}

const Dashboard = () => {
  const [selectedWindow, setSelectedWindow] = useState<WindowKey>('daily');
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadOverview = async (windowKey: WindowKey, opts?: { silent?: boolean }) => {
    if (!opts?.silent) {
      setLoading(true);
      setError(null);
    }

    try {
      const { data } = await apiFetchJson<DashboardOverview>(`/dashboard/overview?window=${windowKey}`);
      setOverview(data);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load dashboard overview.');
      setOverview(null);
    } finally {
      if (!opts?.silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      if (!cancelled) {
        await loadOverview(selectedWindow);
      }
    };

    void run();

    return () => {
      cancelled = true;
    };
  }, [selectedWindow]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      void loadOverview(selectedWindow, { silent: true });
    }, 10000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [selectedWindow]);

  const traffic = overview?.traffic;
  const windowSnapshots = overview?.windows ? Object.values(overview.windows) : [];
  const pieData = traffic
    ? [
        { name: 'Blocked', value: traffic.blocked },
        { name: 'Allowed', value: traffic.allowed },
        { name: 'Errors', value: traffic.errors },
      ]
    : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Executive Dashboard</h1>
          <p className="text-[#94a3b8] mt-1">
            Platform-wide section health, module readiness, and evidence telemetry across daily, weekly,
            monthly, and yearly windows.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="bg-[#1a1d24] px-4 py-2 rounded-md border border-[#2d333b] flex items-center space-x-2">
            <Clock size={16} className="text-[#8e51df]" />
            <span className="text-sm font-medium">
              {overview ? new Date(overview.generatedAt).toLocaleString() : 'Waiting for data'}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {WINDOW_OPTIONS.map((option) => (
              <button
                key={option.key}
                type="button"
                onClick={() => setSelectedWindow(option.key)}
                className={`rounded-lg px-3 py-2 text-sm font-semibold transition-colors ${
                  selectedWindow === option.key
                    ? 'bg-[#8e51df] text-white shadow-[0_0_18px_rgba(142,81,223,0.35)]'
                    : 'bg-[#15181e] text-[#94a3b8] border border-[#2d333b] hover:text-white hover:border-[#8e51df]/40'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      )}

      {loading && !overview ? (
        <div className="rounded-xl border border-[#2d333b] bg-[#15181e] px-5 py-8 text-[#94a3b8]">
          Loading platform overview…
        </div>
      ) : overview ? (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">
            <KpiCard title="Approved Assets" value={overview.platformSummary.approvedAssets} />
            <KpiCard title="Scenario Templates" value={overview.platformSummary.scenarioTemplates} />
            <KpiCard title="Campaigns" value={overview.platformSummary.campaignsTotal} />
            <KpiCard title="Runs" value={overview.platformSummary.runsTotal} />
            <KpiCard title="Evidence Events" value={overview.platformSummary.evidenceEvents} />
            <KpiCard title="Findings" value={overview.platformSummary.findingsTotal} />
            <KpiCard title="WAAP Scenarios" value={overview.platformSummary.waapScenarioCount} />
            <KpiCard title="Assessment Modules" value={overview.platformSummary.assessmentModuleCount} />
          </div>

          <AddTargetForm variant="compact" onRegistered={() => void loadOverview(selectedWindow, { silent: true })} />

          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
            {[
              {
                title: `${traffic?.label ?? 'Selected'} Requests`,
                value: traffic?.requests ?? 0,
                icon: <Activity size={20} />,
                color: 'text-blue-400',
              },
              {
                title: 'WAAP Blocks',
                value: traffic?.blocked ?? 0,
                icon: <ShieldAlert size={20} />,
                color: 'text-rose-400',
              },
              {
                title: 'Allowed / Other',
                value: traffic?.allowed ?? 0,
                icon: <CheckCircle size={20} />,
                color: 'text-emerald-400',
              },
              {
                title: 'Network Errors',
                value: traffic?.errors ?? 0,
                icon: <AlertTriangle size={20} />,
                color: 'text-amber-400',
              },
              {
                title: 'Block Rate',
                value: `${traffic?.blockRate ?? 0}%`,
                icon: <ShieldAlert size={20} />,
                color: 'text-[#8e51df]',
              },
              {
                title: 'Unique Targets',
                value: traffic?.uniqueTargets ?? 0,
                icon: <Layers3 size={20} />,
                color: 'text-cyan-300',
              },
            ].map((kpi) => (
              <div key={kpi.title} className="hud-panel p-5 relative overflow-hidden group hover:border-[#6a2bba]/50 transition-colors">
                <div className={`absolute top-0 right-0 p-4 opacity-20 group-hover:opacity-100 group-hover:scale-110 transition-all ${kpi.color}`}>
                  {kpi.icon}
                </div>
                <h3 className="text-sm text-[#94a3b8] font-medium">{kpi.title}</h3>
                <p className="text-4xl font-bold mt-2">{kpi.value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="hud-panel p-5 xl:col-span-2">
              <h3 className="text-lg font-semibold mb-2">Validation Traffic Timeline</h3>
              <p className="text-sm text-[#94a3b8] mb-6">
                {traffic?.label} of evidence telemetry across blocked, allowed, and network-error outcomes.
              </p>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={traffic?.timeline ?? []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2d333b" vertical={false} />
                    <XAxis dataKey="label" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                    <RechartsTooltip
                      contentStyle={{ backgroundColor: '#1a1d24', border: '1px solid #2d333b', borderRadius: '8px' }}
                      itemStyle={{ fontSize: '14px' }}
                    />
                    <Bar dataKey="blocked" stackId="a" fill="#e11d48" radius={[0, 0, 4, 4]} name="Blocked" />
                    <Bar dataKey="allowed" stackId="a" fill="#22c55e" radius={[4, 4, 0, 0]} name="Allowed" />
                    <Bar dataKey="errors" stackId="a" fill="#f59e0b" radius={[4, 4, 0, 0]} name="Network errors" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="hud-panel p-5">
              <h3 className="text-lg font-semibold mb-2">Outcome Distribution</h3>
              <p className="text-sm text-[#94a3b8] mb-4">
                Distribution for the currently selected reporting window.
              </p>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={58}
                      outerRadius={92}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                    >
                      {pieData.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{ backgroundColor: '#1a1d24', border: '1px solid #2d333b', borderRadius: '8px', color: '#fff' }}
                      itemStyle={{ color: '#fff' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="hud-panel p-5 xl:col-span-2">
              <div className="flex items-center gap-2 mb-4">
                <Boxes size={18} className="text-[#8e51df]" />
                <h3 className="text-lg font-semibold">Section Status</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {overview.sectionStatus.map((section) => (
                  <div key={section.route} className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h4 className="font-semibold text-white">{section.name}</h4>
                        <p className="mt-2 text-sm text-[#94a3b8]">{section.detail}</p>
                      </div>
                      <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] ${STATUS_STYLES[section.status]}`}>
                        {section.status}
                      </span>
                    </div>
                    <div className="mt-4 text-xs uppercase tracking-[0.18em] text-[#64748b]">{section.metric}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="hud-panel p-5">
              <h3 className="text-lg font-semibold mb-4">Period Snapshot</h3>
              <div className="overflow-hidden rounded-xl border border-[#2d333b]">
                <table className="w-full text-sm">
                  <thead className="bg-[#11141a] text-[#94a3b8] text-xs uppercase tracking-[0.16em]">
                    <tr>
                      <th className="px-3 py-3 text-left">Window</th>
                      <th className="px-3 py-3 text-left">Req</th>
                      <th className="px-3 py-3 text-left">Block</th>
                      <th className="px-3 py-3 text-left">Runs</th>
                      <th className="px-3 py-3 text-left">Findings</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#2d333b]">
                    {windowSnapshots.map((snapshot) => (
                      <tr key={snapshot.key} className={snapshot.key === selectedWindow ? 'bg-[#171b23]' : 'bg-[#15181e]'}>
                        <td className="px-3 py-3 font-semibold text-white">{snapshot.label.replace('Last ', '')}</td>
                        <td className="px-3 py-3 text-[#cbd5e1]">{snapshot.requests}</td>
                        <td className="px-3 py-3 text-[#cbd5e1]">
                          {snapshot.blocked} ({snapshot.blockRate}%)
                        </td>
                        <td className="px-3 py-3 text-[#cbd5e1]">{snapshot.runs}</td>
                        <td className="px-3 py-3 text-[#cbd5e1]">{snapshot.findings}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="mt-4 space-y-3">
                {windowSnapshots.map((snapshot) => (
                  <div key={`${snapshot.key}:targets`} className="rounded-lg border border-[#2d333b] bg-[#11141a] px-3 py-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-white font-medium">{snapshot.label}</span>
                      <span className="text-[#94a3b8]">{snapshot.uniqueTargets} targets</span>
                    </div>
                    <div className="mt-1 text-xs text-[#64748b]">{snapshot.newAssets} new asset registrations in period</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="hud-panel p-5">
            <div className="flex items-center gap-2 mb-4">
              <Activity size={18} className="text-[#8e51df]" />
              <h3 className="text-lg font-semibold">Module Inventory</h3>
            </div>
            <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
              <table className="w-full text-sm">
                <thead className="border-b border-[#2d333b] text-[#94a3b8] text-xs uppercase tracking-[0.16em]">
                  <tr>
                    <th className="px-4 py-3 text-left">Module</th>
                    <th className="px-4 py-3 text-left">Domain</th>
                    <th className="px-4 py-3 text-left">Status</th>
                    <th className="px-4 py-3 text-left">Detail</th>
                    <th className="px-4 py-3 text-left">Metric</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2d333b]">
                  {overview.moduleStatus.map((module) => (
                    <tr key={`${module.domain}:${module.name}`} className="hover:bg-[#1a1d24]/80">
                      <td className="px-4 py-3 text-white font-medium">{module.name}</td>
                      <td className="px-4 py-3 text-[#94a3b8]">{module.domain}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] ${STATUS_STYLES[module.status]}`}>
                          {module.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#cbd5e1]">{module.detail}</td>
                      <td className="px-4 py-3 text-[#94a3b8]">{module.metric}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
};

export default Dashboard;
