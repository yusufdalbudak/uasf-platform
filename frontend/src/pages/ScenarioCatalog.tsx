import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  BookOpen,
  Search,
  ShieldAlert,
  Target as TargetIcon,
  Repeat,
  ListTree,
  ArrowRight,
  X,
  Loader2,
  Layers,
  ChevronDown,
} from 'lucide-react';
import { apiFetchJson } from '../lib/api';

type ScenarioRequest = {
  id: string;
  label: string;
  method: string;
  path: string;
  deliveryChannel: string;
  rationale: string;
  repeatCount?: number;
  requestTags?: string[];
  headers?: Record<string, string>;
  body?: unknown;
  bodyMode?: string;
  expected?: {
    verdicts?: string[];
    statusRanges?: Array<{ from: number; to: number }>;
    rationale?: string;
  };
};

type Scenario = {
  id: string;
  name: string;
  category: string;
  attackSurface: string;
  severity: 'high' | 'medium' | 'low';
  summary: string;
  operatorGoal: string;
  currentSignals: string[];
  telemetryExpectations: string[];
  safetyNotes: string[];
  requests: ScenarioRequest[];
  jobCount: number;
  requestCount: number;
};

const severityTone: Record<Scenario['severity'], string> = {
  high: 'border-rose-500/40 bg-rose-500/10 text-rose-200',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-200',
};

const severityChipTone: Record<Scenario['severity'], string> = {
  high: 'bg-rose-500/20 text-rose-200',
  medium: 'bg-amber-500/20 text-amber-200',
  low: 'bg-sky-500/20 text-sky-200',
};

const surfaceIcon: Record<string, string> = {
  web: 'WEB',
  api: 'API',
  edge: 'EDGE',
  identity: 'IDP',
};

const ScenarioCatalog = () => {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>('all');
  const [severity, setSeverity] = useState<string>('all');
  const [surface, setSurface] = useState<string>('all');
  const [selected, setSelected] = useState<Scenario | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      setLoading(true);
      try {
        const { data } = await apiFetchJson<{ scenarios?: Scenario[] }>('/campaign-scenarios');
        if (!cancelled) setScenarios(Array.isArray(data.scenarios) ? data.scenarios : []);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Failed to load scenarios.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const categories = useMemo(() => {
    return Array.from(new Set(scenarios.map((s) => s.category))).sort();
  }, [scenarios]);

  const surfaces = useMemo(() => {
    return Array.from(new Set(scenarios.map((s) => s.attackSurface))).sort();
  }, [scenarios]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return scenarios.filter((s) => {
      if (category !== 'all' && s.category !== category) return false;
      if (severity !== 'all' && s.severity !== severity) return false;
      if (surface !== 'all' && s.attackSurface !== surface) return false;
      if (!q) return true;
      const haystack = [
        s.id,
        s.name,
        s.summary,
        s.operatorGoal,
        s.category,
        s.attackSurface,
        ...(s.currentSignals || []),
        ...(s.requests || []).flatMap((r) => [r.label, r.path, ...(r.requestTags || [])]),
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [scenarios, search, category, severity, surface]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <BookOpen className="text-[#8e51df]" size={28} />
            Scenario catalog
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Library of policy-bound, evidence-driven validation scenarios. Each scenario carries an
            operator goal, expected verdict telemetry, and a safety contract. Launch from the
            Campaigns page once a target is selected.
          </p>
        </div>
        <Link
          to="/campaigns"
          className="inline-flex items-center gap-2 rounded-lg border border-[#8e51df]/40 bg-[#8e51df]/10 px-3 py-2 text-sm text-[#cbd5e1] hover:bg-[#8e51df]/20"
        >
          Open campaigns
          <ArrowRight size={14} />
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
          <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">
            Total scenarios
          </div>
          <div className="text-2xl font-extrabold text-white mt-1">{scenarios.length}</div>
        </div>
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4">
          <div className="text-[10px] uppercase tracking-wider text-rose-200">High severity</div>
          <div className="text-2xl font-extrabold text-rose-100 mt-1">
            {scenarios.filter((s) => s.severity === 'high').length}
          </div>
        </div>
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
          <div className="text-[10px] uppercase tracking-wider text-amber-200">Medium</div>
          <div className="text-2xl font-extrabold text-amber-100 mt-1">
            {scenarios.filter((s) => s.severity === 'medium').length}
          </div>
        </div>
        <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4">
          <div className="text-[10px] uppercase tracking-wider text-sky-200">Low</div>
          <div className="text-2xl font-extrabold text-sky-100 mt-1">
            {scenarios.filter((s) => s.severity === 'low').length}
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
            placeholder="Search by id, name, signal, path, tag…"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#8e51df]/60"
          />
        </div>
        <FilterSelect
          label="Category"
          value={category}
          onChange={setCategory}
          options={[{ value: 'all', label: 'All categories' }, ...categories.map((c) => ({ value: c, label: c }))]}
        />
        <FilterSelect
          label="Severity"
          value={severity}
          onChange={setSeverity}
          options={[
            { value: 'all', label: 'All severities' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
        <FilterSelect
          label="Surface"
          value={surface}
          onChange={setSurface}
          options={[{ value: 'all', label: 'All surfaces' }, ...surfaces.map((s) => ({ value: s, label: s.toUpperCase() }))]}
        />
        <div className="text-xs text-[#94a3b8] ml-auto">
          {filtered.length} of {scenarios.length}
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-2 text-[#94a3b8]">
          <Loader2 size={16} className="animate-spin" /> Loading scenario library…
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-10 text-center text-[#94a3b8]">
          No scenarios match the current filters.
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => setSelected(s)}
              className="text-left rounded-2xl border border-[#2d333b] bg-[#15181e] p-5 hover:border-[#8e51df]/50 hover:bg-[#181c24] transition-colors group"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="text-[10px] font-mono text-[#8e51df] tracking-wide">{s.id}</div>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider ${severityChipTone[s.severity]}`}
                >
                  {s.severity}
                </span>
              </div>
              <h2 className="text-base font-bold text-white mt-1 leading-snug">{s.name}</h2>
              <div className="flex flex-wrap items-center gap-1.5 mt-2 text-[10px] uppercase tracking-wider">
                <span className="px-2 py-0.5 rounded-full bg-[#0b0c10] border border-[#2d333b] text-[#cbd5e1]">
                  {s.category}
                </span>
                <span className="px-2 py-0.5 rounded-full bg-[#0b0c10] border border-[#2d333b] text-[#94a3b8]">
                  {surfaceIcon[s.attackSurface] ?? s.attackSurface.toUpperCase()}
                </span>
              </div>
              <p className="text-xs text-[#94a3b8] mt-3 line-clamp-3">{s.summary}</p>
              <div className="grid grid-cols-2 gap-2 mt-4 text-[10px] uppercase tracking-wider text-[#64748b]">
                <div>
                  <div>Requests</div>
                  <div className="text-white font-mono text-xs mt-0.5">{s.requestCount}</div>
                </div>
                <div>
                  <div>Jobs</div>
                  <div className="text-white font-mono text-xs mt-0.5">{s.jobCount}</div>
                </div>
              </div>
              <div className="flex items-center justify-between mt-4 pt-3 border-t border-[#2d333b] text-xs text-[#94a3b8] group-hover:text-white">
                <span>View details</span>
                <ArrowRight size={14} />
              </div>
            </button>
          ))}
        </div>
      )}

      {selected && (
        <ScenarioDrawer scenario={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
};

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <label className="relative">
      <span className="sr-only">{label}</span>
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

function ScenarioDrawer({ scenario, onClose }: { scenario: Scenario; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-40 flex">
      <button
        type="button"
        aria-label="Close"
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside className="relative ml-auto h-full w-full max-w-2xl bg-[#0f1115] border-l border-[#2d333b] overflow-y-auto p-6 z-10">
        <div className="flex items-start justify-between gap-2">
          <div>
            <div className="text-xs font-mono text-[#8e51df]">{scenario.id}</div>
            <h2 className="text-2xl font-bold text-white mt-1">{scenario.name}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 hover:bg-[#1a1d24] text-[#94a3b8] hover:text-white"
          >
            <X size={18} />
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 mt-3">
          <span className={`text-xs px-2 py-0.5 rounded-full border ${severityTone[scenario.severity]}`}>
            <ShieldAlert size={12} className="inline -mt-0.5 mr-1" />
            {scenario.severity.toUpperCase()}
          </span>
          <span className="text-xs px-2 py-0.5 rounded-full border border-[#2d333b] bg-[#15181e] text-[#cbd5e1]">
            <Layers size={12} className="inline -mt-0.5 mr-1" />
            {scenario.category}
          </span>
          <span className="text-xs px-2 py-0.5 rounded-full border border-[#2d333b] bg-[#15181e] text-[#94a3b8]">
            <TargetIcon size={12} className="inline -mt-0.5 mr-1" />
            {scenario.attackSurface}
          </span>
          <span className="text-xs px-2 py-0.5 rounded-full border border-[#2d333b] bg-[#15181e] text-[#94a3b8]">
            <Repeat size={12} className="inline -mt-0.5 mr-1" />
            {scenario.jobCount} jobs / {scenario.requestCount} requests
          </span>
        </div>

        <Section title="Operator goal">
          <p className="text-sm text-[#cbd5e1] leading-relaxed">{scenario.operatorGoal}</p>
        </Section>

        <Section title="Summary">
          <p className="text-sm text-[#cbd5e1] leading-relaxed">{scenario.summary}</p>
        </Section>

        <Section title="Current signals">
          <ChipList items={scenario.currentSignals} />
        </Section>

        <Section title="Telemetry expectations">
          <ul className="text-sm text-[#cbd5e1] space-y-1 list-disc list-inside">
            {scenario.telemetryExpectations.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </Section>

        <Section title="Safety contract">
          <ul className="text-sm text-[#cbd5e1] space-y-1 list-disc list-inside">
            {scenario.safetyNotes.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </Section>

        <Section title={`Requests (${scenario.requests.length})`}>
          <div className="space-y-3">
            {scenario.requests.map((req) => (
              <div key={req.id} className="rounded-lg border border-[#2d333b] bg-[#15181e] p-3">
                <div className="flex items-center gap-2 text-xs">
                  <span className="font-mono px-2 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-[#8e51df]">
                    {req.method}
                  </span>
                  <code className="font-mono text-[#cbd5e1] truncate">{req.path}</code>
                  {req.repeatCount && req.repeatCount > 1 && (
                    <span className="ml-auto text-[10px] text-[#94a3b8]">
                      ×{req.repeatCount}
                    </span>
                  )}
                </div>
                <div className="text-sm text-white font-semibold mt-2">{req.label}</div>
                <p className="text-xs text-[#94a3b8] mt-1">{req.rationale}</p>
                {req.expected?.verdicts && req.expected.verdicts.length > 0 && (
                  <div className="mt-2 text-[10px] uppercase tracking-wider">
                    <span className="text-[#64748b]">Expected verdicts: </span>
                    {req.expected.verdicts.map((v) => (
                      <span
                        key={v}
                        className="inline-block ml-1 px-1.5 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-[#cbd5e1] font-mono"
                      >
                        {v}
                      </span>
                    ))}
                  </div>
                )}
                {req.requestTags && req.requestTags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {req.requestTags.map((tag) => (
                      <span
                        key={tag}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-[#94a3b8]"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>

        <div className="mt-6 pt-4 border-t border-[#2d333b]">
          <Link
            to="/campaigns"
            className="inline-flex items-center gap-2 rounded-lg border border-[#8e51df]/40 bg-[#8e51df]/10 px-3 py-2 text-sm text-white hover:bg-[#8e51df]/20"
          >
            Launch this scenario in Campaigns
            <ArrowRight size={14} />
          </Link>
        </div>
      </aside>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-5">
      <h3 className="text-xs uppercase tracking-wider text-[#8e51df] font-bold flex items-center gap-2 mb-2">
        <ListTree size={12} /> {title}
      </h3>
      {children}
    </section>
  );
}

function ChipList({ items }: { items: string[] }) {
  if (!items?.length) return <p className="text-sm text-[#64748b]">—</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((it) => (
        <span
          key={it}
          className="text-xs px-2 py-0.5 rounded-full bg-[#15181e] border border-[#2d333b] text-[#cbd5e1]"
        >
          {it}
        </span>
      ))}
    </div>
  );
}

export default ScenarioCatalog;
