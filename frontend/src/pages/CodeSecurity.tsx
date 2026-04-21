import { useEffect, useMemo, useState } from 'react';
import {
  Code2,
  Loader2,
  Search,
  ChevronDown,
  AlertTriangle,
  GitBranch,
  Wrench,
  Upload,
  X,
} from 'lucide-react';
import { ApiError, apiFetchJson } from '../lib/api';

type CodeFinding = {
  id: string;
  repository: string;
  ref: string | null;
  tool: string;
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string | null;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  status: 'open' | 'triaged' | 'accepted_risk' | 'fixed' | 'wont_fix';
  cwe: string | null;
  remediation: string | null;
  rawSnippet: string | null;
  createdAt: string;
};

type Summary = {
  total: number;
  bySeverity: Record<string, number>;
  byRepository: Record<string, number>;
};

const severityTone: Record<CodeFinding['severity'], string> = {
  critical: 'border-rose-500/40 bg-rose-500/10 text-rose-200',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-200',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-200',
  info: 'border-slate-500/40 bg-slate-500/10 text-slate-200',
};

const CodeSecurity = () => {
  const [items, setItems] = useState<CodeFinding[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [repository, setRepository] = useState<string>('all');
  const [severity, setSeverity] = useState<string>('all');
  const [showIngest, setShowIngest] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, sum] = await Promise.all([
        apiFetchJson<{ items: CodeFinding[] }>('/code-security/findings?take=300'),
        apiFetchJson<Summary>('/code-security/summary'),
      ]);
      setItems(Array.isArray(list.data.items) ? list.data.items : []);
      setSummary(sum.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load SAST findings.');
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

  const repos = useMemo(
    () => Array.from(new Set(items.map((i) => i.repository))).sort(),
    [items],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((i) => {
      if (repository !== 'all' && i.repository !== repository) return false;
      if (severity !== 'all' && i.severity !== severity) return false;
      if (!q) return true;
      const hay =
        `${i.title} ${i.description ?? ''} ${i.ruleId} ${i.filePath ?? ''} ${i.cwe ?? ''}`.toLowerCase();
      return hay.includes(q);
    });
  }, [items, search, repository, severity]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Code2 className="text-[#8e51df]" size={28} />
            Code security (SAST)
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Static-analysis findings normalized from SARIF v2 reports produced by your CI pipeline
            (CodeQL, Semgrep, Bandit, ESLint, Trivy, etc.). Findings are grouped by repository and
            severity, with rule, file location, and remediation guidance.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowIngest(true)}
          className="inline-flex items-center gap-2 rounded-lg border border-[#8e51df]/40 bg-[#8e51df]/10 px-3 py-2 text-sm text-white hover:bg-[#8e51df]/20"
        >
          <Upload size={16} /> Ingest SARIF
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <KpiCard label="Total findings" value={summary?.total ?? 0} tone="text-white" />
        <KpiCard label="Critical" value={summary?.bySeverity?.critical ?? 0} tone="text-rose-200" />
        <KpiCard label="High" value={summary?.bySeverity?.high ?? 0} tone="text-orange-200" />
        <KpiCard label="Medium" value={summary?.bySeverity?.medium ?? 0} tone="text-amber-200" />
        <KpiCard label="Low" value={summary?.bySeverity?.low ?? 0} tone="text-sky-200" />
        <KpiCard
          label="Repositories"
          value={Object.keys(summary?.byRepository ?? {}).length}
          tone="text-violet-200"
        />
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[#2d333b] bg-[#15181e] p-3">
        <div className="relative flex-1 min-w-[260px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by title, rule, file, CWE…"
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#8e51df]/60"
          />
        </div>
        <FilterSelect
          value={repository}
          onChange={setRepository}
          options={[{ value: 'all', label: 'All repositories' }, ...repos.map((r) => ({ value: r, label: r }))]}
        />
        <FilterSelect
          value={severity}
          onChange={setSeverity}
          options={[
            { value: 'all', label: 'All severities' },
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
            { value: 'info', label: 'Info' },
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

      {loading ? (
        <p className="text-[#94a3b8]">Loading findings…</p>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-10 text-center text-[#94a3b8]">
          {items.length === 0 ? (
            <>
              <p className="font-semibold text-white">No SAST findings yet</p>
              <p className="text-sm mt-2 max-w-2xl mx-auto">
                Push a SARIF v2 document to{' '}
                <code className="font-mono text-emerald-300">POST /api/code-security/sarif</code>{' '}
                from your CI pipeline, or click <b>Ingest SARIF</b> to upload one manually.
              </p>
            </>
          ) : (
            <p>No findings match the current filters.</p>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}

      {showIngest && (
        <SarifIngestDrawer
          onClose={() => setShowIngest(false)}
          onSuccess={() => {
            setShowIngest(false);
            void load();
          }}
        />
      )}
    </div>
  );
};

function FindingCard({ finding }: { finding: CodeFinding }) {
  return (
    <article className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4 hover:border-[#8e51df]/40">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`text-[10px] uppercase tracking-wider font-bold px-2 py-0.5 rounded-full border ${severityTone[finding.severity]}`}
        >
          {finding.severity}
        </span>
        <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-[#cbd5e1]">
          {finding.tool}
        </span>
        <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-[#8e51df]">
          {finding.ruleId}
        </span>
        {finding.cwe && (
          <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#0b0c10] border border-[#2d333b] text-amber-200">
            {finding.cwe}
          </span>
        )}
        <span className="text-xs text-[#94a3b8] ml-auto inline-flex items-center gap-1">
          <GitBranch size={12} /> {finding.repository}
          {finding.ref ? ` · ${finding.ref}` : ''}
        </span>
      </div>
      <h3 className="text-sm font-bold text-white mt-2">{finding.title}</h3>
      {finding.description && (
        <p className="text-xs text-[#cbd5e1] mt-1 line-clamp-3">{finding.description}</p>
      )}
      {finding.filePath && (
        <div className="mt-2 text-[11px] font-mono text-emerald-300">
          {finding.filePath}
          {finding.lineStart ? `:${finding.lineStart}` : ''}
          {finding.lineEnd && finding.lineEnd !== finding.lineStart ? `-${finding.lineEnd}` : ''}
        </div>
      )}
      {finding.rawSnippet && (
        <pre className="mt-2 rounded-lg border border-[#2d333b] bg-[#0b0c10] p-2 text-[11px] font-mono text-[#cbd5e1] overflow-x-auto whitespace-pre-wrap">
          {finding.rawSnippet}
        </pre>
      )}
      {finding.remediation && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-2 text-[11px] text-emerald-100">
          <Wrench size={14} className="mt-0.5 text-emerald-300" />
          <div>{finding.remediation}</div>
        </div>
      )}
      <div className="text-[10px] text-[#64748b] mt-3">
        Status: <span className="font-mono text-[#cbd5e1]">{finding.status}</span> · Ingested:{' '}
        {new Date(finding.createdAt).toLocaleString()}
      </div>
    </article>
  );
}

function SarifIngestDrawer({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [repo, setRepo] = useState('');
  const [ref, setRef] = useState('');
  const [text, setText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const submit = async () => {
    setErr(null);
    setOk(null);
    if (!repo.trim()) {
      setErr('Repository is required.');
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setErr('SARIF document must be valid JSON.');
      return;
    }
    setSubmitting(true);
    try {
      const { data } = await apiFetchJson<{ created: number; updated: number }>(
        '/code-security/sarif',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repository: repo.trim(), ref: ref.trim() || null, sarif: parsed }),
        },
      );
      setOk(`Ingested ${data.created} new, ${data.updated} updated findings.`);
      window.setTimeout(() => onSuccess(), 700);
    } catch (e) {
      if (e instanceof ApiError) setErr(e.message);
      else setErr(e instanceof Error ? e.message : 'Ingest failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 flex">
      <button
        type="button"
        aria-label="Close"
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside className="relative ml-auto h-full w-full max-w-xl bg-[#0f1115] border-l border-[#2d333b] overflow-y-auto p-6 z-10">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-xl font-bold text-white">Ingest SARIF document</h2>
            <p className="text-xs text-[#94a3b8] mt-1">
              Paste a SARIF v2 report from your CI pipeline. Findings will be normalized and stored.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 hover:bg-[#1a1d24] text-[#94a3b8] hover:text-white"
          >
            <X size={18} />
          </button>
        </div>

        <div className="mt-4 space-y-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider text-[#94a3b8]">Repository</label>
            <input
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              placeholder="org/repo or local path"
              className="w-full mt-1 px-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#8e51df]/60"
            />
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-[#94a3b8]">Ref (optional)</label>
            <input
              value={ref}
              onChange={(e) => setRef(e.target.value)}
              placeholder="branch or commit sha"
              className="w-full mt-1 px-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#8e51df]/60"
            />
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-[#94a3b8]">SARIF JSON</label>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={14}
              placeholder='{"version": "2.1.0", "runs": [...]}'
              className="w-full mt-1 px-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-xs font-mono text-white placeholder:text-[#64748b] focus:outline-none focus:border-[#8e51df]/60"
            />
          </div>
          {err && (
            <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-100">
              {err}
            </div>
          )}
          {ok && (
            <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-100">
              {ok}
            </div>
          )}
          <button
            type="button"
            onClick={() => void submit()}
            disabled={submitting}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-[#6a2bba] to-[#8e51df] px-4 py-2 text-sm font-bold text-white hover:from-[#8e51df] hover:to-[#a372eb] disabled:opacity-50"
          >
            {submitting ? (
              <>
                <Loader2 className="animate-spin" size={16} /> Ingesting…
              </>
            ) : (
              <>
                <Upload size={16} /> Ingest
              </>
            )}
          </button>
        </div>
      </aside>
    </div>
  );
}

function KpiCard({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
      <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">{label}</div>
      <div className={`text-2xl font-extrabold mt-1 ${tone}`}>{value}</div>
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

export default CodeSecurity;
