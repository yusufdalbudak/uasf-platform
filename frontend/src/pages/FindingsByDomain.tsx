import { useCallback, useEffect, useMemo, useState } from 'react';
import { Loader2, RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';
import { apiFetchJson } from '../lib/api';

type DomainFinding = {
  id: string;
  severity: string;
  confidence: string;
  category: string;
  title: string;
  technicalSummary: string | null;
  evidenceSummary: string | null;
  endpoint: string | null;
  status: string;
  findingDomain: string;
  createdAt: string;
  asset: { id: string; hostname: string; displayName: string | null } | null;
};

type Props = {
  /** Lower-case finding domain stored in the SecurityFinding table. */
  domain: 'sast' | 'dependency' | 'ioc' | 'malware' | 'exposure';
  /** Display heading. */
  title: string;
  /** Sub-heading shown below the title. */
  description: string;
  /** Title-side icon. */
  icon: ReactNode;
  /** Empty-state copy that explains what would populate this page in production. */
  emptyMessage: string;
};

const sevClass = (sev: string) => {
  switch (sev.toLowerCase()) {
    case 'critical':
      return 'bg-rose-500/15 text-rose-300 border-rose-500/30';
    case 'high':
      return 'bg-orange-500/15 text-orange-300 border-orange-500/30';
    case 'medium':
      return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30';
    case 'low':
      return 'bg-blue-500/15 text-blue-300 border-blue-500/30';
    default:
      return 'bg-[#2d333b] text-[#cbd5e1] border-[#2d333b]';
  }
};

const FindingsByDomain = ({ domain, title, description, icon, emptyMessage }: Props) => {
  const [findings, setFindings] = useState<DomainFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (silent = false) => {
      if (silent) setRefreshing(true);
      else setLoading(true);
      setError(null);
      try {
        const { data } = await apiFetchJson<{ findings?: DomainFinding[] }>(
          `/findings/by-domain/${domain}`,
        );
        setFindings(Array.isArray(data.findings) ? data.findings : []);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : 'Failed to load findings.');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [domain],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!cancelled) await load();
    })();
    return () => {
      cancelled = true;
    };
  }, [load]);

  const counts = useMemo(() => {
    const out = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    for (const finding of findings) {
      const key = (finding.severity ?? 'Info').replace(/^./, (c) => c.toUpperCase());
      if ((out as Record<string, number>)[key] !== undefined) {
        (out as Record<string, number>)[key] += 1;
      }
    }
    return out;
  }, [findings]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            {icon}
            {title}
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">{description}</p>
        </div>
        <button
          onClick={() => void load(true)}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-lg border border-[#2d333b] bg-[#15181e] px-3 py-2 text-sm text-[#cbd5e1] hover:bg-[#1e232b] disabled:opacity-50"
        >
          {refreshing ? <Loader2 className="animate-spin" size={16} /> : <RefreshCw size={16} />}
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {(['Critical', 'High', 'Medium', 'Low', 'Info'] as const).map((sev) => (
          <div key={sev} className="rounded-lg border border-[#2d333b] bg-[#15181e] px-4 py-3">
            <div className="text-[10px] uppercase tracking-wider text-[#94a3b8] font-bold">{sev}</div>
            <div className={`text-2xl font-black mt-1 ${sevClass(sev).split(' ')[1] ?? ''}`}>
              {counts[sev]}
            </div>
          </div>
        ))}
      </div>

      {loading ? (
        <p className="text-[#94a3b8]">Loading findings…</p>
      ) : findings.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-10 text-center text-[#94a3b8]">
          <p className="font-semibold text-white">No findings recorded for this domain</p>
          <p className="text-sm mt-2 max-w-2xl mx-auto">{emptyMessage}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((finding) => (
            <article
              key={finding.id}
              className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4"
            >
              <header className="flex flex-wrap items-center gap-2 mb-2">
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${sevClass(finding.severity)}`}
                >
                  {finding.severity}
                </span>
                <span className="text-[10px] uppercase text-[#94a3b8] tracking-wider">
                  {finding.category}
                </span>
                <span className="text-[10px] text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">
                  CF: {finding.confidence}
                </span>
                {finding.endpoint && (
                  <span className="font-mono text-[10px] text-[#cbd5e1]">{finding.endpoint}</span>
                )}
                <span className="ml-auto text-[10px] text-[#64748b]">
                  {new Date(finding.createdAt).toLocaleString()}
                </span>
              </header>
              <h3 className="font-bold text-white">{finding.title}</h3>
              {finding.technicalSummary && (
                <p className="text-sm text-[#cbd5e1] mt-2 leading-relaxed">
                  {finding.technicalSummary}
                </p>
              )}
              {finding.evidenceSummary && (
                <pre className="text-xs font-mono text-blue-200 bg-[#0b0c10] border border-[#2d333b] rounded-lg p-3 mt-2 whitespace-pre-wrap">
                  {finding.evidenceSummary}
                </pre>
              )}
              {finding.asset && (
                <div className="mt-2 text-xs text-[#94a3b8]">
                  Asset: <span className="font-mono">{finding.asset.hostname}</span>
                </div>
              )}
            </article>
          ))}
        </div>
      )}
    </div>
  );
};

export default FindingsByDomain;
