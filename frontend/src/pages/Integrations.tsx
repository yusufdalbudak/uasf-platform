import { useEffect, useState } from 'react';
import { CheckCircle2, Loader2, Plug, RefreshCw, XCircle, AlertTriangle } from 'lucide-react';
import { apiFetchJson } from '../lib/api';

type Check = {
  id: string;
  name: string;
  kind: string;
  status: 'ok' | 'degraded' | 'down';
  detail?: string | null;
};

type StatusResponse = {
  service: string;
  version: string;
  checks: Check[];
};

const statusIcon = (status: Check['status']) => {
  if (status === 'ok') return <CheckCircle2 className="text-emerald-400" size={18} />;
  if (status === 'degraded') return <AlertTriangle className="text-yellow-400" size={18} />;
  return <XCircle className="text-rose-400" size={18} />;
};

const statusColor = (status: Check['status']): string => {
  if (status === 'ok') return 'border-emerald-500/30 bg-emerald-500/5';
  if (status === 'degraded') return 'border-yellow-500/30 bg-yellow-500/5';
  return 'border-rose-500/30 bg-rose-500/5';
};

const Integrations = () => {
  const [data, setData] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const { data: payload } = await apiFetchJson<StatusResponse>('/integrations/status');
      setData(payload);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load integrations.');
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
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Plug className="text-[#8e51df]" size={28} />
            Integrations
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Live health of the platform back-ends UASF depends on. Each row reflects a real probe
            (no static text) so operators can confirm the queue, datastore and adapters are
            reachable before launching a campaign.
          </p>
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

      {loading || !data ? (
        <p className="text-[#94a3b8]">Probing back-ends…</p>
      ) : (
        <>
          <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4 text-sm text-[#cbd5e1]">
            Service: <span className="font-mono text-white">{data.service}</span>{' '}
            <span className="text-[#64748b]">v{data.version}</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {data.checks.map((check) => (
              <div
                key={check.id}
                className={`rounded-xl border ${statusColor(check.status)} p-4`}
              >
                <div className="flex items-center gap-3">
                  {statusIcon(check.status)}
                  <div>
                    <div className="font-bold text-white">{check.name}</div>
                    <div className="text-xs text-[#94a3b8] uppercase tracking-wider">
                      {check.kind} · {check.status}
                    </div>
                  </div>
                </div>
                {check.detail && (
                  <pre className="mt-3 text-xs text-[#cbd5e1] font-mono whitespace-pre-wrap">
                    {check.detail}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

export default Integrations;
