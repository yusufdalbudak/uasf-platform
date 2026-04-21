import { useEffect, useState } from 'react';
import { Server, ShieldCheck, Tag } from 'lucide-react';
import AddTargetForm from '../components/AddTargetForm';
import { apiFetchJson } from '../lib/api';

type Alias = { id: string; label: string; kind: string };
type Discovered = { id: string; port: number; protocol: string; bannerSummary: string | null };

type Asset = {
  id: string;
  hostname: string;
  displayName: string | null;
  assetType: string;
  environment: string | null;
  approvalStatus: string;
  assetCriticality: string;
  apptranaAlias: string | null;
  scanPolicy: string | null;
  tags: string[] | null;
  aliases: Alias[];
  discoveredServices?: Discovered[];
};

const Targets = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadAssets = async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) {
      setLoading(true);
      setError(null);
    }

    try {
      const { data } = await apiFetchJson<{ assets?: Asset[] }>('/assets');
      setAssets(data.assets ?? []);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load assets.');
    } finally {
      if (!opts?.silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      if (!cancelled) {
        await loadAssets();
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
          <Server className="text-[#8e51df]" size={28} />
          Approved asset registry
        </h1>
        <p className="text-[#94a3b8] mt-2 max-w-3xl">
          Executable assessments bind to these records. Hostnames are network targets; edge/WAAP aliases are
          correlation metadata only.
        </p>
      </div>

      <AddTargetForm variant="full" onRegistered={() => void loadAssets({ silent: true })} />

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-[#94a3b8]">Loading assets…</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-[#2d333b] text-[#94a3b8] uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3">Hostname</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Environment</th>
                <th className="px-4 py-3">Approval</th>
                <th className="px-4 py-3">Criticality</th>
                <th className="px-4 py-3">Edge/WAAP alias</th>
                <th className="px-4 py-3">Exposure signals</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d333b]">
              {assets.map((a) => (
                <tr key={a.id} className="hover:bg-[#1a1d24]/80">
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{a.hostname}</div>
                    <div className="text-xs text-[#64748b]">{a.displayName}</div>
                    {a.tags && a.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {a.tags.map((t) => (
                          <span
                            key={t}
                            className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded bg-[#2d333b] text-[#94a3b8]"
                          >
                            <Tag size={10} /> {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[#cbd5e1]">{a.assetType}</td>
                  <td className="px-4 py-3 text-[#cbd5e1]">{a.environment ?? '—'}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${
                        a.approvalStatus === 'approved'
                          ? 'bg-emerald-500/15 text-emerald-400'
                          : 'bg-amber-500/15 text-amber-200'
                      }`}
                    >
                      <ShieldCheck size={12} />
                      {a.approvalStatus}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[#cbd5e1]">{a.assetCriticality}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[#94a3b8]">
                    {a.apptranaAlias ?? a.aliases?.[0]?.label ?? '—'}
                  </td>
                  <td className="px-4 py-3 text-[#94a3b8]">
                    {a.discoveredServices?.length ?? 0} services
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {assets.length === 0 && !error && (
            <p className="p-8 text-center text-[#64748b]">No assets in registry.</p>
          )}
        </div>
      )}
    </div>
  );
};

export default Targets;
