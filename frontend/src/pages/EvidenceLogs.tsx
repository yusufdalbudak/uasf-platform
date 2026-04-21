import { useEffect, useState } from 'react';
import { FileText } from 'lucide-react';
import { apiFetchJson } from '../lib/api';

type Log = {
  id: string;
  campaignRunId: string;
  scenarioId: string;
  targetHostname: string;
  method: string;
  path: string;
  responseStatusCode: number;
  latencyMs: number;
  timestamp: string;
};

const EvidenceLogs = () => {
  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    const load = () => {
      void (async () => {
        try {
          const { data } = await apiFetchJson<Log[]>('/evidence');
          if (!cancelled) {
            setLogs(Array.isArray(data) ? data : []);
          }
        } finally {
          if (!cancelled) {
            setLoading(false);
          }
        }
      })();
    };
    load();
    const id = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
        <FileText className="text-[#8e51df]" size={28} />
        Evidence & logs
      </h1>
      <p className="text-[#94a3b8]">
        Normalized validation telemetry (UASF campaigns). Correlates with any configured edge / WAAP tenant logs.
      </p>
      {loading && logs.length === 0 ? (
        <p className="text-[#94a3b8]">Loading…</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e] text-sm">
          <table className="w-full">
            <thead className="border-b border-[#2d333b] text-[#94a3b8] text-xs uppercase">
              <tr>
                <th className="px-3 py-2 text-left">Time</th>
                <th className="px-3 py-2 text-left">Target</th>
                <th className="px-3 py-2 text-left">Scenario</th>
                <th className="px-3 py-2 text-left">Request</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d333b] font-mono text-xs">
              {logs.map((l) => (
                <tr key={l.id} className="hover:bg-[#1a1d24]/80">
                  <td className="px-3 py-2 text-[#94a3b8] whitespace-nowrap">
                    {new Date(l.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-[#cbd5e1] max-w-[180px] truncate">{l.targetHostname}</td>
                  <td className="px-3 py-2 text-[#8e51df]">{l.scenarioId}</td>
                  <td className="px-3 py-2 text-white">
                    {l.method} {l.path}
                  </td>
                  <td className="px-3 py-2">{l.responseStatusCode}</td>
                  <td className="px-3 py-2 text-[#94a3b8]">{l.latencyMs} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default EvidenceLogs;
