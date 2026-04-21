import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  Loader2,
  Network,
  Radar,
  RefreshCw,
  Server,
  ShieldCheck,
  Target as TargetIcon,
  XCircle,
} from 'lucide-react';
import {
  normalizeDeepScanResult,
  normalizeOperatorTargetInput,
  normalizeScanErrorResponse,
  type DeepScanResult,
} from '../../../shared/scanContract';
import { ApiError, apiFetchJson, openSignedDownload } from '../lib/api';

type DiscoveryService = {
  id: string;
  port: number;
  protocol: string;
  bannerSummary: string | null;
  evidenceSource: string | null;
  firstSeen: string;
  lastSeen: string;
  target: { id: string; hostname: string; displayName: string | null; environment: string | null } | null;
};

type DiscoveryReport = {
  id: string;
  targetHostname: string;
  title: string;
  durationMs: number;
  totalFindings: number;
  modulesRun: number;
  modulesSucceeded: number;
  modulesFailed: number;
  createdAt: string;
};

type Asset = {
  id: string;
  hostname: string;
  displayName: string | null;
  environment: string | null;
  approvalStatus: string;
};

type Phase = 'idle' | 'running' | 'done' | 'error';

const Discovery = () => {
  const [target, setTarget] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [services, setServices] = useState<DiscoveryService[]>([]);
  const [recentReports, setRecentReports] = useState<DiscoveryReport[]>([]);
  const [approvedAssets, setApprovedAssets] = useState<Asset[]>([]);
  const [lastResult, setLastResult] = useState<DeepScanResult | null>(null);
  const [lastReportId, setLastReportId] = useState<string | null>(null);
  const [lastServicesPersisted, setLastServicesPersisted] = useState<number>(0);
  const [refreshing, setRefreshing] = useState(false);

  const activeRequest = useRef<AbortController | null>(null);

  const loadAll = async (silent = false) => {
    if (silent) setRefreshing(true);
    try {
      const [servicesRes, reportsRes, assetsRes] = await Promise.all([
        apiFetchJson<{ services?: DiscoveryService[] }>('/discovery/services'),
        apiFetchJson<{ reports?: DiscoveryReport[] }>('/discovery/reports'),
        apiFetchJson<{ assets?: Asset[] }>('/assets'),
      ]);
      setServices(Array.isArray(servicesRes.data.services) ? servicesRes.data.services : []);
      setRecentReports(Array.isArray(reportsRes.data.reports) ? reportsRes.data.reports : []);
      setApprovedAssets(
        Array.isArray(assetsRes.data.assets)
          ? assetsRes.data.assets.filter((asset) => asset.approvalStatus === 'approved')
          : [],
      );
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load discovery data.');
    } finally {
      if (silent) setRefreshing(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!cancelled) await loadAll();
    })();
    return () => {
      cancelled = true;
      activeRequest.current?.abort();
    };
  }, []);

  const runDiscovery = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const normalized = normalizeOperatorTargetInput(target);
    if (!normalized) {
      setError('Enter a valid hostname or label.');
      setPhase('error');
      return;
    }

    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;

    setError(null);
    setPhase('running');
    setLastReportId(null);
    setLastServicesPersisted(0);

    try {
      const { data } = await apiFetchJson<{
        result: unknown;
        reportId?: string;
        servicesPersisted?: number;
      }>('/discovery/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: normalized }),
        signal: controller.signal,
      });
      const normalizedResult = normalizeDeepScanResult(data.result, normalized);
      setLastResult(normalizedResult);
      setLastReportId(data.reportId ?? null);
      setLastServicesPersisted(data.servicesPersisted ?? 0);
      setPhase('done');
      void loadAll(true);
    } catch (e) {
      if (controller.signal.aborted) return;
      if (e instanceof ApiError) {
        const normalizedError = normalizeScanErrorResponse(e.data, normalized);
        setLastResult(normalizedError.result);
        setError(normalizedError.error);
      } else {
        setError(e instanceof Error ? e.message : 'Discovery request failed.');
      }
      setPhase('error');
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
      }
    }
  };

  const servicesByHost = useMemo(() => {
    const map = new Map<string, DiscoveryService[]>();
    for (const service of services) {
      const host = service.target?.hostname ?? 'unknown';
      if (!map.has(host)) map.set(host, []);
      map.get(host)!.push(service);
    }
    return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [services]);

  const moduleResults = lastResult?.moduleResults ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
          <Radar className="text-[#8e51df]" size={28} />
          Discovery & exposure visibility
        </h1>
        <p className="text-[#94a3b8] mt-2 max-w-3xl">
          Run a non-intrusive recon pipeline (DNS, TLS, port exposure) against an approved asset.
          Discovered services are persisted to the asset registry; every run produces an HTML and
          PDF report under Reports.
        </p>
      </div>

      <form
        onSubmit={runDiscovery}
        className="bg-[#15181e] border border-[#2d333b] rounded-2xl p-6 shadow-xl space-y-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-8">
            <label className="block text-sm font-bold tracking-wide text-[#a1a1aa] mb-2 uppercase">
              Approved asset (hostname or alias)
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <TargetIcon size={18} className="text-[#8e51df]" />
              </div>
              <input
                type="text"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                onBlur={() => setTarget((current) => normalizeOperatorTargetInput(current))}
                placeholder="example-app.example.com"
                list="approved-asset-list"
                className="w-full bg-[#0b0c10] border border-[#2d333b] rounded-lg focus:border-[#8e51df] pl-10 pr-3 py-3 text-white outline-none"
              />
              <datalist id="approved-asset-list">
                {approvedAssets.map((asset) => (
                  <option key={asset.id} value={asset.hostname}>
                    {asset.displayName ?? asset.hostname}
                  </option>
                ))}
              </datalist>
            </div>
          </div>
          <div className="md:col-span-4">
            <button
              type="submit"
              disabled={phase === 'running' || !target.trim()}
              className="w-full h-[52px] mt-7 rounded-lg bg-gradient-to-r from-[#6a2bba] to-[#8e51df] hover:from-[#7a32cf] hover:to-[#9b62e6] font-extrabold text-sm tracking-wide flex items-center justify-center gap-2 uppercase disabled:opacity-50"
            >
              {phase === 'running' ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  Discovering…
                </>
              ) : (
                <>
                  <Radar size={18} />
                  Run Discovery
                </>
              )}
            </button>
          </div>
        </div>
        <p className="text-xs text-[#64748b]">
          Modules run: <span className="font-mono">discoveryScanner</span>,{' '}
          <span className="font-mono">tlsScanner</span>,{' '}
          <span className="font-mono">serviceExposureScanner</span>. Bound by the same allowlist
          policy as the application assessment engine.
        </p>
      </form>

      {error && phase === 'error' && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-100 flex items-start gap-2">
          <AlertTriangle size={18} className="text-amber-300 mt-0.5" />
          <div>
            <div className="font-semibold">Discovery did not complete cleanly</div>
            <div className="mt-1">{error}</div>
          </div>
        </div>
      )}

      {phase === 'done' && lastResult && (
        <div className="space-y-4">
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100 flex flex-wrap items-center gap-2">
            <CheckCircle2 size={18} className="text-emerald-400" />
            <span className="font-semibold">Discovery complete for</span>
            <span className="font-mono">{lastResult.executionMeta.target}</span>
            <span className="text-xs">in {lastResult.executionMeta.scanDurationMs} ms</span>
            <span className="text-xs">| {lastServicesPersisted} services persisted</span>
            {lastReportId && (
              <span className="ml-auto flex gap-2">
                <button
                  type="button"
                  onClick={async () => {
                    const err = await openSignedDownload(
                      `/api/reports/${lastReportId}/html`,
                      { expectMime: 'text/html' },
                    );
                    if (err) setError(err);
                  }}
                  className="inline-flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-200 hover:bg-emerald-500/20"
                >
                  <ExternalLink size={12} /> View report
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    const err = await openSignedDownload(
                      `/api/reports/${lastReportId}/pdf`,
                      { expectMime: 'application/pdf' },
                    );
                    if (err) setError(err);
                  }}
                  className="inline-flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-200 hover:bg-emerald-500/20"
                >
                  <Download size={12} /> PDF
                </button>
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
              <div className="text-xs text-[#94a3b8] uppercase tracking-wider">Origin IPv4</div>
              <div className="font-mono text-emerald-400 text-lg mt-1">
                {lastResult.reconData.ip}
              </div>
            </div>
            <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
              <div className="text-xs text-[#94a3b8] uppercase tracking-wider">TLS Issuer</div>
              <div className="font-semibold text-white truncate">{lastResult.reconData.tlsIssuer}</div>
              <div className="text-xs text-[#8e51df] font-mono mt-1">
                Valid to {lastResult.reconData.tlsValidTo}
              </div>
            </div>
            <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
              <div className="text-xs text-[#94a3b8] uppercase tracking-wider">Modules</div>
              <div className="text-white text-lg font-bold mt-1">
                {lastResult.scanSummary.completedModules}/{lastResult.scanSummary.totalModules}{' '}
                <span className="text-xs text-[#94a3b8] font-normal">complete</span>
              </div>
              {lastResult.scanSummary.failedModules > 0 && (
                <div className="text-xs text-amber-300 mt-1">
                  {lastResult.scanSummary.failedModules} module(s) failed — see trace
                </div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
            <h3 className="text-white font-bold mb-2 flex items-center gap-2">
              <Network size={16} className="text-[#8e51df]" /> Module trace
            </h3>
            <div className="space-y-2">
              {moduleResults.map((moduleResult) => (
                <div
                  key={`${moduleResult.moduleName}-${moduleResult.startedAt}`}
                  className="flex flex-wrap items-center gap-3 text-sm border border-[#2d333b]/60 bg-[#0f1115] rounded-lg px-3 py-2"
                >
                  {moduleResult.status === 'success' ? (
                    <CheckCircle2 size={16} className="text-emerald-400" />
                  ) : moduleResult.status === 'partial' ? (
                    <AlertTriangle size={16} className="text-yellow-400" />
                  ) : (
                    <XCircle size={16} className="text-rose-400" />
                  )}
                  <span className="font-bold text-white">{moduleResult.moduleName}</span>
                  <span className="text-xs text-[#94a3b8]">{moduleResult.sourceTool}</span>
                  <span className="text-xs text-emerald-300">CF {moduleResult.confidence}%</span>
                  <span className="text-xs text-[#64748b]">
                    {Math.max(0, moduleResult.endedAt - moduleResult.startedAt)} ms
                  </span>
                  <span className="text-xs text-[#cbd5e1] flex-1 truncate">
                    {moduleResult.normalizedEvidence}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Server className="text-[#8e51df]" size={20} />
          Discovered services ({services.length})
        </h2>
        <button
          onClick={() => void loadAll(true)}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-lg border border-[#2d333b] bg-[#15181e] px-3 py-1.5 text-xs text-[#cbd5e1] hover:bg-[#1e232b] disabled:opacity-50"
        >
          {refreshing ? <Loader2 className="animate-spin" size={14} /> : <RefreshCw size={14} />}
          Refresh
        </button>
      </div>

      {servicesByHost.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-6 text-center text-[#94a3b8] text-sm">
          No services discovered yet. Run a discovery against an approved asset to populate this
          inventory.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {servicesByHost.map(([host, hostServices]) => (
            <div key={host} className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4">
              <div className="flex items-center gap-2 mb-3">
                <ShieldCheck size={16} className="text-emerald-400" />
                <span className="font-bold text-white">{host}</span>
                {hostServices[0]?.target?.environment && (
                  <span className="text-[10px] uppercase tracking-wider text-[#94a3b8] bg-[#2d333b] px-1.5 py-0.5 rounded">
                    {hostServices[0].target.environment}
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 gap-2 text-sm">
                {hostServices.map((service) => (
                  <div
                    key={service.id}
                    className="rounded border border-[#2d333b]/70 bg-[#0f1115] px-3 py-2 flex items-center gap-3"
                  >
                    <span className="font-mono text-emerald-400 font-bold">
                      {service.port}/{service.protocol}
                    </span>
                    <span className="flex-1 text-xs text-[#cbd5e1] truncate">
                      {service.bannerSummary || 'No banner observed.'}
                    </span>
                    <span className="text-[10px] text-[#64748b]">
                      {service.evidenceSource ?? 'unknown source'} · seen{' '}
                      {new Date(service.lastSeen).toLocaleDateString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <h2 className="text-xl font-bold text-white flex items-center gap-2 mt-8">
        Recent discovery reports
      </h2>
      {recentReports.length === 0 ? (
        <p className="text-sm text-[#94a3b8]">No discovery reports recorded yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-[#2d333b] text-[#94a3b8] uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Findings</th>
                <th className="px-4 py-3">Modules</th>
                <th className="px-4 py-3">Duration</th>
                <th className="px-4 py-3">Run at</th>
                <th className="px-4 py-3 text-right">Download</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d333b]">
              {recentReports.map((report) => (
                <tr key={report.id} className="hover:bg-[#1a1d24]/80">
                  <td className="px-4 py-3 font-mono text-xs text-[#cbd5e1]">
                    {report.targetHostname}
                  </td>
                  <td className="px-4 py-3 text-[#cbd5e1]">{report.totalFindings}</td>
                  <td className="px-4 py-3 text-xs text-[#cbd5e1]">
                    {report.modulesSucceeded}/{report.modulesRun}
                    {report.modulesFailed > 0 && (
                      <span className="text-amber-300"> · {report.modulesFailed} failed</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-[#94a3b8]">{report.durationMs} ms</td>
                  <td className="px-4 py-3 text-xs text-[#94a3b8]">
                    {new Date(report.createdAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={async () => {
                        const err = await openSignedDownload(
                          `/api/reports/${report.id}/html`,
                          { expectMime: 'text/html' },
                        );
                        if (err) setError(err);
                      }}
                      className="inline-flex items-center gap-1 rounded border border-[#2d333b] bg-[#0b0c10] px-2 py-1 text-xs text-[#cbd5e1] hover:bg-[#1e232b] mr-2"
                    >
                      <ExternalLink size={12} /> HTML
                    </button>
                    <button
                      type="button"
                      onClick={async () => {
                        const err = await openSignedDownload(
                          `/api/reports/${report.id}/pdf`,
                          { expectMime: 'application/pdf' },
                        );
                        if (err) setError(err);
                      }}
                      className="inline-flex items-center gap-1 rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-xs text-rose-200 hover:bg-rose-500/20"
                    >
                      <Download size={12} /> PDF
                    </button>
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

export default Discovery;
