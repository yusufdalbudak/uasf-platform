import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Globe,
  Loader2,
  Lock,
  Network,
  Search,
  Shield,
  Target,
  Terminal,
  XCircle,
} from 'lucide-react';
import {
  normalizeDeepScanResult,
  normalizeOperatorTargetInput,
  normalizeScanErrorResponse,
  type AssessmentModuleResult,
  type DeepScanResult,
  type ScanFinding,
} from '../../../shared/scanContract';
import { ApiError, apiFetchJson } from '../lib/api';

type ScannerPhase = 'idle' | 'running' | 'done' | 'error';
type ScannerTab = 'overview' | 'taxonomy' | 'evidence';

type ScannerErrorState = {
  message: string;
  code?: string;
  target: string;
};

type CurrentRun = {
  requestId: number;
  target: string;
};

type CompletedRunMeta = {
  target: string;
  finishedAt: number;
  outcome: 'done' | 'error';
};

const FuzzingLog = ({ target }: { target: string }) => {
  const [logs, setLogs] = useState<string[]>([]);

  useEffect(() => {
    const sequence = [
      'Initializing modular validation orchestrator...',
      'Validating profile against enterprise allowance database...',
      `Target accepted: ${target}`,
      '[M01] Bootstrapping discoveryScanner & IP routing logic...',
      '[M02] Bootstrapping tlsScanner for Crypto Integrity...',
      '[M03] Bootstrapping headerAssessment ...',
      '[M04] Executing serviceExposureScanner (Stealth SYN)...',
      '[M05] Engaging webAssessment fingerprint heuristics...',
      'Aggregating and normalizing evidence traces...',
      'Evaluating strict risk probabilities (FindingScorer)...',
      'Compilation complete.',
    ];
    let i = 0;
    const interval = window.setInterval(() => {
      setLogs((prev) => [...prev, sequence[i]]);
      i += 1;
      if (i >= sequence.length) {
        window.clearInterval(interval);
      }
    }, 400);

    return () => window.clearInterval(interval);
  }, [target]);

  return (
    <div className="bg-[#0b0c10] border border-[#2d333b] rounded-xl p-5 font-mono text-[11px] md:text-sm h-64 overflow-y-auto w-full text-emerald-400 shadow-[inset_0_4px_24px_rgba(0,0,0,0.5)] flex flex-col justify-end">
      {logs.map((line, index) => (
        <div key={`${line}-${index}`} className="opacity-90">
          {'>'} {line}
        </div>
      ))}
      <div className="animate-pulse">{'>'} _</div>
    </div>
  );
};

const VulnerabilityRow = ({ finding }: { finding: ScanFinding }) => {
  const [open, setOpen] = useState(false);

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'text-rose-500 bg-rose-500/10 border-rose-500/30';
      case 'High':
        return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
      case 'Medium':
        return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
      case 'Low':
        return 'text-blue-400 bg-blue-400/10 border-blue-400/30';
      default:
        return 'text-[#94a3b8] bg-[#2d333b]/50 border-[#2d333b]';
    }
  };

  return (
    <div className="bg-[#15181e] border border-[#2d333b] rounded-xl overflow-hidden mb-3 hover:border-[#8e51df]/50 transition-all duration-300 group">
      <div className="p-5 flex gap-4 items-center cursor-pointer" onClick={() => setOpen((prev) => !prev)}>
        <div
          className={`shrink-0 w-24 text-center text-xs font-black py-1.5 rounded border uppercase tracking-widest ${getSeverityStyle(finding.severity)}`}
        >
          {finding.severity}
        </div>
        <div className="flex-1 font-semibold text-[#e2e8f0] text-base group-hover:text-white transition-colors">
          {finding.title}
        </div>
        <div className="hidden md:flex items-center gap-2">
          {typeof finding.confidence === 'number' && (
            <span className="text-xs tracking-wider text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded border border-emerald-400/20">
              CF: {finding.confidence}%
            </span>
          )}
          <div className="text-xs font-bold tracking-widest uppercase text-[#64748b] bg-[#1e232b] px-3 py-1 rounded text-center">
            {finding.category}
          </div>
        </div>
        <div className="text-[#64748b] group-hover:text-white transition-colors">
          {open ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>
      </div>

      {open && (
        <div className="p-6 bg-[#0f1115] border-t border-[#2d333b] space-y-5 text-sm">
          <div className="flex items-start gap-4">
            <span className="font-bold text-white min-w-[120px] tracking-wide">DESCRIPTION:</span>
            <span className="text-[#a1a1aa] leading-relaxed">{finding.description}</span>
          </div>
          {finding.cwe && (
            <div className="flex items-center gap-4">
              <span className="font-bold text-white min-w-[120px] tracking-wide">THREAT SPEC:</span>
              <span className="text-rose-400 font-mono text-xs bg-rose-400/10 px-2 py-1 rounded border border-rose-400/20">
                {finding.cwe}
              </span>
            </div>
          )}
          {finding.evidence && (
            <div className="flex items-start gap-4">
              <span className="font-bold text-white min-w-[120px] tracking-wide">TRACE LOG:</span>
              <div className="flex-1 bg-[#0b0c10] border border-[#2d333b] rounded-lg p-4 font-mono text-xs text-blue-300 overflow-x-auto whitespace-pre-wrap">
                {finding.evidence}
              </div>
            </div>
          )}
          {finding.remediation && (
            <div className="flex items-start gap-4 mt-6 pt-5 border-t border-[#2d333b] border-dashed">
              <span className="font-bold text-emerald-400 min-w-[120px] tracking-wide">REMEDIATION:</span>
              <span className="text-[#a1a1aa] italic leading-relaxed">{finding.remediation}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const EvidenceRow = ({ moduleResult }: { moduleResult: AssessmentModuleResult }) => {
  const [open, setOpen] = useState(false);
  const duration =
    moduleResult.endedAt && moduleResult.startedAt ? moduleResult.endedAt - moduleResult.startedAt : 0;

  return (
    <div className="bg-[#15181e] border border-[#2d333b] rounded-xl overflow-hidden mb-4">
      <div
        className="p-5 flex gap-4 items-center cursor-pointer hover:bg-[#1e232b] transition-colors"
        onClick={() => setOpen((prev) => !prev)}
      >
        <div className="shrink-0 flex items-center justify-center">
          {moduleResult.status === 'success' ? (
            <CheckCircle2 size={24} className="text-emerald-500" />
          ) : moduleResult.status === 'partial' ? (
            <AlertTriangle size={24} className="text-yellow-500" />
          ) : (
            <XCircle size={24} className="text-rose-500" />
          )}
        </div>
        <div className="flex-1">
          <div className="text-white font-bold tracking-wide">{moduleResult.moduleName}</div>
          <div className="text-[#8e51df] font-mono text-xs mt-1">
            Tool: {moduleResult.sourceTool} | Confidence: {moduleResult.confidence}% | Duration: {duration}ms
          </div>
        </div>
        <div className="text-xs font-bold uppercase text-[#64748b] bg-[#0b0c10] px-3 py-1 rounded">
          {moduleResult.findings.length} Findings
        </div>
        <div className="text-[#64748b]">{open ? <ChevronUp size={20} /> : <ChevronDown size={20} />}</div>
      </div>
      {open && (
        <div className="p-6 bg-[#0f1115] border-t border-[#2d333b]">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h4 className="text-white font-bold text-sm mb-3">Normalized Evidence</h4>
              <div className="bg-[#0b0c10] p-4 rounded-lg font-mono text-xs text-emerald-400 border border-[#2d333b]">
                {moduleResult.normalizedEvidence || 'No normalized evidence'}
              </div>

              {moduleResult.errors && moduleResult.errors.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-white font-bold text-sm mb-3">Module Errors</h4>
                  <div className="bg-rose-500/10 p-4 rounded-lg font-mono text-xs text-rose-400 border border-rose-500/20">
                    {moduleResult.errors.map((error, index) => (
                      <div key={`${error}-${index}`}>[ERROR] {error}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
            <div>
              <h4 className="text-white font-bold text-sm mb-3">Raw Source Output</h4>
              <div className="bg-[#0b0c10] p-4 rounded-lg font-mono text-xs text-[#a1a1aa] border border-[#2d333b] h-48 overflow-y-auto whitespace-pre-wrap">
                {moduleResult.rawEvidence || '<empty>'}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

function hasRenderableResult(result: DeepScanResult | null): result is DeepScanResult {
  // Any normalized result is renderable; per UASF lifecycle rules the page
  // must never silently fall back to the initial empty state. An empty result
  // becomes a "completed assessment with no findings" panel, not an invisible
  // state. A null result (no run ever started) returns false.
  return result !== null;
}

const Scanner = () => {
  const [target, setTarget] = useState('juiceshopnew.testapptrana.net');
  const [phase, setPhase] = useState<ScannerPhase>('idle');
  const [allowedKeys, setAllowedKeys] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<ScannerTab>('overview');
  const [currentRun, setCurrentRun] = useState<CurrentRun | null>(null);
  const [lastCompletedResult, setLastCompletedResult] = useState<DeepScanResult | null>(null);
  const [lastError, setLastError] = useState<ScannerErrorState | null>(null);
  const [completedRun, setCompletedRun] = useState<CompletedRunMeta | null>(null);

  const requestSequenceRef = useRef(0);
  const activeControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const { data } = await apiFetchJson<{ keys?: unknown }>('/policy/allowed-target-keys');
        if (cancelled) {
          return;
        }

        setAllowedKeys(Array.isArray(data.keys) ? data.keys.filter((key): key is string => typeof key === 'string') : []);
      } catch {
        if (!cancelled) {
          setAllowedKeys([]);
        }
      }
    })();

    return () => {
      cancelled = true;
      activeControllerRef.current?.abort();
    };
  }, []);

  const runScan = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const normalizedTarget = normalizeOperatorTargetInput(target);
    if (!normalizedTarget) {
      setLastError({
        message: 'Enter a valid hostname or URL.',
        code: 'INVALID_SCAN_TARGET',
        target: '',
      });
      setPhase('error');
      return;
    }

    activeControllerRef.current?.abort();

    const requestId = requestSequenceRef.current + 1;
    requestSequenceRef.current = requestId;

    const controller = new AbortController();
    activeControllerRef.current = controller;

    setTarget(normalizedTarget);
    setLastError(null);
    setCurrentRun({ requestId, target: normalizedTarget });
    setPhase('running');

    try {
      const { data } = await apiFetchJson<unknown>('/scan/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: normalizedTarget }),
        signal: controller.signal,
      });

      if (requestId !== requestSequenceRef.current) {
        return;
      }

      const normalizedResult = normalizeDeepScanResult(data, normalizedTarget);
      setLastCompletedResult(normalizedResult);
      setLastError(null);
      setActiveTab('overview');
      setCompletedRun({ target: normalizedTarget, finishedAt: Date.now(), outcome: 'done' });
      setPhase('done');
    } catch (error) {
      if (controller.signal.aborted || requestId !== requestSequenceRef.current) {
        return;
      }

      if (error instanceof ApiError) {
        const normalizedError = normalizeScanErrorResponse(error.data, normalizedTarget);
        // Always commit the normalized error result so the UI does not appear
        // to silently reset; an empty result still produces a visible
        // "completed with no findings" panel.
        setLastCompletedResult(normalizedError.result);
        setLastError({
          message: normalizedError.error,
          code: normalizedError.code,
          target: normalizedTarget,
        });
      } else {
        setLastError({
          message: error instanceof Error ? error.message : 'Assessment request failed.',
          target: normalizedTarget,
        });
      }
      setCompletedRun({ target: normalizedTarget, finishedAt: Date.now(), outcome: 'error' });
      setPhase('error');
    } finally {
      if (activeControllerRef.current === controller) {
        activeControllerRef.current = null;
      }
      setCurrentRun((prev) => (prev?.requestId === requestId ? null : prev));
    }
  };

  const displayResult = lastCompletedResult;
  const recon = displayResult?.reconData;
  const findings = displayResult?.findings ?? [];
  const moduleResults = displayResult?.moduleResults ?? [];
  const summary = displayResult?.scanSummary;
  const meta = displayResult?.executionMeta;
  const counts = {
    Critical: findings.filter((finding) => finding.severity === 'Critical').length,
    High: findings.filter((finding) => finding.severity === 'High').length,
    Medium: findings.filter((finding) => finding.severity === 'Medium').length,
    Low: findings.filter((finding) => finding.severity === 'Low').length,
  };

  return (
    <div className="space-y-8 max-w-6xl pb-10">
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-3 text-white">
          <div className="p-2 bg-gradient-to-br from-[#8e51df] to-[#6a2bba] rounded-lg shadow-[0_0_15px_rgba(142,81,223,0.4)]">
            <Search size={24} className="text-white" />
          </div>
          Application Assessment
        </h1>
        <p className="text-[#94a3b8] mt-3 tracking-wide">Enterprise modular validation orchestrator.</p>
      </div>

      {lastError && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
          <p className="font-semibold text-amber-50">Assessment did not complete cleanly</p>
          <p className="mt-1 text-amber-100/90">{lastError.message}</p>
          {lastError.code && (
            <p className="mt-2 text-xs font-mono uppercase tracking-wider text-amber-200/80">{lastError.code}</p>
          )}
        </div>
      )}

      {allowedKeys.length > 0 && (
        <p className="text-xs text-[#64748b]">
          Policy allowlist: <span className="font-mono text-[#94a3b8]">{allowedKeys.join(', ')}</span>
        </p>
      )}

      <form
        onSubmit={runScan}
        className="bg-[#15181e] border border-[#2d333b] rounded-2xl p-6 shadow-xl relative overflow-hidden"
      >
        <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-end relative z-10">
          <div className="md:col-span-8">
            <label className="block text-sm font-bold tracking-wide text-[#a1a1aa] mb-2 uppercase">
              Target Hostname
            </label>
            <div className="relative group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Target size={18} className="text-[#8e51df]" />
              </div>
              <input
                type="text"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                onBlur={() => setTarget((currentTarget) => normalizeOperatorTargetInput(currentTarget))}
                className="w-full bg-[#0b0c10] border border-[#2d333b] rounded-lg focus:border-[#8e51df] pl-12 pr-4 py-3.5 text-white font-medium outline-none"
              />
            </div>
          </div>
          <div className="md:col-span-4">
            <button
              type="submit"
              disabled={!target.trim()}
              className="w-full h-[52px] rounded-lg bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 font-extrabold text-sm tracking-wide shadow-[0_0_20px_rgba(225,29,72,0.3)] flex items-center justify-center gap-2 uppercase disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {phase === 'running' ? (
                <>
                  <Loader2 size={18} className="animate-spin text-white" />
                  Restart Assessment
                </>
              ) : (
                <>
                  <Terminal size={18} className="text-white" />
                  Launch Modular Scan
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {phase === 'running' && currentRun && (
        <div className="bg-[#15181e] border border-[#8e51df]/30 rounded-2xl p-6 shadow-[0_0_30px_rgba(142,81,223,0.1)] space-y-5">
          <h3 className="font-bold flex items-center gap-3 text-white text-lg tracking-wide">
            <Loader2 size={22} className="animate-spin text-[#8e51df]" /> Assessment in progress
          </h3>
          <p className="text-sm text-[#cbd5e1]">
            Executing modular validation against{' '}
            <span className="font-mono text-[#8e51df]">{currentRun.target}</span>. Results will persist on this page
            when the run completes.
          </p>
          {hasRenderableResult(displayResult) && (
            <p className="text-xs text-[#94a3b8]">
              Previous assessment results remain visible below until this run finishes.
            </p>
          )}
          <FuzzingLog key={`${currentRun.requestId}-${currentRun.target}`} target={currentRun.target} />
        </div>
      )}

      {(phase === 'done' || phase === 'error') && completedRun && (
        <div
          className={`rounded-xl border px-4 py-3 text-sm flex flex-wrap items-center gap-2 ${
            completedRun.outcome === 'done'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-100'
              : 'border-amber-500/40 bg-amber-500/10 text-amber-100'
          }`}
        >
          {completedRun.outcome === 'done' ? (
            <CheckCircle2 size={18} className="text-emerald-400" />
          ) : (
            <AlertTriangle size={18} className="text-amber-300" />
          )}
          <span className="font-semibold">
            Assessment {completedRun.outcome === 'done' ? 'completed' : 'returned an error'} for
          </span>
          <span className="font-mono">{completedRun.target}</span>
          <span className="text-xs opacity-80">
            at {new Date(completedRun.finishedAt).toLocaleTimeString()}
          </span>
        </div>
      )}

      {hasRenderableResult(displayResult) && recon && summary && meta && (
        <div className="space-y-6 animate-in slide-in-from-bottom-5 duration-500">
          <div className="flex flex-wrap items-center gap-2 border-b border-[#2d333b] pb-4">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-5 py-2.5 rounded-lg text-sm font-bold tracking-wide transition-colors ${activeTab === 'overview' ? 'bg-[#8e51df] text-white' : 'text-[#94a3b8] hover:text-white hover:bg-[#2d333b]/50'}`}
            >
              Execution Overview
            </button>
            <button
              onClick={() => setActiveTab('taxonomy')}
              className={`px-5 py-2.5 rounded-lg text-sm font-bold tracking-wide transition-colors ${activeTab === 'taxonomy' ? 'bg-rose-500 text-white' : 'text-[#94a3b8] hover:text-white hover:bg-[#2d333b]/50'}`}
            >
              Threat Taxonomy ({findings.length})
            </button>
            <button
              onClick={() => setActiveTab('evidence')}
              className={`px-5 py-2.5 rounded-lg text-sm font-bold tracking-wide transition-colors ${activeTab === 'evidence' ? 'bg-blue-500 text-white' : 'text-[#94a3b8] hover:text-white hover:bg-[#2d333b]/50'}`}
            >
              Module Trace Details
            </button>
          </div>

          {activeTab === 'overview' && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-[#15181e] border border-[#2d333b] rounded-xl p-5">
                  <div className="text-[#a1a1aa] text-xs font-bold uppercase tracking-wider mb-2">Duration</div>
                  <div className="text-3xl font-black text-white">
                    {meta.scanDurationMs} <span className="text-base text-[#64748b]">ms</span>
                  </div>
                </div>
                <div className="bg-[#15181e] border border-[#2d333b] rounded-xl p-5">
                  <div className="text-[#a1a1aa] text-xs font-bold uppercase tracking-wider mb-2">Modules Run</div>
                  <div className="text-3xl font-black text-white">{summary.totalModules}</div>
                  <div className="text-xs font-medium mt-1 text-emerald-400">
                    {summary.completedModules} Success / {summary.failedModules} Failed
                  </div>
                </div>
                <div className="bg-[#15181e] border border-[#2d333b] rounded-xl p-5">
                  <div className="text-[#a1a1aa] text-xs font-bold uppercase tracking-wider mb-2">Avg Confidence</div>
                  <div className="text-3xl font-black text-blue-400">{summary.averageConfidence}%</div>
                </div>
                <div className="bg-[#15181e] border border-[#2d333b] rounded-xl p-5">
                  <div className="text-[#a1a1aa] text-xs font-bold uppercase tracking-wider mb-2">Total Vectors</div>
                  <div className="text-3xl font-black text-rose-500">
                    {findings.length} <span className="text-base text-[#64748b]">risks</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
                <div
                  className={`p-6 rounded-2xl border ${counts.Critical > 0 ? 'bg-gradient-to-br from-[#1a0f14] to-[#2c0b14] border-rose-500/40 shadow-[0_0_30px_rgba(244,63,94,0.15)] relative overflow-hidden' : 'bg-[#15181e] border-[#2d333b]'}`}
                >
                  <div className={`text-5xl font-black mb-2 ${counts.Critical > 0 ? 'text-rose-500' : 'text-[#e2e8f0]'}`}>
                    {counts.Critical}
                  </div>
                  <div className="text-xs font-black uppercase tracking-widest text-[#a1a1aa]">Critical Risk</div>
                </div>
                <div
                  className={`p-6 rounded-2xl border ${counts.High > 0 ? 'bg-gradient-to-br from-[#1a130c] to-[#291405] border-orange-500/40 shadow-[0_0_30px_rgba(249,115,22,0.1)]' : 'bg-[#15181e] border-[#2d333b]'}`}
                >
                  <div className={`text-5xl font-black mb-2 ${counts.High > 0 ? 'text-orange-500' : 'text-[#e2e8f0]'}`}>
                    {counts.High}
                  </div>
                  <div className="text-xs font-black uppercase tracking-widest text-[#a1a1aa]">High Risk</div>
                </div>
                <div
                  className={`p-6 rounded-2xl border ${counts.Medium > 0 ? 'bg-gradient-to-br from-[#1a180b] to-[#2c2605] border-yellow-400/40' : 'bg-[#15181e] border-[#2d333b]'}`}
                >
                  <div className={`text-5xl font-black mb-2 ${counts.Medium > 0 ? 'text-yellow-400' : 'text-[#e2e8f0]'}`}>
                    {counts.Medium}
                  </div>
                  <div className="text-xs font-black uppercase tracking-widest text-[#a1a1aa]">Medium Risk</div>
                </div>
                <div
                  className={`p-6 rounded-2xl border ${counts.Low > 0 ? 'bg-[#0b121a] border-blue-400/30' : 'bg-[#15181e] border-[#2d333b]'}`}
                >
                  <div className={`text-5xl font-black mb-2 ${counts.Low > 0 ? 'text-blue-400' : 'text-[#e2e8f0]'}`}>
                    {counts.Low}
                  </div>
                  <div className="text-xs font-black uppercase tracking-widest text-[#a1a1aa]">Informational</div>
                </div>
              </div>

              <div className="bg-gradient-to-b from-[#15181e] to-[#0f1115] border border-[#2d333b] rounded-2xl overflow-hidden shadow-xl">
                <div className="p-7">
                  <h2 className="text-xl font-extrabold flex items-center gap-3 mb-6 text-white tracking-wide">
                    <Globe size={22} className="text-[#8e51df]" /> Topography Extracted
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                    <div className="space-y-2 p-4 bg-[#0b0c10]/50 rounded-xl border border-[#2d333b]/50">
                      <span className="text-xs text-[#a1a1aa] uppercase font-black tracking-widest">
                        <Network size={14} className="inline mr-1 text-[#8e51df]" /> Origin IPv4
                      </span>
                      <p className="font-mono text-xl text-emerald-400 font-bold">{recon.ip}</p>
                    </div>
                    <div className="space-y-2 p-4 bg-[#0b0c10]/50 rounded-xl border border-[#2d333b]/50">
                      <span className="text-xs text-[#a1a1aa] uppercase font-black tracking-widest">
                        <Lock size={14} className="inline mr-1 text-[#8e51df]" /> X.509
                      </span>
                      <p className="text-base font-bold text-white truncate">{recon.tlsIssuer}</p>
                      <p className="text-xs font-mono font-medium text-[#8e51df] mt-1">{recon.tlsValidTo}</p>
                    </div>
                    <div className="space-y-2 p-4 bg-[#0b0c10]/50 rounded-xl border border-[#2d333b]/50">
                      <span className="text-xs text-[#a1a1aa] uppercase font-black tracking-widest">Routing</span>
                      <div className="text-[12px] font-mono text-[#cbd5e1] space-y-1">
                        {recon.dnsDetails.length > 0 ? (
                          recon.dnsDetails.slice(0, 3).map((detail, index) => (
                            <div key={`${detail}-${index}`}>{detail}</div>
                          ))
                        ) : (
                          <div>No routing details available.</div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'taxonomy' && (
            <div className="space-y-4">
              {Array.isArray(findings) && findings.length > 0 ? (
                findings.map((finding) => <VulnerabilityRow key={finding.id} finding={finding} />)
              ) : (
                <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-6 text-sm text-[#94a3b8]">
                  No findings were produced for the last completed assessment.
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div>
              <div className="mb-6 flex gap-4">
                <div className="bg-[#15181e] rounded-lg border border-[#2d333b] px-5 py-3 flex-1 flex items-center gap-3">
                  <Shield size={24} className="text-[#8e51df]" />
                  <div>
                    <div className="text-[#a1a1aa] uppercase tracking-widest text-[10px] font-bold">Execution Traces</div>
                    <div className="text-white font-black text-xl">{moduleResults.length} Modules Engaged</div>
                  </div>
                </div>
              </div>
              <div className="space-y-4">
                {Array.isArray(moduleResults) && moduleResults.length > 0 ? (
                  moduleResults.map((moduleResult) => (
                    <EvidenceRow
                      key={`${moduleResult.moduleName}-${moduleResult.startedAt}`}
                      moduleResult={moduleResult}
                    />
                  ))
                ) : (
                  <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-6 text-sm text-[#94a3b8]">
                    No module traces were captured for the last completed assessment.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Scanner;
