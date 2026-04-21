import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BookOpen,
  ChevronRight,
  Cpu,
  Download,
  ExternalLink,
  FileBarChart,
  History,
  Layers,
  Loader2,
  PlayCircle,
  Radar,
  RefreshCw,
  ShieldCheck,
  Target as TargetIcon,
} from 'lucide-react';
import { ApiError, apiFetchJson, openSignedDownload } from '../lib/api';

// ---------------------------------------------------------------------------
// Types — kept aligned with backend DTOs
// ---------------------------------------------------------------------------

type SignalFamily =
  | 'passive_http'
  | 'tls'
  | 'markup'
  | 'url_route'
  | 'dom_structural'
  | 'behavior'
  | 'service';

type AdapterFlags = {
  passiveHttp: boolean;
  markup: boolean;
  urlRoute: boolean;
  structural: boolean;
  behavior: boolean;
  service: boolean;
};

type FingerprintProfile = {
  id: string;
  name: string;
  description: string;
  probes: string[];
  enableNmap: boolean;
  adapters?: AdapterFlags;
};

type HardeningProfile = {
  id: string;
  name: string;
  description: string;
  probeCount: number;
  categories: string[];
};

type ProfilesPayload = {
  fingerprint: FingerprintProfile[];
  hardening: HardeningProfile[];
};

type TechIntelRunListItem = {
  id: string;
  targetKey: string;
  resolvedHostname: string;
  profileId: string;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed';
  technologyCount: number;
  correlationCount: number;
  highOrCriticalCount: number;
  durationMs: number;
  createdAt: string;
};

type DetectedTechnology = {
  id: string;
  productKey: string;
  productName: string;
  vendor: string | null;
  category: string;
  version: string | null;
  versionFamily: string | null;
  versionCertainty: 'exact' | 'probable' | 'family' | 'unknown';
  confidence: 'low' | 'medium' | 'high' | 'very_high';
  /** 0..100 fused probability score from the multi-signal confidence model. */
  confidenceScore?: number | null;
  /** Signal families whose observations contributed to this detection. */
  signalFamilies?: SignalFamily[] | null;
  /** Detection-method ids that fired for this detection. */
  detectionMethodIds?: string[] | null;
  /** Ids of {@link FingerprintObservation} rows that corroborated this detection. */
  observationIds?: string[] | null;
  evidence: Array<{ source: string; detail: string; matchedRule?: string }>;
};

type FingerprintObservation = {
  id: string;
  runId: string;
  family: SignalFamily;
  methodId: string;
  methodLabel: string;
  signalKey: string;
  signalValue: string;
  evidenceSnippet: string;
  productKey: string | null;
  versionLiteral: string | null;
  weight: number;
  vendorMatch: boolean;
  metadata: Record<string, unknown> | null;
  capturedAt: string;
};

type DetectionMethod = {
  id: string;
  label: string;
  family: SignalFamily;
  kind: 'passive' | 'active';
  description: string;
  owaspRef?: string | null;
  typicalWeight: number;
};

type VulnerabilityCorrelation = {
  id: string;
  detectedTechnologyId: string;
  productKey: string;
  detectedVersion: string | null;
  advisoryId: string;
  cveId: string | null;
  severityLabel: string;
  severityScore: number | null;
  summary: string;
  affectedRanges: string | null;
  fixedVersions: string | null;
  source: string;
  sourceUrl: string | null;
  strength: 'confirmed_version_match' | 'probable_version_match' | 'product_match_version_ambiguous' | 'text_match';
  certaintyLabel: string;
  /** More granular classification for the UI than {@link strength}. */
  matchType?: 'exact' | 'probable' | 'family' | 'ambiguous' | null;
  triageState: 'open' | 'confirmed' | 'false_positive' | 'mitigated' | 'risk_accepted';
};

type ExecutionTrace = {
  declaredProbes: string[];
  executedProbes: string[];
  httpProbed: boolean;
  tlsProbed: boolean;
  nmapProbed: boolean;
  probeErrors: string[];
};

type TechIntelRunDetail = {
  run: TechIntelRunListItem & {
    errorMessage: string | null;
    executionTrace: ExecutionTrace | null;
  };
  technologies: DetectedTechnology[];
  correlations: VulnerabilityCorrelation[];
  observations?: FingerprintObservation[];
  methodsExercised?: string[];
};

type WafValidationListItem = {
  id: string;
  targetKey: string;
  resolvedHostname: string;
  profileId: string;
  status: string;
  totalEvents: number;
  matchedEvents: number;
  partiallyMatchedEvents: number;
  mismatchedEvents: number;
  ambiguousEvents: number;
  durationMs: number;
  createdAt: string;
};

type WafValidationEvent = {
  id: string;
  probeId: string;
  probeLabel: string;
  category: string;
  method: string;
  path: string;
  responseStatus: number;
  responseDurationMs: number;
  observedVerdict: string;
  observedConfidence: number;
  expectedVerdicts: string;
  expectationOutcome: 'matched' | 'partially_matched' | 'mismatched' | 'ambiguous';
  expectationReasons: string[];
  bodyPreview: string | null;
  responseHeaders: Record<string, string>;
  errorMessage: string | null;
  verdictSignals: Array<{ source: string; name: string; detail?: string }>;
};

type WafValidationDetail = {
  run: WafValidationListItem & { errorMessage: string | null };
  events: WafValidationEvent[];
};

// ---------------------------------------------------------------------------
// Style helpers
// ---------------------------------------------------------------------------

const tabClass = (active: boolean) =>
  `px-4 py-2 text-sm font-medium rounded-md transition border ${
    active
      ? 'bg-[#6a2bba]/20 text-[#c4a8ee] border-[#6a2bba]/40'
      : 'bg-[#1a1d24] text-[#94a3b8] border-[#2d333b] hover:text-white hover:border-[#3d434b]'
  }`;

const severityToneMap: Record<string, string> = {
  Critical: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  High: 'bg-orange-500/15 text-orange-200 border-orange-500/30',
  Medium: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  Low: 'bg-sky-500/15 text-sky-200 border-sky-500/30',
};

const certaintyToneMap: Record<string, string> = {
  exact: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  probable: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  family: 'bg-sky-500/15 text-sky-200 border-sky-500/30',
  unknown: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

const confidenceToneMap: Record<string, string> = {
  very_high: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  high: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  medium: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  low: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

const strengthToneMap: Record<string, string> = {
  confirmed_version_match: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  probable_version_match: 'bg-orange-500/15 text-orange-200 border-orange-500/30',
  product_match_version_ambiguous: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  text_match: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

const expectationToneMap: Record<string, string> = {
  matched: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  partially_matched: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  mismatched: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  ambiguous: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

const familyToneMap: Record<SignalFamily, string> = {
  passive_http: 'bg-sky-500/15 text-sky-200 border-sky-500/30',
  tls: 'bg-indigo-500/15 text-indigo-200 border-indigo-500/30',
  markup: 'bg-violet-500/15 text-violet-200 border-violet-500/30',
  url_route: 'bg-teal-500/15 text-teal-200 border-teal-500/30',
  dom_structural: 'bg-fuchsia-500/15 text-fuchsia-200 border-fuchsia-500/30',
  behavior: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  service: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
};

const familyLabelMap: Record<SignalFamily, string> = {
  passive_http: 'Passive HTTP',
  tls: 'TLS',
  markup: 'Markup',
  url_route: 'URL / Route',
  dom_structural: 'DOM / Structural',
  behavior: 'Behavior',
  service: 'Service',
};

const matchTypeToneMap: Record<string, string> = {
  exact: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  probable: 'bg-orange-500/15 text-orange-200 border-orange-500/30',
  family: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  ambiguous: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

const verdictToneMap: Record<string, string> = {
  blocked: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  challenged: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  edge_mitigated: 'bg-violet-500/15 text-violet-200 border-violet-500/30',
  origin_rejected: 'bg-orange-500/15 text-orange-200 border-orange-500/30',
  allowed: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  network_error: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  ambiguous: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

const formatCategory = (c: string) =>
  c.replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());

/**
 * The fingerprint engine emits the structured field name as a prefix on
 * every header / cookie evidence row (e.g. `via: 1.1 …cloudfront.net`).
 * If we render those rows with only the generic source label ("header")
 * the operator sees two rows that *appear* identical even though their
 * underlying signal is completely different (`via` vs `x-amz-cf-id`).
 * Pulling the field name out and using it as the row's visual label
 * makes each evidence line unambiguously distinct.
 */
const splitEvidenceLabel = (source: string, detail: string): { label: string; value: string } => {
  const colon = detail.indexOf(':');
  if (colon > 0 && colon < 80 && (source === 'header' || source === 'cookie' || source === 'banner')) {
    const field = detail.slice(0, colon).trim();
    const value = detail.slice(colon + 1).trim();
    if (field && value) return { label: `${source} · ${field}`, value };
  }
  return { label: source, value: detail };
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type TabId =
  | 'overview'
  | 'fingerprints'
  | 'versions'
  | 'vulnerabilities'
  | 'hardening'
  | 'evidence'
  | 'methods'
  | 'history';

const TechIntel = () => {
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  const [profiles, setProfiles] = useState<ProfilesPayload | null>(null);

  const [targetKey, setTargetKey] = useState('');
  const [fingerprintProfileId, setFingerprintProfileId] = useState('');
  const [hardeningProfileId, setHardeningProfileId] = useState('');

  const [runs, setRuns] = useState<TechIntelRunListItem[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [runDetail, setRunDetail] = useState<TechIntelRunDetail | null>(null);
  const [loadingRun, setLoadingRun] = useState(false);
  const [launchingFingerprint, setLaunchingFingerprint] = useState(false);

  const [wafRuns, setWafRuns] = useState<WafValidationListItem[]>([]);
  const [selectedWafRunId, setSelectedWafRunId] = useState<string | null>(null);
  const [wafDetail, setWafDetail] = useState<WafValidationDetail | null>(null);
  const [loadingWaf, setLoadingWaf] = useState(false);
  const [launchingHardening, setLaunchingHardening] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [methodsCatalog, setMethodsCatalog] = useState<DetectionMethod[]>([]);

  /**
   * Authoritative overview metrics computed server-side from the underlying
   * tables (DISTINCT product/advisory counts, not sum-of-per-run-counters).
   * The previous OverviewTab summed per-run counters, which made
   * "Detected technologies" track the run count any time the same
   * technology was repeatedly rediscovered across runs and gave operators
   * the impression the cards were duplicates of each other.
   */
  const [overviewStats, setOverviewStats] = useState<{
    fingerprintRunCount: number;
    distinctTechnologyCount: number;
    distinctProductCount: number;
    totalCorrelationCount: number;
    distinctAdvisoryCount: number;
    highOrCriticalAdvisoryCount: number;
    wafRunCount: number;
    wafTotalEvents: number;
    wafMatchedEvents: number;
    wafPartiallyMatchedEvents: number;
    wafMismatchedEvents: number;
    wafAmbiguousEvents: number;
    lastFingerprintRunAt: string | null;
    lastWafRunAt: string | null;
  } | null>(null);

  // ---------------------------------------------------------------------------
  // Initial load: profiles + run lists
  // ---------------------------------------------------------------------------

  const loadProfiles = async () => {
    try {
      const res = await apiFetchJson<ProfilesPayload>('/tech-intel/profiles');
      setProfiles(res.data);
      if (res.data.fingerprint[0]) setFingerprintProfileId((id) => id || res.data.fingerprint[0].id);
      if (res.data.hardening[0]) setHardeningProfileId((id) => id || res.data.hardening[0].id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load profiles.');
    }
  };

  const loadRuns = async () => {
    try {
      const res = await apiFetchJson<{ items: TechIntelRunListItem[] }>('/tech-intel/runs');
      setRuns(Array.isArray(res.data.items) ? res.data.items : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load runs.');
    }
  };

  const loadWafRuns = async () => {
    try {
      const res = await apiFetchJson<{ items: WafValidationListItem[] }>('/tech-intel/waf/runs');
      setWafRuns(Array.isArray(res.data.items) ? res.data.items : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load WAF runs.');
    }
  };

  const loadMethodsCatalog = async () => {
    try {
      const res = await apiFetchJson<{ methods: DetectionMethod[] }>('/tech-intel/methods');
      setMethodsCatalog(Array.isArray(res.data.methods) ? res.data.methods : []);
    } catch (err) {
      console.warn('Failed to load detection methods catalog:', err);
      setMethodsCatalog([]);
    }
  };

  const loadOverviewStats = async () => {
    try {
      const res = await apiFetchJson<NonNullable<typeof overviewStats>>('/tech-intel/overview');
      setOverviewStats(res.data);
    } catch (err) {
      // Overview stats are non-critical: fall back to client-side aggregation
      // rather than blocking the whole page on this single endpoint.
      setOverviewStats(null);
      console.warn('Failed to load tech-intel overview stats:', err);
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (cancelled) return;
      await Promise.all([
        loadProfiles(),
        loadRuns(),
        loadWafRuns(),
        loadOverviewStats(),
        loadMethodsCatalog(),
      ]);
    })();
    return () => {
      cancelled = true;
    };
    // Mount-only loader: each load function is stable and re-creates the
    // request from current state when called via the buttons / launch flows.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---------------------------------------------------------------------------
  // Selected detail loaders
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!selectedRunId) {
      return;
    }
    let cancelled = false;
    void (async () => {
      setLoadingRun(true);
      try {
        const res = await apiFetchJson<TechIntelRunDetail>(`/tech-intel/runs/${selectedRunId}`);
        if (!cancelled) setRunDetail(res.data);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load run detail.');
        }
      } finally {
        if (!cancelled) setLoadingRun(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedRunId]);

  useEffect(() => {
    if (!selectedWafRunId) {
      return;
    }
    let cancelled = false;
    void (async () => {
      setLoadingWaf(true);
      try {
        const res = await apiFetchJson<WafValidationDetail>(`/tech-intel/waf/runs/${selectedWafRunId}`);
        if (!cancelled) setWafDetail(res.data);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load WAF run detail.');
        }
      } finally {
        if (!cancelled) setLoadingWaf(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedWafRunId]);

  // ---------------------------------------------------------------------------
  // Launch actions
  // ---------------------------------------------------------------------------

  const launchFingerprint = async () => {
    if (!targetKey.trim() || !fingerprintProfileId) {
      setError('Pick an approved target and a profile.');
      return;
    }
    setError(null);
    setNotice(null);
    setLaunchingFingerprint(true);
    try {
      const res = await apiFetchJson<{ runId: string; status: string }>('/tech-intel/runs', {
        method: 'POST',
        body: JSON.stringify({ targetKey: targetKey.trim(), profileId: fingerprintProfileId }),
        headers: { 'Content-Type': 'application/json' },
      });
      setNotice(`Fingerprint run ${res.data.runId.slice(0, 8)}… complete (${res.data.status}).`);
      await Promise.all([loadRuns(), loadOverviewStats()]);
      setSelectedRunId(res.data.runId);
      setActiveTab('fingerprints');
    } catch (err) {
      if (err instanceof ApiError) {
        const data = err.data as { error?: string; code?: string } | null;
        setError(data?.error ?? err.message);
      } else {
        setError(err instanceof Error ? err.message : 'Run failed.');
      }
    } finally {
      setLaunchingFingerprint(false);
    }
  };

  const launchHardening = async () => {
    if (!targetKey.trim() || !hardeningProfileId) {
      setError('Pick an approved target and a profile.');
      return;
    }
    setError(null);
    setNotice(null);
    setLaunchingHardening(true);
    try {
      const res = await apiFetchJson<{ runId: string; status: string }>('/tech-intel/waf/runs', {
        method: 'POST',
        body: JSON.stringify({ targetKey: targetKey.trim(), profileId: hardeningProfileId }),
        headers: { 'Content-Type': 'application/json' },
      });
      setNotice(`WAF hardening run ${res.data.runId.slice(0, 8)}… complete (${res.data.status}).`);
      await Promise.all([loadWafRuns(), loadOverviewStats()]);
      setSelectedWafRunId(res.data.runId);
      setActiveTab('hardening');
    } catch (err) {
      if (err instanceof ApiError) {
        const data = err.data as { error?: string; code?: string } | null;
        setError(data?.error ?? err.message);
      } else {
        setError(err instanceof Error ? err.message : 'Run failed.');
      }
    } finally {
      setLaunchingHardening(false);
    }
  };

  /**
   * Open a Tech Intelligence report through the safe signed-URL +
   * Blob download flow.  We refuse to save a JSON error envelope as
   * `report.pdf` (which used to surface as "corrupted PDF") and surface
   * any backend rendering failure as an inline error in the page.
   */
  const downloadReport = async (runId: string, kind: 'html' | 'pdf') => {
    const errMessage = await openSignedDownload(
      `/api/tech-intel/runs/${runId}/report.${kind}`,
      { expectMime: kind === 'pdf' ? 'application/pdf' : 'text/html' },
    );
    if (errMessage) setError(errMessage);
  };

  // ---------------------------------------------------------------------------
  // Derived counts
  // ---------------------------------------------------------------------------

  const runStats = useMemo(() => {
    if (!runDetail) return null;
    const techByCertainty = runDetail.technologies.reduce<Record<string, number>>(
      (acc, t) => {
        acc[t.versionCertainty] = (acc[t.versionCertainty] ?? 0) + 1;
        return acc;
      },
      {},
    );
    return { techByCertainty };
  }, [runDetail]);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-md bg-gradient-to-br from-[#6a2bba] to-[#4d1c8c] flex items-center justify-center">
              <Radar className="text-white" size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Tech Intelligence</h1>
              <p className="text-sm text-[#94a3b8]">
                Vendor-agnostic technology fingerprinting, version-aware advisory correlation, and curated
                WAF hardening validation for approved targets only.
              </p>
            </div>
          </div>
        </div>
        <button
          onClick={() => {
            void loadRuns();
            void loadWafRuns();
            void loadOverviewStats();
          }}
          className="flex items-center gap-2 px-3 py-2 text-sm rounded-md border border-[#2d333b] bg-[#1a1d24] text-[#94a3b8] hover:text-white"
        >
          <RefreshCw size={14} />
          Reload runs
        </button>
      </div>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 text-rose-200 px-4 py-3 rounded-md text-sm flex items-start gap-2">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <div>{error}</div>
        </div>
      )}
      {notice && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-200 px-4 py-3 rounded-md text-sm">
          {notice}
        </div>
      )}

      <LaunchPanel
        targetKey={targetKey}
        onTargetKeyChange={setTargetKey}
        profiles={profiles}
        fingerprintProfileId={fingerprintProfileId}
        onFingerprintProfileChange={setFingerprintProfileId}
        hardeningProfileId={hardeningProfileId}
        onHardeningProfileChange={setHardeningProfileId}
        launchingFingerprint={launchingFingerprint}
        launchingHardening={launchingHardening}
        onLaunchFingerprint={() => void launchFingerprint()}
        onLaunchHardening={() => void launchHardening()}
      />

      <div className="flex flex-wrap gap-2">
        {(
          [
            { id: 'overview', label: 'Overview', icon: <Activity size={14} /> },
            { id: 'fingerprints', label: 'Fingerprints', icon: <Cpu size={14} /> },
            { id: 'versions', label: 'Versions', icon: <Layers size={14} /> },
            { id: 'vulnerabilities', label: 'Vulnerability correlation', icon: <AlertTriangle size={14} /> },
            { id: 'evidence', label: 'Evidence trace', icon: <FileBarChart size={14} /> },
            { id: 'methods', label: 'Detection methods', icon: <BookOpen size={14} /> },
            { id: 'history', label: 'Run history', icon: <History size={14} /> },
            { id: 'hardening', label: 'WAF Hardening Validation', icon: <ShieldCheck size={14} /> },
          ] as Array<{ id: TabId; label: string; icon: JSX.Element }>
        ).map((tab) => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} className={tabClass(activeTab === tab.id)}>
            <span className="inline-flex items-center gap-2">
              {tab.icon}
              {tab.label}
            </span>
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <OverviewTab
          runs={runs}
          wafRuns={wafRuns}
          stats={overviewStats}
          selectedRunId={selectedRunId}
          onSelectRun={(id) => {
            setSelectedRunId(id);
            setActiveTab('fingerprints');
          }}
          selectedWafRunId={selectedWafRunId}
          onSelectWafRun={(id) => {
            setSelectedWafRunId(id);
            setActiveTab('hardening');
          }}
        />
      )}

      {activeTab === 'fingerprints' && (
        <FingerprintsTab
          runs={runs}
          selectedRunId={selectedRunId}
          onSelectRun={setSelectedRunId}
          runDetail={runDetail}
          loading={loadingRun}
          onDownloadReport={(kind) => selectedRunId && void downloadReport(selectedRunId, kind)}
        />
      )}

      {activeTab === 'versions' && (
        <VersionsTab runDetail={runDetail} runStats={runStats} />
      )}

      {activeTab === 'vulnerabilities' && (
        <VulnerabilitiesTab runDetail={runDetail} />
      )}

      {activeTab === 'hardening' && (
        <HardeningTab
          wafRuns={wafRuns}
          selectedWafRunId={selectedWafRunId}
          onSelectWafRun={setSelectedWafRunId}
          wafDetail={wafDetail}
          loading={loadingWaf}
        />
      )}

      {activeTab === 'evidence' && (
        <EvidenceTab runDetail={runDetail} wafDetail={wafDetail} />
      )}

      {activeTab === 'methods' && (
        <MethodsTab
          catalog={methodsCatalog}
          runDetail={runDetail}
        />
      )}

      {activeTab === 'history' && (
        <HistoryTab
          runs={runs}
          wafRuns={wafRuns}
          selectedRunId={selectedRunId}
          onSelectRun={(id) => {
            setSelectedRunId(id);
            setActiveTab('fingerprints');
          }}
          selectedWafRunId={selectedWafRunId}
          onSelectWafRun={(id) => {
            setSelectedWafRunId(id);
            setActiveTab('hardening');
          }}
        />
      )}
    </div>
  );
};

export default TechIntel;

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const Card = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <div className={`bg-[#1a1d24] border border-[#2d333b] rounded-lg p-5 ${className ?? ''}`}>{children}</div>
);

const Pill = ({ children, tone }: { children: React.ReactNode; tone?: string }) => (
  <span
    className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[11px] font-medium tracking-wide ${
      tone ?? 'bg-slate-500/15 text-slate-300 border-slate-500/30'
    }`}
  >
    {children}
  </span>
);

const LaunchPanel = ({
  targetKey,
  onTargetKeyChange,
  profiles,
  fingerprintProfileId,
  onFingerprintProfileChange,
  hardeningProfileId,
  onHardeningProfileChange,
  launchingFingerprint,
  launchingHardening,
  onLaunchFingerprint,
  onLaunchHardening,
}: {
  targetKey: string;
  onTargetKeyChange: (v: string) => void;
  profiles: ProfilesPayload | null;
  fingerprintProfileId: string;
  onFingerprintProfileChange: (v: string) => void;
  hardeningProfileId: string;
  onHardeningProfileChange: (v: string) => void;
  launchingFingerprint: boolean;
  launchingHardening: boolean;
  onLaunchFingerprint: () => void;
  onLaunchHardening: () => void;
}) => {
  const fingerprintProfile = profiles?.fingerprint.find((p) => p.id === fingerprintProfileId);
  const hardeningProfile = profiles?.hardening.find((p) => p.id === hardeningProfileId);

  return (
    <Card>
      <div className="grid grid-cols-1 lg:grid-cols-[1fr,1fr,1fr] gap-4">
        <div className="space-y-2">
          <label className="text-[11px] tracking-wider text-[#94a3b8] uppercase flex items-center gap-2">
            <TargetIcon size={12} /> Approved target
          </label>
          <input
            type="text"
            value={targetKey}
            onChange={(e) => onTargetKeyChange(e.target.value)}
            placeholder="hostname or registered alias"
            className="w-full bg-[#0f1115] border border-[#2d333b] rounded-md px-3 py-2 text-sm focus:outline-none focus:border-[#6a2bba]"
          />
          <p className="text-[11px] text-[#64748b]">
            Only approved targets registered under <span className="text-[#94a3b8]">Targets</span> can run here.
          </p>
        </div>

        <div className="space-y-2">
          <label className="text-[11px] tracking-wider text-[#94a3b8] uppercase flex items-center gap-2">
            <Cpu size={12} /> Fingerprint profile
          </label>
          <select
            value={fingerprintProfileId}
            onChange={(e) => onFingerprintProfileChange(e.target.value)}
            className="w-full bg-[#0f1115] border border-[#2d333b] rounded-md px-3 py-2 text-sm focus:outline-none focus:border-[#6a2bba]"
          >
            {(profiles?.fingerprint ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          {fingerprintProfile && (
            <p className="text-[11px] text-[#64748b] line-clamp-2">{fingerprintProfile.description}</p>
          )}
          <button
            onClick={onLaunchFingerprint}
            disabled={launchingFingerprint || !targetKey || !fingerprintProfileId}
            className="w-full mt-1 px-3 py-2 rounded-md bg-[#6a2bba] hover:bg-[#7e36d1] disabled:bg-[#2d333b] disabled:text-[#64748b] text-white text-sm font-medium flex items-center justify-center gap-2 transition"
          >
            {launchingFingerprint ? <Loader2 size={14} className="animate-spin" /> : <PlayCircle size={14} />}
            Run fingerprint
          </button>
        </div>

        <div className="space-y-2">
          <label className="text-[11px] tracking-wider text-[#94a3b8] uppercase flex items-center gap-2">
            <ShieldCheck size={12} /> Hardening profile
          </label>
          <select
            value={hardeningProfileId}
            onChange={(e) => onHardeningProfileChange(e.target.value)}
            className="w-full bg-[#0f1115] border border-[#2d333b] rounded-md px-3 py-2 text-sm focus:outline-none focus:border-[#6a2bba]"
          >
            {(profiles?.hardening ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.probeCount})
              </option>
            ))}
          </select>
          {hardeningProfile && (
            <p className="text-[11px] text-[#64748b] line-clamp-2">{hardeningProfile.description}</p>
          )}
          <button
            onClick={onLaunchHardening}
            disabled={launchingHardening || !targetKey || !hardeningProfileId}
            className="w-full mt-1 px-3 py-2 rounded-md bg-[#1a1d24] border border-[#2d333b] hover:border-[#6a2bba] disabled:opacity-50 text-white text-sm font-medium flex items-center justify-center gap-2 transition"
          >
            {launchingHardening ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
            Run WAF validation
          </button>
        </div>
      </div>

      <div className="mt-4 pt-4 border-t border-[#2d333b] text-[11px] text-[#64748b] leading-relaxed">
        <strong className="text-[#94a3b8]">Safe by design.</strong> Profiles are curated and read-only; there is
        no operator-supplied payload field.  WAF hardening runs use canonical, well-published detection markers
        and never include bypass, evasion, decoy, fragmentation, spoofing, or proxy-rotation behaviour.
      </div>
    </Card>
  );
};

const OverviewTab = ({
  runs,
  wafRuns,
  stats: overviewStats,
  selectedRunId,
  onSelectRun,
  selectedWafRunId,
  onSelectWafRun,
}: {
  runs: TechIntelRunListItem[];
  wafRuns: WafValidationListItem[];
  stats: {
    fingerprintRunCount: number;
    distinctTechnologyCount: number;
    distinctProductCount: number;
    totalCorrelationCount: number;
    distinctAdvisoryCount: number;
    highOrCriticalAdvisoryCount: number;
    wafRunCount: number;
    wafTotalEvents: number;
    wafMatchedEvents: number;
    wafPartiallyMatchedEvents: number;
    wafMismatchedEvents: number;
    wafAmbiguousEvents: number;
    lastFingerprintRunAt: string | null;
    lastWafRunAt: string | null;
  } | null;
  selectedRunId: string | null;
  onSelectRun: (id: string) => void;
  selectedWafRunId: string | null;
  onSelectWafRun: (id: string) => void;
}) => {
  // Authoritative server-side numbers when available.  Each card is mapped
  // to a semantically distinct dataset so the values can never appear to
  // mirror each other by coincidence the way "sum of per-run counters"
  // did before.  The list-derived fallbacks are intentionally
  // approximate (per-run sums over-count duplicates) and are tagged in
  // the hint so operators don't read them as exact numbers.
  const usingApprox = !overviewStats;
  const fp = overviewStats?.fingerprintRunCount ?? runs.length;
  // Approximate fallback: per-run technology counts summed across all
  // recent runs.  Over-counts repeats but is a useful "non-zero"
  // hint when /tech-intel/overview is temporarily unavailable.
  const distinctTech =
    overviewStats?.distinctTechnologyCount ??
    runs.reduce((sum, r) => sum + (r.technologyCount ?? 0), 0);
  const distinctProduct = overviewStats?.distinctProductCount ?? distinctTech;
  const advisoryCount =
    overviewStats?.distinctAdvisoryCount ??
    runs.reduce((sum, r) => sum + (r.correlationCount ?? 0), 0);
  const highCritical =
    overviewStats?.highOrCriticalAdvisoryCount ??
    runs.reduce((sum, r) => sum + (r.highOrCriticalCount ?? 0), 0);
  const wafRunCount = overviewStats?.wafRunCount ?? wafRuns.length;
  const wafMatched =
    overviewStats?.wafMatchedEvents ??
    wafRuns.reduce((sum, r) => sum + (r.matchedEvents ?? 0), 0);
  const wafMismatched =
    overviewStats?.wafMismatchedEvents ??
    wafRuns.reduce((sum, r) => sum + (r.mismatchedEvents ?? 0), 0);
  const wafTotalEvents =
    overviewStats?.wafTotalEvents ??
    wafRuns.reduce((sum, r) => sum + (r.totalEvents ?? 0), 0);
  const approxTag = usingApprox ? ' (approx)' : '';

  const stats: {
    label: string;
    value: string | number;
    icon: JSX.Element;
    hint?: string;
  }[] = [
    {
      label: 'Fingerprint runs',
      value: fp,
      icon: <Cpu size={16} />,
      hint: overviewStats?.lastFingerprintRunAt
        ? `Last: ${new Date(overviewStats.lastFingerprintRunAt).toLocaleString()}`
        : undefined,
    },
    {
      label: 'Distinct technologies',
      value: distinctTech,
      icon: <Layers size={16} />,
      hint: `${distinctProduct} distinct products${approxTag}`,
    },
    {
      label: 'Distinct advisories',
      value: advisoryCount,
      icon: <AlertTriangle size={16} />,
      hint: overviewStats
        ? `${overviewStats.totalCorrelationCount} total correlations`
        : `${advisoryCount} approx (sum of per-run)`,
    },
    {
      label: 'High / Critical',
      value: highCritical,
      icon: <ShieldCheck size={16} />,
      hint: `Distinct advisories${approxTag}`,
    },
    {
      label: 'WAF runs',
      value: wafRunCount,
      icon: <Activity size={16} />,
      hint: overviewStats?.lastWafRunAt
        ? `Last: ${new Date(overviewStats.lastWafRunAt).toLocaleString()}`
        : undefined,
    },
    {
      label: 'WAF matched / mismatched',
      value: `${wafMatched} / ${wafMismatched}`,
      icon: <ChevronRight size={16} />,
      hint: `Across ${wafTotalEvents} events${approxTag}`,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {stats.map((s) => (
          <Card key={s.label} className="!p-4">
            <div className="flex items-center justify-between text-[#94a3b8]">
              <span className="text-[10px] tracking-wider uppercase">{s.label}</span>
              {s.icon}
            </div>
            <div className="text-2xl font-bold mt-2 text-white">{s.value}</div>
            {s.hint && (
              <div className="text-[10px] text-[#64748b] mt-1 truncate" title={s.hint}>
                {s.hint}
              </div>
            )}
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <h3 className="text-sm font-semibold text-white mb-3">Recent fingerprint runs</h3>
          {runs.length === 0 && <p className="text-sm text-[#64748b]">No runs yet.</p>}
          <div className="space-y-2">
            {runs.slice(0, 8).map((r) => (
              <button
                key={r.id}
                onClick={() => onSelectRun(r.id)}
                className={`w-full text-left px-3 py-2 rounded border transition ${
                  selectedRunId === r.id
                    ? 'border-[#6a2bba]/40 bg-[#6a2bba]/10'
                    : 'border-[#2d333b] hover:border-[#3d434b]'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-white truncate">{r.targetKey}</span>
                  <Pill tone={statusTone(r.status)}>{r.status}</Pill>
                </div>
                <div className="text-[11px] text-[#64748b] mt-1 flex flex-wrap gap-x-3 gap-y-1">
                  <span>{r.profileId}</span>
                  <span>tech: {r.technologyCount}</span>
                  <span>corr: {r.correlationCount}</span>
                  <span>H/C: {r.highOrCriticalCount}</span>
                  <span>{new Date(r.createdAt).toLocaleString()}</span>
                </div>
              </button>
            ))}
          </div>
        </Card>

        <Card>
          <h3 className="text-sm font-semibold text-white mb-3">Recent WAF hardening runs</h3>
          {wafRuns.length === 0 && <p className="text-sm text-[#64748b]">No runs yet.</p>}
          <div className="space-y-2">
            {wafRuns.slice(0, 8).map((r) => (
              <button
                key={r.id}
                onClick={() => onSelectWafRun(r.id)}
                className={`w-full text-left px-3 py-2 rounded border transition ${
                  selectedWafRunId === r.id
                    ? 'border-[#6a2bba]/40 bg-[#6a2bba]/10'
                    : 'border-[#2d333b] hover:border-[#3d434b]'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-white truncate">{r.targetKey}</span>
                  <Pill tone={statusTone(r.status)}>{r.status}</Pill>
                </div>
                <div className="text-[11px] text-[#64748b] mt-1 flex flex-wrap gap-x-3 gap-y-1">
                  <span>{r.profileId}</span>
                  <span>matched: {r.matchedEvents}</span>
                  <span>partial: {r.partiallyMatchedEvents}</span>
                  <span>mismatched: {r.mismatchedEvents}</span>
                  <span>{new Date(r.createdAt).toLocaleString()}</span>
                </div>
              </button>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};

/**
 * Renders the profile→backend execution trace recorded by the orchestrator.
 * Lets the operator verify a run actually fired the probes its profile
 * declared (rather than trusting the profile id alone).  Anything declared
 * but not executed is surfaced as `not executed` and the probe-level
 * errors (if any) are shown verbatim.
 */
const ExecutionTraceBlock = ({ trace }: { trace: ExecutionTrace }) => {
  const declaredSet = new Set(trace.declaredProbes);
  const executedSet = new Set(trace.executedProbes);
  const skipped = trace.declaredProbes.filter((p) => !executedSet.has(p));
  const stray = trace.executedProbes.filter((p) => !declaredSet.has(p));
  return (
    <div className="mt-3 border-t border-[#2d333b] pt-3 space-y-2">
      <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">
        Execution trace
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-[11px]">
        <div>
          <span className="text-[#64748b]">HTTP:</span>{' '}
          <span className={trace.httpProbed ? 'text-emerald-300' : 'text-[#94a3b8]'}>
            {trace.httpProbed ? 'fired' : 'not used'}
          </span>
        </div>
        <div>
          <span className="text-[#64748b]">TLS:</span>{' '}
          <span className={trace.tlsProbed ? 'text-emerald-300' : 'text-[#94a3b8]'}>
            {trace.tlsProbed ? 'fired' : 'not used'}
          </span>
        </div>
        <div>
          <span className="text-[#64748b]">Nmap:</span>{' '}
          <span className={trace.nmapProbed ? 'text-emerald-300' : 'text-[#94a3b8]'}>
            {trace.nmapProbed ? 'fired' : 'not used'}
          </span>
        </div>
      </div>
      <div className="text-[11px] text-[#94a3b8]">
        <span className="text-[#64748b]">Executed probes ({trace.executedProbes.length}):</span>{' '}
        {trace.executedProbes.length === 0
          ? <span className="text-[#64748b]">none</span>
          : trace.executedProbes.map((p) => (
              <code
                key={p}
                className="inline-block mr-1 mb-1 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-200 font-mono"
              >
                {p}
              </code>
            ))}
      </div>
      {skipped.length > 0 && (
        <div className="text-[11px] text-[#94a3b8]">
          <span className="text-[#64748b]">Declared but not executed:</span>{' '}
          {skipped.map((p) => (
            <code
              key={p}
              className="inline-block mr-1 mb-1 px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-200 font-mono"
            >
              {p}
            </code>
          ))}
        </div>
      )}
      {stray.length > 0 && (
        <div className="text-[11px] text-rose-200">
          <span className="text-[#64748b]">Engine integrity warning — executed but not declared:</span>{' '}
          {stray.map((p) => (
            <code
              key={p}
              className="inline-block mr-1 mb-1 px-1.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-200 font-mono"
            >
              {p}
            </code>
          ))}
        </div>
      )}
      {trace.probeErrors.length > 0 && (
        <details className="text-[11px] text-[#94a3b8]">
          <summary className="cursor-pointer text-[#64748b] hover:text-white">
            Probe-level diagnostics ({trace.probeErrors.length})
          </summary>
          <ul className="mt-1 space-y-0.5 list-disc list-inside">
            {trace.probeErrors.map((e, i) => (
              <li key={i} className="text-amber-200/80 font-mono">
                {e}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
};

const statusTone = (status: string): string => {
  switch (status) {
    case 'completed':
      return 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30';
    case 'partial':
      return 'bg-amber-500/15 text-amber-200 border-amber-500/30';
    case 'failed':
      return 'bg-rose-500/15 text-rose-200 border-rose-500/30';
    case 'running':
    case 'queued':
      return 'bg-sky-500/15 text-sky-200 border-sky-500/30';
    default:
      return 'bg-slate-500/15 text-slate-300 border-slate-500/30';
  }
};

const FingerprintsTab = ({
  runs,
  selectedRunId,
  onSelectRun,
  runDetail,
  loading,
  onDownloadReport,
}: {
  runs: TechIntelRunListItem[];
  selectedRunId: string | null;
  onSelectRun: (id: string) => void;
  runDetail: TechIntelRunDetail | null;
  loading: boolean;
  onDownloadReport: (kind: 'html' | 'pdf') => void;
}) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-[280px,1fr] gap-4">
      <Card className="!p-3 max-h-[70vh] overflow-y-auto">
        <h3 className="text-xs font-semibold text-[#94a3b8] tracking-wider uppercase mb-2 px-1">All runs</h3>
        {runs.length === 0 && <p className="text-sm text-[#64748b] px-1">No runs.</p>}
        <div className="space-y-1">
          {runs.map((r) => (
            <button
              key={r.id}
              onClick={() => onSelectRun(r.id)}
              className={`w-full text-left px-3 py-2 rounded text-sm transition ${
                selectedRunId === r.id
                  ? 'bg-[#6a2bba]/15 border border-[#6a2bba]/30'
                  : 'hover:bg-[#0f1115] border border-transparent'
              }`}
            >
              <div className="font-medium text-white truncate">{r.targetKey}</div>
              <div className="text-[11px] text-[#64748b] mt-0.5">
                {r.technologyCount} tech · {r.correlationCount} corr · {r.status}
              </div>
            </button>
          ))}
        </div>
      </Card>

      <div className="space-y-4">
        {!selectedRunId && (
          <Card>
            <p className="text-sm text-[#94a3b8]">Select a run from the list to inspect detected technologies and evidence.</p>
          </Card>
        )}
        {selectedRunId && loading && (
          <Card>
            <Loader2 className="animate-spin text-[#94a3b8]" size={16} />
          </Card>
        )}
        {selectedRunId && !loading && runDetail && (
          <>
            <Card>
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <div className="text-xs text-[#94a3b8] uppercase tracking-wider">Run summary</div>
                  <div className="text-base font-semibold text-white mt-1">{runDetail.run.targetKey}</div>
                  <div className="text-xs text-[#64748b] mt-0.5">
                    Resolved: {runDetail.run.resolvedHostname} · Profile: {runDetail.run.profileId} ·{' '}
                    {runDetail.run.durationMs} ms · {new Date(runDetail.run.createdAt).toLocaleString()}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Pill tone={statusTone(runDetail.run.status)}>{runDetail.run.status}</Pill>
                  <button
                    onClick={() => onDownloadReport('html')}
                    className="px-2 py-1 rounded border border-[#2d333b] text-[#94a3b8] hover:text-white text-xs flex items-center gap-1"
                  >
                    <Download size={12} /> HTML
                  </button>
                  <button
                    onClick={() => onDownloadReport('pdf')}
                    className="px-2 py-1 rounded border border-[#2d333b] text-[#94a3b8] hover:text-white text-xs flex items-center gap-1"
                  >
                    <Download size={12} /> PDF
                  </button>
                </div>
              </div>
              {runDetail.run.errorMessage && (
                <p className="text-[11px] text-amber-200 mt-2">Notes: {runDetail.run.errorMessage}</p>
              )}
              {runDetail.run.executionTrace && (
                <ExecutionTraceBlock trace={runDetail.run.executionTrace} />
              )}
            </Card>

            {runDetail.technologies.length === 0 && (
              <Card><p className="text-sm text-[#64748b]">No technologies detected.</p></Card>
            )}
            {Object.entries(groupBy(runDetail.technologies, (t) => t.category)).map(([category, techs]) => (
              <Card key={category}>
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                  <span className="text-[#c4a8ee]">{formatCategory(category)}</span>
                  <span className="text-[11px] text-[#64748b]">{techs.length}</span>
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {techs.map((t) => (
                    <TechCard key={t.id} tech={t} />
                  ))}
                </div>
              </Card>
            ))}
          </>
        )}
      </div>
    </div>
  );
};

const TechCard = ({ tech }: { tech: DetectedTechnology }) => (
  <div className="border border-[#2d333b] rounded-md p-3 bg-[#0f1115]">
    <div className="flex items-center justify-between gap-2 mb-2">
      <div>
        <div className="text-sm font-semibold text-white">{tech.productName}</div>
        <div className="text-[11px] text-[#64748b]">{tech.vendor ?? '—'}</div>
      </div>
      <div className="flex items-center gap-1.5 flex-wrap justify-end">
        <Pill tone={confidenceToneMap[tech.confidence]}>CF {tech.confidence}</Pill>
        {typeof tech.confidenceScore === 'number' && (
          <Pill tone="bg-slate-500/15 text-slate-200 border-slate-500/30">
            score {tech.confidenceScore}
          </Pill>
        )}
      </div>
    </div>
    <div className="flex flex-wrap gap-1.5 mb-2">
      <Pill>{formatCategory(tech.category)}</Pill>
      {tech.version && <Pill tone="bg-slate-500/15 text-slate-200 border-slate-500/30">v{tech.version}</Pill>}
      {tech.versionFamily && tech.versionFamily !== tech.version && (
        <Pill tone="bg-slate-500/15 text-slate-200 border-slate-500/30">family {tech.versionFamily}</Pill>
      )}
      <Pill tone={certaintyToneMap[tech.versionCertainty]}>{tech.versionCertainty}</Pill>
    </div>
    {tech.signalFamilies && tech.signalFamilies.length > 0 && (
      <div className="flex flex-wrap gap-1 mb-2">
        {tech.signalFamilies.map((f) => (
          <Pill key={f} tone={familyToneMap[f]}>
            {familyLabelMap[f]}
          </Pill>
        ))}
      </div>
    )}
    {tech.detectionMethodIds && tech.detectionMethodIds.length > 0 && (
      <div className="text-[10px] text-[#64748b] mb-2">
        Methods: <span className="font-mono text-[#94a3b8]">{tech.detectionMethodIds.join(', ')}</span>
      </div>
    )}
    {tech.evidence?.length > 0 && (
      <details className="text-[11px] text-[#94a3b8] mt-2">
        <summary className="cursor-pointer text-[#c4a8ee] hover:text-white">Evidence ({tech.evidence.length})</summary>
        <ul className="mt-2 space-y-1 font-mono leading-relaxed">
          {tech.evidence.map((e, idx) => {
            const { label, value } = splitEvidenceLabel(e.source, e.detail);
            return (
              <li key={idx} className="break-all">
                <span className="text-[#c4a8ee]">{label}:</span> {value}
              </li>
            );
          })}
        </ul>
      </details>
    )}
  </div>
);

const VersionsTab = ({
  runDetail,
  runStats,
}: {
  runDetail: TechIntelRunDetail | null;
  runStats: { techByCertainty: Record<string, number> } | null;
}) => {
  if (!runDetail) {
    return <Card><p className="text-sm text-[#94a3b8]">Select a fingerprint run to view version-confidence panels.</p></Card>;
  }
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap gap-3">
          {(['exact', 'probable', 'family', 'unknown'] as const).map((c) => (
            <div key={c} className="flex-1 min-w-[140px] border border-[#2d333b] rounded-md p-3 bg-[#0f1115]">
              <div className="text-[10px] tracking-wider text-[#64748b] uppercase">{c}</div>
              <div className="text-2xl font-bold text-white">{runStats?.techByCertainty?.[c] ?? 0}</div>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <h3 className="text-sm font-semibold text-white mb-3">Detected versions</h3>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] text-[#94a3b8] uppercase tracking-wider">
              <th className="py-2">Product</th>
              <th>Version</th>
              <th>Family</th>
              <th>Certainty</th>
              <th>Confidence</th>
              <th>Score</th>
              <th>Signal families</th>
            </tr>
          </thead>
          <tbody>
            {runDetail.technologies.map((t) => (
              <tr key={t.id} className="border-t border-[#2d333b]">
                <td className="py-2">
                  <div className="text-white">{t.productName}</div>
                  <div className="text-[11px] text-[#64748b]">{formatCategory(t.category)}</div>
                </td>
                <td className="text-white font-mono">{t.version ?? '—'}</td>
                <td className="text-[#94a3b8] font-mono">{t.versionFamily ?? '—'}</td>
                <td><Pill tone={certaintyToneMap[t.versionCertainty]}>{t.versionCertainty}</Pill></td>
                <td><Pill tone={confidenceToneMap[t.confidence]}>{t.confidence}</Pill></td>
                <td className="text-white font-mono">
                  {typeof t.confidenceScore === 'number' ? t.confidenceScore : '—'}
                </td>
                <td>
                  <div className="flex flex-wrap gap-1">
                    {(t.signalFamilies ?? []).map((f) => (
                      <Pill key={f} tone={familyToneMap[f]}>
                        {familyLabelMap[f]}
                      </Pill>
                    ))}
                    {(!t.signalFamilies || t.signalFamilies.length === 0) && (
                      <span className="text-[11px] text-[#64748b]">—</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
};

const VulnerabilitiesTab = ({ runDetail }: { runDetail: TechIntelRunDetail | null }) => {
  if (!runDetail) {
    return <Card><p className="text-sm text-[#94a3b8]">Select a fingerprint run to view advisory correlations.</p></Card>;
  }
  if (runDetail.correlations.length === 0) {
    return (
      <Card>
        <p className="text-sm text-[#94a3b8]">
          No correlations were produced for this run.  Either no detected products are present in the cached
          advisory feed, or the version evidence did not match any affected ranges with sufficient certainty.
        </p>
      </Card>
    );
  }
  return (
    <Card>
      <h3 className="text-sm font-semibold text-white mb-3">
        Vulnerability correlation ({runDetail.correlations.length})
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] text-[#94a3b8] uppercase tracking-wider">
              <th className="py-2 pr-3">Severity</th>
              <th className="pr-3">Advisory</th>
              <th className="pr-3">Product / version</th>
              <th className="pr-3">Summary</th>
              <th className="pr-3">Match type</th>
              <th className="pr-3">Match strength</th>
              <th className="pr-3">Fixed in</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {runDetail.correlations.map((c) => (
              <tr key={c.id} className="border-t border-[#2d333b] align-top">
                <td className="py-3 pr-3">
                  <Pill tone={severityToneMap[c.severityLabel] ?? severityToneMap.Critical}>{c.severityLabel}</Pill>
                  {c.severityScore !== null && (
                    <div className="text-[10px] text-[#64748b] mt-1">CVSS {c.severityScore.toFixed(1)}</div>
                  )}
                </td>
                <td className="py-3 pr-3 font-mono text-[12px] text-white">{c.advisoryId}</td>
                <td className="py-3 pr-3">
                  <div className="text-white">{c.productKey}</div>
                  <div className="text-[11px] text-[#94a3b8]">{c.detectedVersion ?? 'version unknown'}</div>
                </td>
                <td className="py-3 pr-3 text-[#cbd5e1] max-w-[420px]">
                  <div>{c.summary}</div>
                  <div className="text-[11px] text-[#64748b] mt-1">{c.certaintyLabel}</div>
                  {c.affectedRanges && (
                    <div className="text-[11px] text-[#94a3b8] mt-1 font-mono break-all">range: {c.affectedRanges}</div>
                  )}
                </td>
                <td className="py-3 pr-3">
                  {c.matchType ? (
                    <Pill tone={matchTypeToneMap[c.matchType]}>{c.matchType}</Pill>
                  ) : (
                    <span className="text-[11px] text-[#64748b]">—</span>
                  )}
                </td>
                <td className="py-3 pr-3">
                  <Pill tone={strengthToneMap[c.strength]}>{c.strength.replace(/_/g, ' ')}</Pill>
                </td>
                <td className="py-3 pr-3 font-mono text-[12px] text-[#cbd5e1]">{c.fixedVersions ?? '—'}</td>
                <td className="py-3">
                  {c.sourceUrl ? (
                    <a
                      href={c.sourceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[#c4a8ee] hover:text-white"
                    >
                      {c.source} <ExternalLink size={12} />
                    </a>
                  ) : (
                    <span className="text-[#94a3b8]">{c.source}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
};

const HardeningTab = ({
  wafRuns,
  selectedWafRunId,
  onSelectWafRun,
  wafDetail,
  loading,
}: {
  wafRuns: WafValidationListItem[];
  selectedWafRunId: string | null;
  onSelectWafRun: (id: string) => void;
  wafDetail: WafValidationDetail | null;
  loading: boolean;
}) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-[280px,1fr] gap-4">
      <Card className="!p-3 max-h-[70vh] overflow-y-auto">
        <h3 className="text-xs font-semibold text-[#94a3b8] tracking-wider uppercase mb-2 px-1">All WAF runs</h3>
        {wafRuns.length === 0 && <p className="text-sm text-[#64748b] px-1">No runs.</p>}
        <div className="space-y-1">
          {wafRuns.map((r) => (
            <button
              key={r.id}
              onClick={() => onSelectWafRun(r.id)}
              className={`w-full text-left px-3 py-2 rounded text-sm transition ${
                selectedWafRunId === r.id
                  ? 'bg-[#6a2bba]/15 border border-[#6a2bba]/30'
                  : 'hover:bg-[#0f1115] border border-transparent'
              }`}
            >
              <div className="font-medium text-white truncate">{r.targetKey}</div>
              <div className="text-[11px] text-[#64748b] mt-0.5">
                {r.matchedEvents}/{r.totalEvents} matched · {r.status}
              </div>
            </button>
          ))}
        </div>
      </Card>

      <div className="space-y-4">
        {!selectedWafRunId && <Card><p className="text-sm text-[#94a3b8]">Select a WAF run.</p></Card>}
        {selectedWafRunId && loading && (
          <Card><Loader2 className="animate-spin text-[#94a3b8]" size={16} /></Card>
        )}
        {selectedWafRunId && !loading && wafDetail && (
          <>
            <Card>
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <div className="text-xs text-[#94a3b8] uppercase tracking-wider">WAF Hardening Summary</div>
                  <div className="text-base font-semibold text-white mt-1">{wafDetail.run.targetKey}</div>
                  <div className="text-xs text-[#64748b] mt-0.5">
                    {wafDetail.run.profileId} · {wafDetail.run.durationMs} ms ·{' '}
                    {new Date(wafDetail.run.createdAt).toLocaleString()}
                  </div>
                </div>
                <Pill tone={statusTone(wafDetail.run.status)}>{wafDetail.run.status}</Pill>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
                {[
                  { label: 'Total', value: wafDetail.run.totalEvents, tone: '' },
                  { label: 'Matched', value: wafDetail.run.matchedEvents, tone: 'text-emerald-300' },
                  { label: 'Partial', value: wafDetail.run.partiallyMatchedEvents, tone: 'text-amber-300' },
                  { label: 'Mismatched', value: wafDetail.run.mismatchedEvents, tone: 'text-rose-300' },
                ].map((s) => (
                  <div key={s.label} className="border border-[#2d333b] rounded p-3 bg-[#0f1115]">
                    <div className="text-[10px] uppercase tracking-wider text-[#64748b]">{s.label}</div>
                    <div className={`text-2xl font-bold mt-1 ${s.tone || 'text-white'}`}>{s.value}</div>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <h3 className="text-sm font-semibold text-white mb-3">Probe events</h3>
              {wafDetail.events.length === 0 && <p className="text-sm text-[#94a3b8]">No probe events recorded.</p>}
              <div className="space-y-2">
                {wafDetail.events.map((e) => (
                  <details key={e.id} className="border border-[#2d333b] rounded-md bg-[#0f1115] open:border-[#3d434b]">
                    <summary className="cursor-pointer px-3 py-2 flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-[11px] text-[#64748b]">{e.method}</span>
                      <span className="text-sm text-white truncate">{e.probeLabel}</span>
                      <span className="text-[11px] text-[#64748b] truncate">{e.path}</span>
                      <span className="ml-auto flex items-center gap-2">
                        <Pill tone={verdictToneMap[e.observedVerdict]}>{e.observedVerdict}</Pill>
                        <Pill tone={expectationToneMap[e.expectationOutcome]}>{e.expectationOutcome.replace('_', ' ')}</Pill>
                        <span className="text-[11px] text-[#64748b]">HTTP {e.responseStatus}</span>
                      </span>
                    </summary>
                    <div className="px-3 py-3 border-t border-[#2d333b] text-[12px] text-[#cbd5e1] space-y-2">
                      <div>
                        <span className="text-[#94a3b8]">Expected:</span> {e.expectedVerdicts || 'any'}
                      </div>
                      {e.expectationReasons.length > 0 && (
                        <ul className="list-disc list-inside text-[#94a3b8]">
                          {e.expectationReasons.map((r, i) => <li key={i}>{r}</li>)}
                        </ul>
                      )}
                      {e.verdictSignals.length > 0 && (
                        <div>
                          <div className="text-[10px] text-[#64748b] uppercase tracking-wider mb-1">Verdict signals</div>
                          <ul className="font-mono text-[11px]">
                            {e.verdictSignals.map((s, i) => (
                              <li key={i}><span className="text-[#c4a8ee]">{s.source}:{s.name}</span> {s.detail ?? ''}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {e.errorMessage && <div className="text-rose-200">Error: {e.errorMessage}</div>}
                    </div>
                  </details>
                ))}
              </div>
            </Card>
          </>
        )}
      </div>
    </div>
  );
};

const EvidenceTab = ({
  runDetail,
  wafDetail,
}: {
  runDetail: TechIntelRunDetail | null;
  wafDetail: WafValidationDetail | null;
}) => {
  const observations = runDetail?.observations ?? [];
  const observationsByFamily = useMemo(() => {
    const out: Partial<Record<SignalFamily, FingerprintObservation[]>> = {};
    for (const obs of observations) {
      const list = out[obs.family] ?? [];
      list.push(obs);
      out[obs.family] = list;
    }
    return out;
  }, [observations]);

  return (
    <div className="space-y-4">
      <Card>
        <h3 className="text-sm font-semibold text-white mb-2">Observation ledger (raw signals)</h3>
        {!runDetail && <p className="text-sm text-[#94a3b8]">Select a fingerprint run to inspect evidence.</p>}
        {runDetail && observations.length === 0 && (
          <p className="text-sm text-[#94a3b8]">
            No atomic observations were persisted for this run (older runs created before the
            multi-signal engine was introduced only have the per-product evidence blocks below).
          </p>
        )}
        {runDetail && observations.length > 0 && (
          <div className="space-y-3">
            <p className="text-[11px] text-[#64748b]">
              Every row below is an atomic signal captured by a single adapter.  Rows are grouped
              by signal family so operators can see whether a detection is corroborated by multiple
              independent sources (markup + passive HTTP + TLS, for example) or rests on a single
              weak signal.
            </p>
            {(Object.keys(observationsByFamily) as SignalFamily[]).map((family) => {
              const list = observationsByFamily[family] ?? [];
              return (
                <div key={family} className="border border-[#2d333b] rounded-md bg-[#0f1115]">
                  <div className="px-3 py-2 border-b border-[#2d333b] flex items-center gap-2">
                    <Pill tone={familyToneMap[family]}>{familyLabelMap[family]}</Pill>
                    <span className="text-[11px] text-[#64748b]">{list.length} observation{list.length === 1 ? '' : 's'}</span>
                  </div>
                  <ul className="divide-y divide-[#2d333b]">
                    {list.map((obs) => (
                      <li key={obs.id} className="px-3 py-2">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="font-mono text-[11px] text-[#c4a8ee]">{obs.methodId}</span>
                          <span className="text-[11px] text-[#94a3b8]">{obs.methodLabel}</span>
                          {obs.productKey && (
                            <Pill tone="bg-slate-500/15 text-slate-200 border-slate-500/30">
                              {obs.productKey}
                            </Pill>
                          )}
                          {obs.versionLiteral && (
                            <Pill tone="bg-slate-500/15 text-slate-200 border-slate-500/30">
                              v{obs.versionLiteral}
                            </Pill>
                          )}
                          <span className="ml-auto text-[10px] text-[#64748b]">
                            weight {obs.weight.toFixed(2)}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-[#cbd5e1] break-all">
                          <span className="text-[#94a3b8]">{obs.signalKey}:</span>{' '}
                          {obs.evidenceSnippet}
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <Card>
        <h3 className="text-sm font-semibold text-white mb-2">Per-product evidence summary</h3>
        {!runDetail && <p className="text-sm text-[#94a3b8]">Select a fingerprint run to inspect evidence.</p>}
        {runDetail && (
          <div className="space-y-3">
            {runDetail.technologies.map((t) => (
              <div key={t.id} className="border border-[#2d333b] rounded-md p-3 bg-[#0f1115]">
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <span className="text-sm font-semibold text-white">{t.productName}</span>
                  <Pill>{formatCategory(t.category)}</Pill>
                  <Pill tone={confidenceToneMap[t.confidence]}>{t.confidence}</Pill>
                  <Pill tone={certaintyToneMap[t.versionCertainty]}>{t.versionCertainty}</Pill>
                  {typeof t.confidenceScore === 'number' && (
                    <Pill tone="bg-slate-500/15 text-slate-200 border-slate-500/30">
                      score {t.confidenceScore}
                    </Pill>
                  )}
                </div>
                <ul className="font-mono text-[11px] text-[#cbd5e1] space-y-1 leading-relaxed">
                  {(t.evidence ?? []).map((e, i) => {
                    const { label, value } = splitEvidenceLabel(e.source, e.detail);
                    return (
                      <li key={i} className="break-all">
                        <span className="text-[#c4a8ee] inline-block min-w-[160px] mr-2">{label}</span>
                        {value}
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <h3 className="text-sm font-semibold text-white mb-2">WAF probe evidence</h3>
        {!wafDetail && <p className="text-sm text-[#94a3b8]">Select a WAF hardening run to inspect probe evidence.</p>}
        {wafDetail && (
          <div className="space-y-3">
            {wafDetail.events.map((e) => (
              <details key={e.id} className="border border-[#2d333b] rounded-md p-3 bg-[#0f1115]">
                <summary className="cursor-pointer flex items-center gap-2 flex-wrap text-sm">
                  <span className="font-mono text-[11px] text-[#64748b]">{e.method}</span>
                  <span className="text-white">{e.probeLabel}</span>
                  <span className="text-[11px] text-[#64748b] truncate">{e.path}</span>
                </summary>
                <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="text-[11px] text-[#94a3b8]">
                    <div className="text-[10px] uppercase tracking-wider text-[#64748b] mb-1">Response headers</div>
                    <ul className="font-mono leading-relaxed">
                      {Object.entries(e.responseHeaders).map(([k, v]) => (
                        <li key={k}><span className="text-[#c4a8ee]">{k}:</span> {String(v)}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="text-[11px] text-[#94a3b8]">
                    <div className="text-[10px] uppercase tracking-wider text-[#64748b] mb-1">Body preview</div>
                    <pre className="font-mono text-[11px] text-[#cbd5e1] whitespace-pre-wrap break-all max-h-64 overflow-auto">
{e.bodyPreview ?? '—'}
                    </pre>
                  </div>
                </div>
              </details>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
};

const MethodsTab = ({
  catalog,
  runDetail,
}: {
  catalog: DetectionMethod[];
  runDetail: TechIntelRunDetail | null;
}) => {
  const exercised = useMemo(() => {
    return new Set(runDetail?.methodsExercised ?? []);
  }, [runDetail]);

  const [familyFilter, setFamilyFilter] = useState<SignalFamily | 'all'>('all');
  const [onlyExercised, setOnlyExercised] = useState(false);

  const filtered = useMemo(() => {
    return catalog
      .filter((m) => familyFilter === 'all' || m.family === familyFilter)
      .filter((m) => !onlyExercised || exercised.has(m.id))
      .sort((a, b) => {
        if (a.family !== b.family) return a.family.localeCompare(b.family);
        return a.id.localeCompare(b.id);
      });
  }, [catalog, familyFilter, onlyExercised, exercised]);

  const byFamily = useMemo(() => {
    const out: Partial<Record<SignalFamily, DetectionMethod[]>> = {};
    for (const m of filtered) {
      const list = out[m.family] ?? [];
      list.push(m);
      out[m.family] = list;
    }
    return out;
  }, [filtered]);

  return (
    <div className="space-y-4">
      <Card>
        <h3 className="text-sm font-semibold text-white mb-2">Detection methods catalog</h3>
        <p className="text-[11px] text-[#64748b] leading-relaxed mb-3">
          Every fingerprint observation is produced by a named detection method.  The catalog
          below enumerates the methods shipped by this build — its family, whether it is a
          passive reading of traffic or a safe controlled active probe, its typical weight in
          the fused confidence score, and the OWASP WSTG reference that inspired it.  When a
          fingerprint run is selected, methods that actually fired during that run are marked
          with a "fired" badge.
        </p>
        <div className="flex items-center gap-3 flex-wrap">
          <select
            value={familyFilter}
            onChange={(e) => setFamilyFilter(e.target.value as SignalFamily | 'all')}
            className="bg-[#0f1115] border border-[#2d333b] rounded-md px-2 py-1 text-sm focus:outline-none focus:border-[#6a2bba]"
          >
            <option value="all">All signal families</option>
            {(Object.keys(familyLabelMap) as SignalFamily[]).map((f) => (
              <option key={f} value={f}>
                {familyLabelMap[f]}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-[12px] text-[#94a3b8]">
            <input
              type="checkbox"
              checked={onlyExercised}
              onChange={(e) => setOnlyExercised(e.target.checked)}
              disabled={!runDetail}
            />
            Only methods fired in the selected run
          </label>
          {runDetail && (
            <span className="text-[11px] text-[#64748b]">
              {exercised.size} method{exercised.size === 1 ? '' : 's'} fired in run{' '}
              <span className="font-mono text-[#94a3b8]">{runDetail.run.id.slice(0, 8)}</span>
            </span>
          )}
        </div>
      </Card>

      {(Object.keys(byFamily) as SignalFamily[]).map((family) => {
        const list = byFamily[family] ?? [];
        return (
          <Card key={family}>
            <div className="flex items-center gap-2 mb-3">
              <Pill tone={familyToneMap[family]}>{familyLabelMap[family]}</Pill>
              <span className="text-[11px] text-[#64748b]">{list.length} method{list.length === 1 ? '' : 's'}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {list.map((m) => (
                <div key={m.id} className="border border-[#2d333b] rounded-md p-3 bg-[#0f1115]">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <div>
                      <div className="text-sm font-semibold text-white">{m.label}</div>
                      <div className="font-mono text-[10px] text-[#64748b]">{m.id}</div>
                    </div>
                    <div className="flex flex-col items-end gap-1">
                      <Pill
                        tone={
                          m.kind === 'active'
                            ? 'bg-amber-500/15 text-amber-200 border-amber-500/30'
                            : 'bg-sky-500/15 text-sky-200 border-sky-500/30'
                        }
                      >
                        {m.kind}
                      </Pill>
                      {exercised.has(m.id) && (
                        <Pill tone="bg-emerald-500/15 text-emerald-200 border-emerald-500/30">
                          fired
                        </Pill>
                      )}
                    </div>
                  </div>
                  <p className="text-[12px] text-[#cbd5e1] leading-relaxed mb-2">{m.description}</p>
                  <div className="flex items-center gap-3 text-[11px] text-[#64748b]">
                    <span>
                      weight <span className="font-mono text-[#94a3b8]">{m.typicalWeight.toFixed(2)}</span>
                    </span>
                    {m.owaspRef && (
                      <span>
                        OWASP <span className="font-mono text-[#94a3b8]">{m.owaspRef}</span>
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        );
      })}

      {filtered.length === 0 && (
        <Card>
          <p className="text-sm text-[#94a3b8]">No detection methods match the current filter.</p>
        </Card>
      )}
    </div>
  );
};

const HistoryTab = ({
  runs,
  wafRuns,
  selectedRunId,
  onSelectRun,
  selectedWafRunId,
  onSelectWafRun,
}: {
  runs: TechIntelRunListItem[];
  wafRuns: WafValidationListItem[];
  selectedRunId: string | null;
  onSelectRun: (id: string) => void;
  selectedWafRunId: string | null;
  onSelectWafRun: (id: string) => void;
}) => {
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      <Card>
        <h3 className="text-sm font-semibold text-white mb-3">Fingerprint run history</h3>
        {runs.length === 0 ? (
          <p className="text-sm text-[#64748b]">No fingerprint runs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] text-[#94a3b8] uppercase tracking-wider">
                  <th className="py-2 pr-2">Target</th>
                  <th className="pr-2">Profile</th>
                  <th className="pr-2">Status</th>
                  <th className="pr-2">Tech</th>
                  <th className="pr-2">Corr</th>
                  <th className="pr-2">H/C</th>
                  <th className="pr-2">Duration</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => onSelectRun(r.id)}
                    className={`border-t border-[#2d333b] cursor-pointer ${
                      selectedRunId === r.id ? 'bg-[#6a2bba]/10' : 'hover:bg-[#0f1115]'
                    }`}
                  >
                    <td className="py-2 pr-2 text-white truncate max-w-[220px]">{r.targetKey}</td>
                    <td className="pr-2 font-mono text-[11px] text-[#94a3b8]">{r.profileId}</td>
                    <td className="pr-2">
                      <Pill tone={statusTone(r.status)}>{r.status}</Pill>
                    </td>
                    <td className="pr-2 text-white font-mono">{r.technologyCount}</td>
                    <td className="pr-2 text-white font-mono">{r.correlationCount}</td>
                    <td className="pr-2 text-white font-mono">{r.highOrCriticalCount}</td>
                    <td className="pr-2 text-[#94a3b8] font-mono">{r.durationMs} ms</td>
                    <td className="text-[11px] text-[#64748b]">{new Date(r.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <h3 className="text-sm font-semibold text-white mb-3">WAF hardening run history</h3>
        {wafRuns.length === 0 ? (
          <p className="text-sm text-[#64748b]">No WAF hardening runs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] text-[#94a3b8] uppercase tracking-wider">
                  <th className="py-2 pr-2">Target</th>
                  <th className="pr-2">Profile</th>
                  <th className="pr-2">Status</th>
                  <th className="pr-2">Match</th>
                  <th className="pr-2">Partial</th>
                  <th className="pr-2">Mismatch</th>
                  <th className="pr-2">Total</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {wafRuns.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => onSelectWafRun(r.id)}
                    className={`border-t border-[#2d333b] cursor-pointer ${
                      selectedWafRunId === r.id ? 'bg-[#6a2bba]/10' : 'hover:bg-[#0f1115]'
                    }`}
                  >
                    <td className="py-2 pr-2 text-white truncate max-w-[220px]">{r.targetKey}</td>
                    <td className="pr-2 font-mono text-[11px] text-[#94a3b8]">{r.profileId}</td>
                    <td className="pr-2">
                      <Pill tone={statusTone(r.status)}>{r.status}</Pill>
                    </td>
                    <td className="pr-2 text-emerald-300 font-mono">{r.matchedEvents}</td>
                    <td className="pr-2 text-amber-300 font-mono">{r.partiallyMatchedEvents}</td>
                    <td className="pr-2 text-rose-300 font-mono">{r.mismatchedEvents}</td>
                    <td className="pr-2 text-white font-mono">{r.totalEvents}</td>
                    <td className="text-[11px] text-[#64748b]">{new Date(r.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

function groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of items) {
    const k = keyFn(item);
    if (!out[k]) out[k] = [];
    out[k].push(item);
  }
  return out;
}
