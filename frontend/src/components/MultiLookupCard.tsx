import { useEffect, useState } from 'react';
import {
  Search,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  AlertTriangle,
  ExternalLink,
  Lock,
  HelpCircle,
} from 'lucide-react';
import { apiFetchJson } from '../lib/api';

/**
 * Multi-source reputation lookup card.
 *
 * One indicator -> 5 providers (Local IOC DB + VirusTotal + abuse.ch
 * ThreatFox / URLhaus / MalwareBazaar). The backend orchestrates the fan-out
 * so the API key never touches the browser; this component is a pure renderer
 * over `/api/lookup/status` and `/api/lookup/multi`.
 */

type ProviderId = 'local_db' | 'virustotal' | 'threatfox' | 'urlhaus' | 'malwarebazaar';
type ProviderStatus = 'ok' | 'not_found' | 'not_configured' | 'unsupported' | 'error';
type Verdict =
  | 'malicious'
  | 'suspicious'
  | 'harmless'
  | 'undetected'
  | 'clean'
  | 'unknown';

interface ProviderResult {
  provider: ProviderId;
  providerName: string;
  status: ProviderStatus;
  verdict: Verdict;
  threatLabel: string | null;
  summary: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  tags: string[];
  meta: Record<string, string | number | null>;
  permalink: string | null;
  detail: string | null;
}

interface MultiLookupResponse {
  kind: string;
  value: string;
  startedAt: string;
  durationMs: number;
  aggregateVerdict: Verdict;
  hitCount: number;
  checkedCount: number;
  providers: ProviderResult[];
}

interface StatusResponse {
  providers: Array<{
    id: ProviderId;
    name: string;
    configured: boolean;
    docs: string;
  }>;
}

const verdictTone: Record<Verdict, string> = {
  malicious: 'bg-rose-500/20 text-rose-100 border-rose-500/40',
  suspicious: 'bg-amber-500/20 text-amber-100 border-amber-500/40',
  harmless: 'bg-emerald-500/20 text-emerald-100 border-emerald-500/40',
  clean: 'bg-emerald-500/20 text-emerald-100 border-emerald-500/40',
  undetected: 'bg-slate-500/20 text-slate-200 border-slate-500/40',
  unknown: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
};

const verdictLabel: Record<Verdict, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  harmless: 'Harmless',
  clean: 'Clean',
  undetected: 'Undetected',
  unknown: 'Unknown',
};

const statusLabel: Record<ProviderStatus, string> = {
  ok: 'Hit',
  not_found: 'No record',
  not_configured: 'Not configured',
  unsupported: 'N/A',
  error: 'Error',
};

const statusTone: Record<ProviderStatus, string> = {
  ok: 'bg-rose-500/20 text-rose-100 border-rose-500/40',
  not_found: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  not_configured: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  unsupported: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  error: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
};

function VerdictIcon({ verdict, status }: { verdict: Verdict; status: ProviderStatus }) {
  if (status === 'not_configured') return <Lock size={14} className="text-amber-300" />;
  if (status === 'unsupported') return <HelpCircle size={14} className="text-slate-400" />;
  if (status === 'error') return <AlertTriangle size={14} className="text-rose-300" />;
  if (verdict === 'malicious') return <ShieldX size={14} className="text-rose-300" />;
  if (verdict === 'suspicious') return <ShieldAlert size={14} className="text-amber-300" />;
  if (verdict === 'harmless' || verdict === 'clean')
    return <ShieldCheck size={14} className="text-emerald-300" />;
  return <ShieldQuestion size={14} className="text-slate-400" />;
}

const PROVIDER_DOCS: Record<ProviderId, string> = {
  local_db: 'https://github.com/advisories',
  virustotal: 'https://docs.virustotal.com/reference/overview',
  threatfox: 'https://threatfox.abuse.ch/api/',
  urlhaus: 'https://urlhaus-api.abuse.ch/',
  malwarebazaar: 'https://bazaar.abuse.ch/api/',
};

const ABUSE_CH_AUTH_DOCS = 'https://auth.abuse.ch/';

const MultiLookupCard = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<MultiLookupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<StatusResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const r = await apiFetchJson<StatusResponse>('/lookup/status');
        if (!cancelled) setStatus(r.data);
      } catch {
        /* status is optional UX; tolerate failure */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const submit = async (event?: React.FormEvent) => {
    event?.preventDefault();
    const trimmed = query.trim();
    if (!trimmed || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await apiFetchJson<MultiLookupResponse>('/lookup/multi', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: trimmed }),
      });
      setResult(r.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Multi-source lookup failed.');
    } finally {
      setLoading(false);
    }
  };

  // Backend reports which providers are configured so we can show a
  // "Sources checked" preview before the user runs a query.
  const configuredCount = status?.providers.filter((p) => p.configured).length ?? 0;
  const totalCount = status?.providers.length ?? 0;
  const abuseConfigured = status?.providers.find((p) => p.id === 'threatfox')?.configured ?? false;

  return (
    <div className="rounded-2xl border border-[#2d333b] bg-[#15181e] p-6 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <Search className="text-[#8e51df] mt-0.5" size={20} />
          <div>
            <h2 className="text-lg font-bold text-white">Cross-source reputation lookup</h2>
            <p className="text-xs text-[#94a3b8] mt-1 max-w-2xl">
              Paste any indicator (file hash, URL, domain, or IPv4) — the backend
              fans the request out to every configured reputation source and
              renders one verdict per source. The indicator is never sent
              anywhere except the providers below; API keys stay on the server.
            </p>
          </div>
        </div>
        {status && (
          <div className="text-[10px] uppercase tracking-wider text-[#94a3b8] mt-1">
            {configuredCount}/{totalCount} sources configured
          </div>
        )}
      </div>

      <form onSubmit={(e) => void submit(e)} className="flex flex-col sm:flex-row gap-2">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f  •  http://malicious.example/path  •  185.220.101.7  •  evil-domain.tld"
          className="flex-1 px-3 py-2 rounded-lg bg-[#0b0c10] border border-[#2d333b] text-sm text-white placeholder:text-[#64748b] font-mono focus:outline-none focus:border-[#8e51df]/60"
        />
        <button
          type="submit"
          disabled={loading || query.trim().length === 0}
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#8e51df]/40 bg-[#8e51df]/10 px-4 py-2 text-sm text-white hover:bg-[#8e51df]/20 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? <Loader2 className="animate-spin" size={16} /> : <Search size={16} />}
          {loading ? 'Checking…' : 'Check all sources'}
        </button>
      </form>

      {status && !abuseConfigured && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-100 flex items-start gap-2">
          <Lock size={12} className="mt-0.5 flex-shrink-0" />
          <span>
            <span className="font-semibold">abuse.ch providers not configured.</span>{' '}
            Set <span className="font-mono">ABUSE_CH_AUTH_KEY</span> in the backend
            <span className="font-mono"> .env</span> file (one key covers ThreatFox + URLhaus +
            MalwareBazaar). Get a free key at{' '}
            <a
              href={ABUSE_CH_AUTH_DOCS}
              target="_blank"
              rel="noreferrer noopener"
              className="underline text-amber-200 hover:text-amber-100"
            >
              auth.abuse.ch
            </a>
            . The lookup will still query VirusTotal and the local IOC database.
          </span>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-100 flex items-start gap-2">
          <AlertTriangle size={14} className="mt-0.5" /> {error}
        </div>
      )}

      {result && <MultiLookupResults result={result} />}
    </div>
  );
};

function MultiLookupResults({ result }: { result: MultiLookupResponse }) {
  const aggregateText =
    result.hitCount === 0
      ? `No provider returned a hit (${result.checkedCount} provider${result.checkedCount === 1 ? '' : 's'} checked).`
      : `${result.hitCount} of ${result.checkedCount} providers flagged this indicator.`;

  return (
    <div className="space-y-3 pt-2">
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-[#2d333b] bg-[#0b0c10] px-3 py-2 text-xs">
        <span className="text-[#94a3b8] uppercase tracking-wider text-[10px]">
          Aggregate verdict
        </span>
        <span
          className={`px-2 py-0.5 rounded-md border text-[11px] uppercase tracking-wider font-bold ${verdictTone[result.aggregateVerdict]}`}
        >
          {verdictLabel[result.aggregateVerdict]}
        </span>
        <span className="text-[#cbd5e1]">{aggregateText}</span>
        <span className="ml-auto font-mono text-[10px] text-[#64748b]">
          kind={result.kind} • {result.durationMs}ms
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2">
        {result.providers.map((p) => (
          <ProviderRow key={p.provider} p={p} />
        ))}
      </div>
    </div>
  );
}

function ProviderRow({ p }: { p: ProviderResult }) {
  const showDetails = p.status === 'ok';
  return (
    <div
      className={`rounded-lg border ${
        p.status === 'ok'
          ? p.verdict === 'malicious'
            ? 'border-rose-500/40 bg-rose-500/5'
            : p.verdict === 'suspicious'
              ? 'border-amber-500/40 bg-amber-500/5'
              : 'border-emerald-500/30 bg-emerald-500/5'
          : 'border-[#2d333b] bg-[#0b0c10]'
      } px-3 py-2`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <VerdictIcon verdict={p.verdict} status={p.status} />
        <span className="text-sm font-semibold text-white">{p.providerName}</span>
        <span
          className={`px-2 py-0.5 rounded-md border text-[10px] uppercase tracking-wider ${statusTone[p.status]}`}
        >
          {statusLabel[p.status]}
        </span>
        {p.status === 'ok' && (
          <span
            className={`px-2 py-0.5 rounded-md border text-[10px] uppercase tracking-wider ${verdictTone[p.verdict]}`}
          >
            {verdictLabel[p.verdict]}
          </span>
        )}
        {p.threatLabel && (
          <span className="text-xs text-[#cbd5e1] font-mono truncate max-w-md">
            {p.threatLabel}
          </span>
        )}
        {p.permalink && (
          <a
            href={p.permalink}
            target="_blank"
            rel="noreferrer noopener"
            className="ml-auto inline-flex items-center gap-1 text-xs text-[#8e51df] hover:text-[#a372eb]"
          >
            Open <ExternalLink size={11} />
          </a>
        )}
        {!p.permalink && p.status === 'not_configured' && (
          <a
            href={p.provider === 'virustotal' ? PROVIDER_DOCS.virustotal : ABUSE_CH_AUTH_DOCS}
            target="_blank"
            rel="noreferrer noopener"
            className="ml-auto inline-flex items-center gap-1 text-xs text-amber-300 hover:text-amber-200"
          >
            How to enable <ExternalLink size={11} />
          </a>
        )}
      </div>

      {(p.summary || p.detail) && (
        <p className="text-[11px] text-[#94a3b8] mt-1">{p.summary ?? p.detail}</p>
      )}

      {showDetails && (Object.keys(p.meta).length > 0 || p.firstSeen || p.lastSeen) && (
        <div className="mt-2 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-x-4 gap-y-1 text-[11px]">
          {p.firstSeen && (
            <KV
              k="First seen"
              v={new Date(p.firstSeen).toLocaleString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
              })}
            />
          )}
          {p.lastSeen && (
            <KV
              k="Last seen"
              v={new Date(p.lastSeen).toLocaleString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
              })}
            />
          )}
          {Object.entries(p.meta).map(([k, v]) =>
            v === null ? null : <KV key={k} k={prettyKey(k)} v={String(v)} />,
          )}
        </div>
      )}
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-[9px] uppercase tracking-wider text-[#64748b]">{k}</span>
      <span className="text-[#cbd5e1] font-mono text-[10px] truncate" title={v}>
        {v}
      </span>
    </div>
  );
}

function prettyKey(k: string): string {
  return k
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (c) => c.toUpperCase())
    .trim();
}

export default MultiLookupCard;
