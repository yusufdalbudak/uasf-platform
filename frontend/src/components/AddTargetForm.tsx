import { useState } from 'react';
import { PlusCircle } from 'lucide-react';
import { ApiError, apiFetchJson } from '../lib/api';

type Props = {
  onRegistered?: () => void;
  variant?: 'full' | 'compact';
};

const AddTargetForm = ({ onRegistered, variant = 'full' }: Props) => {
  const [hostname, setHostname] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [environment, setEnvironment] = useState('');
  const [apptranaAlias, setApptranaAlias] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
    setSubmitting(true);
    try {
      const { data } = await apiFetchJson<{
        error?: string;
        targetCreated?: boolean;
        allowlistCreated?: boolean;
      }>('/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hostname,
          displayName: displayName.trim() || null,
          environment: environment.trim() || null,
          apptranaAlias: apptranaAlias.trim() || null,
        }),
      });
      const parts: string[] = [];
      if (data.targetCreated) parts.push('asset registered');
      else parts.push('asset already in registry');
      if (data.allowlistCreated) parts.push('allowlist updated');
      else parts.push('allowlist already contained hostname');
      setMessage({ kind: 'ok', text: parts.join(' · ') });
      setHostname('');
      setDisplayName('');
      setEnvironment('');
      setApptranaAlias('');
      onRegistered?.();
    } catch (err) {
      setMessage({
        kind: 'err',
        text: err instanceof ApiError || err instanceof Error ? err.message : 'Request failed',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const compact = variant === 'compact';

  return (
    <form
      onSubmit={submit}
      className={
        compact
          ? 'rounded-xl border border-[#2d333b] bg-[#15181e] p-4 space-y-3'
          : 'rounded-xl border border-[#2d333b] bg-[#15181e] p-6 space-y-4'
      }
    >
      <div className="flex items-center gap-2">
        <PlusCircle className="text-[#8e51df]" size={compact ? 20 : 22} />
        <h2 className={compact ? 'text-base font-semibold text-white' : 'text-lg font-semibold text-white'}>
          Register web target
        </h2>
      </div>
      <p className="text-sm text-[#94a3b8]">
        Paste a hostname or URL; it is normalized before policy checks. Adds an approved registry row and the
        allowlist entry for this environment.
      </p>

      <div className={compact ? 'grid gap-3 sm:grid-cols-2' : 'grid gap-4 sm:grid-cols-2'}>
        <label className="block sm:col-span-2">
          <span className="text-xs uppercase tracking-wide text-[#94a3b8]">Hostname or URL *</span>
          <input
            required
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder="e.g. vulnhub.com or https://example.com/path"
            className="mt-1 w-full rounded-lg border border-[#2d333b] bg-[#0d0f14] px-3 py-2 text-sm text-white placeholder:text-[#64748b] focus:border-[#6a2bba] focus:outline-none focus:ring-1 focus:ring-[#6a2bba]"
          />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-wide text-[#94a3b8]">Display name</span>
          <input
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Optional label"
            className="mt-1 w-full rounded-lg border border-[#2d333b] bg-[#0d0f14] px-3 py-2 text-sm text-white placeholder:text-[#64748b] focus:border-[#6a2bba] focus:outline-none focus:ring-1 focus:ring-[#6a2bba]"
          />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-wide text-[#94a3b8]">Environment</span>
          <input
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            placeholder="e.g. staging"
            className="mt-1 w-full rounded-lg border border-[#2d333b] bg-[#0d0f14] px-3 py-2 text-sm text-white placeholder:text-[#64748b] focus:border-[#6a2bba] focus:outline-none focus:ring-1 focus:ring-[#6a2bba]"
          />
        </label>
        <label className="block sm:col-span-2">
          <span className="text-xs uppercase tracking-wide text-[#94a3b8]">Edge/WAAP alias</span>
          <input
            value={apptranaAlias}
            onChange={(e) => setApptranaAlias(e.target.value)}
            placeholder="Optional console label (not used as socket target)"
            className="mt-1 w-full rounded-lg border border-[#2d333b] bg-[#0d0f14] px-3 py-2 text-sm text-white placeholder:text-[#64748b] focus:border-[#6a2bba] focus:outline-none focus:ring-1 focus:ring-[#6a2bba]"
          />
        </label>
      </div>

      {message && (
        <div
          className={
            message.kind === 'ok'
              ? 'rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-100'
              : 'rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-100'
          }
        >
          {message.text}
        </div>
      )}

      <button
        type="submit"
        disabled={submitting || !hostname.trim()}
        className="rounded-lg bg-[#6a2bba] px-4 py-2 text-sm font-medium text-white hover:bg-[#8e51df] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {submitting ? 'Saving…' : 'Add target'}
      </button>
    </form>
  );
};

export default AddTargetForm;
