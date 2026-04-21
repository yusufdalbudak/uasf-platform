import { useEffect, useState } from 'react';
import {
  Loader2,
  Monitor,
  Moon,
  Palette,
  RefreshCw,
  Settings as SettingsIcon,
  Sun,
} from 'lucide-react';
import { apiFetchJson } from '../lib/api';
import { useTheme } from '../theme/ThemeContext';

type SettingsResponse = {
  service: string;
  version: string;
  policy: {
    requireRegisteredAsset: boolean;
    allowlistKeys: string[];
  };
  runtime: {
    databaseSynchronize: boolean;
    nodeVersion: string;
    platform: string;
    uptimeSeconds: number;
  };
};

const Settings = () => {
  const [data, setData] = useState<SettingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const { data: payload } = await apiFetchJson<SettingsResponse>('/settings');
      setData(payload);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load settings.');
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

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const parts: string[] = [];
    if (days) parts.push(`${days}d`);
    if (hours) parts.push(`${hours}h`);
    parts.push(`${minutes}m`);
    return parts.join(' ');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <SettingsIcon className="text-[#8e51df]" size={28} />
            Settings
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Read-only view of the active service identity, allowlist policy and runtime. Secrets
            are never returned by the API; only shape and policy posture are surfaced here.
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

      <AppearanceCard />

      {loading || !data ? (
        <p className="text-[#94a3b8]">Loading settings…</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <section className="rounded-xl border border-[#2d333b] bg-[#15181e] p-5">
            <h2 className="font-bold text-white mb-3">Service</h2>
            <KV label="Name" value={data.service} mono />
            <KV label="Version" value={data.version} mono />
            <KV label="Node" value={data.runtime.nodeVersion} mono />
            <KV label="Platform" value={data.runtime.platform} mono />
            <KV label="Uptime" value={formatUptime(data.runtime.uptimeSeconds)} />
          </section>

          <section className="rounded-xl border border-[#2d333b] bg-[#15181e] p-5">
            <h2 className="font-bold text-white mb-3">Policy</h2>
            <KV
              label="Require registered asset"
              value={data.policy.requireRegisteredAsset ? 'enforced' : 'disabled'}
            />
            <KV
              label="Database synchronize (dev)"
              value={data.runtime.databaseSynchronize ? 'on' : 'off'}
            />
            <div className="mt-3">
              <div className="text-xs uppercase tracking-wider text-[#94a3b8] font-bold mb-2">
                Allowlist keys ({data.policy.allowlistKeys.length})
              </div>
              {data.policy.allowlistKeys.length === 0 ? (
                <p className="text-sm text-[#64748b] italic">No keys in the merged allowlist.</p>
              ) : (
                <div className="flex flex-wrap gap-1 max-h-40 overflow-y-auto">
                  {data.policy.allowlistKeys.map((key) => (
                    <span
                      key={key}
                      className="font-mono text-[11px] bg-[#0b0c10] border border-[#2d333b] rounded px-2 py-0.5 text-[#cbd5e1]"
                    >
                      {key}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  );
};

const KV = ({ label, value, mono }: { label: string; value: string; mono?: boolean }) => (
  <div className="flex items-center justify-between border-b border-[#2d333b]/60 py-1.5 text-sm">
    <span className="text-[#94a3b8]">{label}</span>
    <span className={mono ? 'font-mono text-white' : 'text-white'}>{value}</span>
  </div>
);

/**
 * Appearance section — lets the operator pick between light, dark or
 * system theme.  Persisted via the global ThemeContext (localStorage
 * `uasf:theme`).  Applies instantly across the entire app via the
 * `[data-theme="..."]` overlay in `theme/themeOverrides.css` — no
 * page refresh required.
 */
function AppearanceCard() {
  const { choice, resolved, setChoice } = useTheme();
  const options: Array<{
    id: 'light' | 'dark' | 'system';
    label: string;
    description: string;
    icon: typeof Sun;
  }> = [
    {
      id: 'light',
      label: 'Light',
      description: 'Bright surface optimised for daytime work.',
      icon: Sun,
    },
    {
      id: 'dark',
      label: 'Dark',
      description: 'Operator-grade dark UI (default).',
      icon: Moon,
    },
    {
      id: 'system',
      label: 'System',
      description: 'Follows your OS appearance preference.',
      icon: Monitor,
    },
  ];

  return (
    <section className="rounded-xl border border-[#2d333b] bg-[#15181e] p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-bold text-white flex items-center gap-2">
          <Palette size={16} className="text-[#8e51df]" />
          Appearance
        </h2>
        <span className="text-[10px] uppercase tracking-wider text-[#64748b]">
          Currently rendering: <span className="text-[#cbd5e1] font-mono">{resolved}</span>
        </span>
      </div>
      <p className="text-sm text-[#94a3b8] mb-4">
        Pick a theme for the entire UASF console. Your choice is stored locally on this
        device and applies instantly to every page.
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {options.map((opt) => {
          const Icon = opt.icon;
          const isSelected = choice === opt.id;
          return (
            <button
              key={opt.id}
              type="button"
              onClick={() => setChoice(opt.id)}
              className={`text-left rounded-lg border px-4 py-3 transition ${
                isSelected
                  ? 'border-[#8e51df] bg-[#6a2bba]/15 shadow-[inset_0_0_0_1px_rgba(142,81,223,0.3)]'
                  : 'border-[#2d333b] bg-[#0b0c10] hover:border-[#8e51df]/40 hover:bg-[#1e232b]'
              }`}
              aria-pressed={isSelected}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <Icon
                    size={16}
                    className={isSelected ? 'text-[#8e51df]' : 'text-[#94a3b8]'}
                  />
                  <span className="font-semibold text-white text-sm">{opt.label}</span>
                </div>
                {isSelected && (
                  <span className="text-[10px] uppercase tracking-wider text-[#8e51df]">
                    Active
                  </span>
                )}
              </div>
              <p className="text-xs text-[#94a3b8] leading-snug">{opt.description}</p>
            </button>
          );
        })}
      </div>
    </section>
  );
}

export default Settings;
