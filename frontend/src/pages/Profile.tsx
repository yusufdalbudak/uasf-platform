import { useEffect, useState } from 'react';
import { Loader2, ShieldCheck, Trash2, LogOut, KeyRound, Save, Smartphone, X } from 'lucide-react';
import { useAuth } from '../auth/useAuth';
import { apiFetchJson, ApiError } from '../lib/api';
import type { AuthSessionRow, AuthUser } from '../auth/types';

/**
 * The Profile page is the operator's self-service IAM panel:
 *   - update display name
 *   - change password (revokes ALL sessions, forcing re-login)
 *   - inspect and revoke individual active sessions
 *   - exercise GDPR / KVKK right to erasure
 */
export default function Profile() {
  const { user, setUser, logout } = useAuth();
  const [displayName, setDisplayName] = useState(user?.displayName ?? '');
  const [savingName, setSavingName] = useState(false);
  const [nameMsg, setNameMsg] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changing, setChanging] = useState(false);
  const [pwMsg, setPwMsg] = useState<string | null>(null);

  const [sessions, setSessions] = useState<AuthSessionRow[]>([]);
  const [sessionsErr, setSessionsErr] = useState<string | null>(null);
  const [loadingSessions, setLoadingSessions] = useState(true);

  const [deletePassword, setDeletePassword] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [deleteErr, setDeleteErr] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) setDisplayName(user?.displayName ?? '');
    });
    return () => {
      cancelled = true;
    };
  }, [user]);

  const loadSessions = async () => {
    setLoadingSessions(true);
    setSessionsErr(null);
    try {
      const { data } = await apiFetchJson<{ sessions: AuthSessionRow[] }>('/auth/sessions');
      setSessions(data.sessions);
    } catch (e) {
      setSessionsErr(e instanceof ApiError ? e.message : 'Failed to load sessions.');
    } finally {
      setLoadingSessions(false);
    }
  };
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await apiFetchJson<{ sessions: AuthSessionRow[] }>('/auth/sessions');
        if (cancelled) return;
        setSessions(data.sessions);
        setSessionsErr(null);
      } catch (e) {
        if (cancelled) return;
        setSessionsErr(e instanceof ApiError ? e.message : 'Failed to load sessions.');
      } finally {
        if (!cancelled) setLoadingSessions(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const onSaveName = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingName(true);
    setNameMsg(null);
    try {
      const { data } = await apiFetchJson<{ user: AuthUser }>('/auth/me', {
        method: 'PATCH',
        body: JSON.stringify({ displayName }),
      });
      setUser(data.user);
      setNameMsg('Saved.');
    } catch (e) {
      setNameMsg(e instanceof ApiError ? e.message : 'Failed.');
    } finally {
      setSavingName(false);
    }
  };

  const onChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwMsg(null);
    if (newPassword !== confirmPassword) {
      setPwMsg('New passwords do not match.');
      return;
    }
    setChanging(true);
    try {
      await apiFetchJson('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setPwMsg('Password updated. You will be signed out shortly.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => {
        void logout();
      }, 1200);
    } catch (e) {
      setPwMsg(e instanceof ApiError ? e.message : 'Failed.');
    } finally {
      setChanging(false);
    }
  };

  const onRevokeSession = async (id: string) => {
    try {
      await apiFetchJson(`/auth/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await loadSessions();
    } catch (e) {
      setSessionsErr(e instanceof ApiError ? e.message : 'Failed.');
    }
  };

  const onDeleteAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setDeleteErr(null);
    setDeleting(true);
    try {
      await apiFetchJson('/auth/delete-account', {
        method: 'POST',
        body: JSON.stringify({ password: deletePassword }),
      });
      // The server has wiped the row + sessions; clear local state.
      await logout();
    } catch (e) {
      setDeleteErr(e instanceof ApiError ? e.message : 'Failed.');
    } finally {
      setDeleting(false);
    }
  };

  if (!user) {
    return (
      <div className="text-sm text-[#94a3b8] p-6">
        <Loader2 size={16} className="inline mr-2 animate-spin" /> Loading profile…
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl text-white font-semibold">Account &amp; security</h1>
        <p className="text-sm text-[#94a3b8] mt-1">
          Manage your identity, sessions, and privacy controls. Audit-logged.
        </p>
      </div>

      {/* Identity card */}
      <Card title="Identity">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
          <KV k="Email" v={user.email} />
          <KV k="Role" v={<span className="capitalize">{user.role}</span>} />
          <KV k="Email verified" v={user.emailVerified ? 'Yes' : 'No'} />
          <KV
            k="Account created"
            v={new Date(user.createdAt).toLocaleString()}
          />
          <KV
            k="Privacy notice version"
            v={user.gdprConsentVersion ?? 'Not recorded'}
          />
          <KV
            k="Last sign-in"
            v={user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : 'First session'}
          />
        </div>
        <form onSubmit={onSaveName} className="mt-5 flex items-end gap-3">
          <label className="flex-1">
            <span className="text-xs uppercase tracking-wider text-[#94a3b8]">Display name</span>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={128}
              placeholder="(optional)"
              className="mt-1 w-full px-3 py-2 bg-[#15181e] border border-[#2d333b] rounded-lg text-sm text-white outline-none focus:border-[#8e51df]"
            />
          </label>
          <button
            type="submit"
            disabled={savingName}
            className="px-4 py-2 bg-[#6a2bba] text-white text-sm rounded-lg flex items-center gap-2 hover:bg-[#7a3bcb] disabled:opacity-60"
          >
            {savingName ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
            Save
          </button>
        </form>
        {nameMsg && <p className="mt-2 text-xs text-[#94a3b8]">{nameMsg}</p>}
      </Card>

      {/* Password change */}
      <Card title="Change password">
        <form onSubmit={onChangePassword} className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <PasswordField
            label="Current password"
            value={currentPassword}
            onChange={setCurrentPassword}
            autoComplete="current-password"
            wide
          />
          <PasswordField
            label="New password"
            value={newPassword}
            onChange={setNewPassword}
            autoComplete="new-password"
          />
          <PasswordField
            label="Confirm new password"
            value={confirmPassword}
            onChange={setConfirmPassword}
            autoComplete="new-password"
          />
          <div className="sm:col-span-2 flex items-center gap-3 mt-2">
            <button
              type="submit"
              disabled={changing}
              className="px-4 py-2 bg-[#6a2bba] text-white text-sm rounded-lg flex items-center gap-2 hover:bg-[#7a3bcb] disabled:opacity-60"
            >
              {changing ? <Loader2 size={14} className="animate-spin" /> : <KeyRound size={14} />}
              Update password
            </button>
            {pwMsg && <span className="text-xs text-[#94a3b8]">{pwMsg}</span>}
          </div>
        </form>
        <p className="mt-3 text-xs text-[#64748b]">
          Changing your password revokes every active session on every device — including this one.
        </p>
      </Card>

      {/* Sessions */}
      <Card title="Active sessions">
        {loadingSessions ? (
          <div className="text-sm text-[#94a3b8] flex items-center gap-2">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : sessionsErr ? (
          <div className="text-sm text-red-300">{sessionsErr}</div>
        ) : sessions.length === 0 ? (
          <div className="text-sm text-[#94a3b8]">No active sessions.</div>
        ) : (
          <div className="space-y-2">
            {sessions.map((s) => (
              <div
                key={s.id}
                className="flex items-center gap-3 p-3 bg-[#15181e] border border-[#2d333b] rounded-lg"
              >
                <Smartphone size={16} className="text-[#8e51df] shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white truncate">
                    {s.userAgent ?? 'Unknown client'}
                  </div>
                  <div className="text-xs text-[#94a3b8] mt-0.5">
                    {s.ipAddress ?? 'no ip'} · last used{' '}
                    {s.lastUsedAt ? new Date(s.lastUsedAt).toLocaleString() : 'never'} · expires{' '}
                    {new Date(s.expiresAt).toLocaleString()}
                  </div>
                </div>
                {s.current ? (
                  <span className="text-[10px] uppercase tracking-wider px-2 py-1 rounded bg-emerald-950/40 border border-emerald-900/40 text-emerald-300">
                    Current
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => onRevokeSession(s.id)}
                    className="text-xs flex items-center gap-1 px-2 py-1 rounded border border-[#2d333b] text-[#cbd5e1] hover:bg-[#2d333b]/40"
                    title="Revoke this session"
                  >
                    <X size={12} /> Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
        <button
          type="button"
          onClick={() => void logout()}
          className="mt-4 px-4 py-2 bg-transparent border border-[#2d333b] text-sm text-[#cbd5e1] rounded-lg flex items-center gap-2 hover:bg-[#2d333b]/40"
        >
          <LogOut size={14} /> Sign out of this device
        </button>
      </Card>

      {/* Delete account */}
      <Card title="Delete account" tone="danger">
        <p className="text-sm text-[#cbd5e1] leading-relaxed">
          Exercise your GDPR / KVKK right to erasure. Your identity row, all active sessions, and
          all outstanding password-reset / verification tokens are permanently removed. The audit
          ledger keeps an anonymized record of the deletion (without your email or user id) for
          security accountability.
        </p>
        {!deleteOpen ? (
          <button
            type="button"
            onClick={() => setDeleteOpen(true)}
            className="mt-4 px-4 py-2 bg-red-950/30 border border-red-900/40 text-sm text-red-300 rounded-lg flex items-center gap-2 hover:bg-red-950/60"
          >
            <Trash2 size={14} /> I understand, delete my account
          </button>
        ) : (
          <form onSubmit={onDeleteAccount} className="mt-4 space-y-3">
            <PasswordField
              label="Confirm with your password"
              value={deletePassword}
              onChange={setDeletePassword}
              autoComplete="current-password"
              wide
            />
            {deleteErr && <div className="text-sm text-red-300">{deleteErr}</div>}
            <div className="flex items-center gap-2">
              <button
                type="submit"
                disabled={deleting}
                className="px-4 py-2 bg-red-700 text-white text-sm rounded-lg flex items-center gap-2 hover:bg-red-600 disabled:opacity-60"
              >
                {deleting ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
                Permanently delete account
              </button>
              <button
                type="button"
                onClick={() => {
                  setDeleteOpen(false);
                  setDeletePassword('');
                  setDeleteErr(null);
                }}
                className="px-4 py-2 text-sm text-[#cbd5e1] rounded-lg hover:bg-[#2d333b]/40"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </Card>

      <div className="text-xs text-[#64748b] flex items-start gap-2">
        <ShieldCheck size={14} className="mt-0.5 text-emerald-500 shrink-0" />
        <span>
          All actions on this page are recorded in the auth audit log alongside the request IP and
          user agent so security operations can investigate suspicious activity.
        </span>
      </div>
    </div>
  );
}

function Card({
  title,
  tone,
  children,
}: {
  title: string;
  tone?: 'danger';
  children: React.ReactNode;
}) {
  return (
    <div
      className={`rounded-2xl p-6 ${
        tone === 'danger'
          ? 'border border-red-900/30 bg-red-950/10'
          : 'border border-[#2d333b] bg-[#15181e]'
      }`}
    >
      <h2 className="text-sm font-semibold tracking-wider text-white uppercase">{title}</h2>
      <div className="mt-4">{children}</div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">{k}</div>
      <div className="text-sm text-white mt-0.5">{v}</div>
    </div>
  );
}

function PasswordField({
  label,
  value,
  onChange,
  autoComplete,
  wide,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete: string;
  wide?: boolean;
}) {
  return (
    <label className={wide ? 'sm:col-span-2 block' : 'block'}>
      <span className="text-xs uppercase tracking-wider text-[#94a3b8]">{label}</span>
      <input
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        minLength={1}
        className="mt-1 w-full px-3 py-2 bg-[#15181e] border border-[#2d333b] rounded-lg text-sm text-white outline-none focus:border-[#8e51df]"
      />
    </label>
  );
}
