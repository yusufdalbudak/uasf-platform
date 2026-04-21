import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Loader2, Lock, ShieldCheck } from 'lucide-react';
import AuthLayout from '../auth/AuthLayout';
import { apiFetchJson, ApiError } from '../lib/api';
import { Field, ErrorBanner } from './Login';

export default function ResetPassword() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const t = params.get('token');
    if (t) {
      queueMicrotask(() => {
        if (!cancelled) setToken(t);
      });
    }
    return () => {
      cancelled = true;
    };
  }, [params]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    setSubmitting(true);
    try {
      await apiFetchJson('/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({ token, newPassword: password }),
      });
      setDone(true);
      setTimeout(() => navigate('/login', { replace: true }), 1800);
    } catch (e2) {
      setError(e2 instanceof ApiError ? e2.message : 'Reset failed.');
    } finally {
      setSubmitting(false);
    }
  };

  if (done) {
    return (
      <AuthLayout title="Password updated" subtitle="Redirecting you to sign in…">
        <div className="flex items-center gap-2 p-4 rounded-lg bg-emerald-950/30 border border-emerald-900/40 text-sm text-emerald-300">
          <ShieldCheck size={18} />
          Your password has been reset. Existing sessions on every device have been revoked.
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Choose a new password"
      subtitle="Resetting will sign you out everywhere."
      footer={
        <Link to="/login" className="text-[#8e51df] hover:text-[#a875e8]">
          Back to sign in
        </Link>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4">
        <Field
          label="Reset token"
          icon={<Lock size={16} />}
          input={
            <input
              type="text"
              required
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="w-full bg-transparent text-sm text-white placeholder:text-[#475569] outline-none font-mono"
              placeholder="Paste the reset token"
            />
          }
        />
        <Field
          label="New password"
          icon={<Lock size={16} />}
          input={
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-transparent text-sm text-white placeholder:text-[#475569] outline-none"
              placeholder="At least 12 characters"
            />
          }
        />
        <Field
          label="Confirm new password"
          icon={<Lock size={16} />}
          input={
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="w-full bg-transparent text-sm text-white placeholder:text-[#475569] outline-none"
              placeholder="Re-enter your password"
            />
          }
        />
        {error && <ErrorBanner message={error} />}
        <button
          type="submit"
          disabled={submitting || !token}
          className="w-full mt-2 bg-gradient-to-r from-[#8e51df] to-[#6a2bba] text-white font-medium py-2.5 rounded-lg flex items-center justify-center gap-2 hover:shadow-lg hover:shadow-[#6a2bba]/30 transition disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {submitting ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />}
          {submitting ? 'Updating…' : 'Update password'}
        </button>
      </form>
    </AuthLayout>
  );
}
