import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Loader2, Mail, Lock, AlertCircle } from 'lucide-react';
import AuthLayout from '../auth/AuthLayout';
import { useAuth } from '../auth/useAuth';
import { ApiError } from '../lib/api';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      const target =
        (location.state as { from?: string } | null)?.from && (location.state as { from?: string }).from!.startsWith('/')
          ? (location.state as { from?: string }).from!
          : '/';
      navigate(target, { replace: true });
    } catch (e2) {
      const msg = e2 instanceof ApiError ? e2.message : 'Sign-in failed.';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthLayout
      title="Sign in"
      subtitle="Welcome back. Enter your credentials to access the platform."
      footer={
        <>
          New to the platform?{' '}
          <Link to="/signup" className="text-[#8e51df] hover:text-[#a875e8]">
            Create an account
          </Link>
          <br />
          <Link to="/forgot-password" className="text-[#94a3b8] hover:text-white text-xs mt-2 inline-block">
            Forgot your password?
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4">
        <Field
          label="Email"
          icon={<Mail size={16} />}
          input={
            <input
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-transparent text-sm text-white placeholder:text-[#475569] outline-none"
              placeholder="you@example.com"
            />
          }
        />
        <Field
          label="Password"
          icon={<Lock size={16} />}
          input={
            <input
              type="password"
              autoComplete="current-password"
              required
              minLength={1}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-transparent text-sm text-white placeholder:text-[#475569] outline-none"
              placeholder="••••••••"
            />
          }
        />
        {error && <ErrorBanner message={error} />}
        <button
          type="submit"
          disabled={submitting}
          className="w-full mt-2 bg-gradient-to-r from-[#8e51df] to-[#6a2bba] text-white font-medium py-2.5 rounded-lg flex items-center justify-center gap-2 hover:shadow-lg hover:shadow-[#6a2bba]/30 transition disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {submitting && <Loader2 size={16} className="animate-spin" />}
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </AuthLayout>
  );
}

export function Field({ label, icon, input }: { label: string; icon: React.ReactNode; input: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs uppercase tracking-wider text-[#94a3b8]">{label}</span>
      <div className="mt-1 flex items-center gap-2 px-3 py-2.5 bg-[#15181e] border border-[#2d333b] rounded-lg focus-within:border-[#8e51df] transition">
        <span className="text-[#475569]">{icon}</span>
        {input}
      </div>
    </label>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 p-3 rounded-lg bg-red-950/40 border border-red-900/40 text-sm text-red-300">
      <AlertCircle size={16} className="mt-0.5 shrink-0" />
      <span>{message}</span>
    </div>
  );
}
