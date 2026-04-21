import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Loader2, Mail, MailCheck } from 'lucide-react';
import AuthLayout from '../auth/AuthLayout';
import { apiFetchJson, ApiError } from '../lib/api';
import { Field, ErrorBanner } from './Login';

interface ForgotResponse {
  ok: boolean;
  /** Returned only in development so operators can complete the flow without SMTP. */
  devToken?: string;
}

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [devToken, setDevToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const { data } = await apiFetchJson<ForgotResponse>('/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ email }),
      });
      setDevToken(data.devToken ?? null);
      setDone(true);
    } catch (e2) {
      setError(e2 instanceof ApiError ? e2.message : 'Request failed.');
    } finally {
      setSubmitting(false);
    }
  };

  if (done) {
    return (
      <AuthLayout
        title="Check your inbox"
        subtitle="If an account exists for that email, we've sent a reset link."
        footer={
          <Link to="/login" className="text-[#8e51df] hover:text-[#a875e8]">
            Back to sign in
          </Link>
        }
      >
        <div className="flex items-center gap-2 p-4 rounded-lg bg-emerald-950/30 border border-emerald-900/40 text-sm text-emerald-300">
          <MailCheck size={18} />
          Reset link issued. The email never reveals whether the account exists.
        </div>
        {devToken && (
          <div className="mt-4 text-xs text-[#94a3b8] leading-relaxed">
            <strong className="text-[#cbd5e1]">Dev mode:</strong> SMTP is not configured, so the
            reset token is shown here so you can complete the flow:
            <pre className="mt-2 p-3 bg-[#0f1115] border border-[#2d333b] rounded overflow-x-auto text-[11px] text-[#cbd5e1]">
              {devToken}
            </pre>
            <p className="mt-2">
              Use it on the{' '}
              <Link to={`/reset-password?token=${encodeURIComponent(devToken)}`} className="text-[#8e51df]">
                reset-password page
              </Link>
              .
            </p>
          </div>
        )}
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Forgot your password?"
      subtitle="Enter your email and we'll send you a reset link."
      footer={
        <Link to="/login" className="text-[#8e51df] hover:text-[#a875e8]">
          Back to sign in
        </Link>
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
        {error && <ErrorBanner message={error} />}
        <button
          type="submit"
          disabled={submitting}
          className="w-full mt-2 bg-gradient-to-r from-[#8e51df] to-[#6a2bba] text-white font-medium py-2.5 rounded-lg flex items-center justify-center gap-2 hover:shadow-lg hover:shadow-[#6a2bba]/30 transition disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {submitting && <Loader2 size={16} className="animate-spin" />}
          {submitting ? 'Sending…' : 'Send reset link'}
        </button>
      </form>
    </AuthLayout>
  );
}
