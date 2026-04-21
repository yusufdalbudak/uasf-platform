import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Loader2, Mail, Lock, User as UserIcon, ShieldCheck } from 'lucide-react';
import AuthLayout from '../auth/AuthLayout';
import { useAuth } from '../auth/useAuth';
import { ApiError } from '../lib/api';
import { Field, ErrorBanner } from './Login';

export default function Signup() {
  const { signup } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [consent, setConsent] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    if (!consent) {
      setError('You must accept the privacy notice to continue.');
      return;
    }
    setSubmitting(true);
    try {
      const result = await signup({
        email,
        password,
        displayName: displayName.trim() || undefined,
        gdprConsent: true,
      });
      if (result.pendingVerification) {
        setPending(true);
        return;
      }
      navigate('/', { replace: true });
    } catch (e2) {
      const msg = e2 instanceof ApiError ? e2.message : 'Signup failed.';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  if (pending) {
    return (
      <AuthLayout title="Check your inbox" subtitle="One more step to activate your account.">
        <div className="text-sm text-[#cbd5e1] leading-relaxed">
          We've sent a verification link to <strong className="text-white">{email}</strong>. Click
          it to activate your account, then return to{' '}
          <Link to="/login" className="text-[#8e51df] hover:text-[#a875e8]">
            sign in
          </Link>
          .
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Create your account"
      subtitle="The first account on a fresh deployment becomes administrator automatically."
      footer={
        <>
          Already have an account?{' '}
          <Link to="/login" className="text-[#8e51df] hover:text-[#a875e8]">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4">
        <Field
          label="Display name"
          icon={<UserIcon size={16} />}
          input={
            <input
              type="text"
              autoComplete="name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={128}
              className="w-full bg-transparent text-sm text-white placeholder:text-[#475569] outline-none"
              placeholder="(optional)"
            />
          }
        />
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
          label="Confirm password"
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
        <p className="text-xs text-[#64748b] leading-relaxed">
          Use 12+ characters. Long passphrases are fine — passwords of 16+ characters are
          accepted without composition rules (per NIST SP 800-63B).
        </p>

        <label className="flex items-start gap-2.5 mt-2 text-sm text-[#cbd5e1] leading-relaxed cursor-pointer">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            className="mt-1 accent-[#8e51df]"
          />
          <span>
            I have read and accept the{' '}
            <a href="#" className="text-[#8e51df] hover:text-[#a875e8]">
              privacy notice
            </a>{' '}
            (GDPR / KVKK). I understand my email is processed solely to provide access and
            audit security-sensitive actions, and that I can request account deletion at any
            time from my profile.
          </span>
        </label>

        {error && <ErrorBanner message={error} />}

        <button
          type="submit"
          disabled={submitting}
          className="w-full mt-2 bg-gradient-to-r from-[#8e51df] to-[#6a2bba] text-white font-medium py-2.5 rounded-lg flex items-center justify-center gap-2 hover:shadow-lg hover:shadow-[#6a2bba]/30 transition disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {submitting ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />}
          {submitting ? 'Creating account…' : 'Create account'}
        </button>
      </form>
    </AuthLayout>
  );
}
