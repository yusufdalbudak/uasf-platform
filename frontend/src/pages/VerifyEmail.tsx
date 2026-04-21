import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Loader2, MailCheck, AlertCircle } from 'lucide-react';
import AuthLayout from '../auth/AuthLayout';
import { apiFetchJson, ApiError } from '../lib/api';

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const [status, setStatus] = useState<'verifying' | 'ok' | 'error'>('verifying');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const token = params.get('token');
      if (!token) {
        if (!cancelled) {
          setStatus('error');
          setError('Verification link is missing the token parameter.');
        }
        return;
      }
      try {
        await apiFetchJson('/auth/verify-email', {
          method: 'POST',
          body: JSON.stringify({ token }),
        });
        if (!cancelled) setStatus('ok');
      } catch (e) {
        if (!cancelled) {
          setStatus('error');
          setError(e instanceof ApiError ? e.message : 'Verification failed.');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [params]);

  return (
    <AuthLayout
      title="Verify your email"
      footer={
        <Link to="/login" className="text-[#8e51df] hover:text-[#a875e8]">
          Continue to sign in
        </Link>
      }
    >
      {status === 'verifying' && (
        <div className="flex items-center gap-2 text-sm text-[#cbd5e1]">
          <Loader2 size={16} className="animate-spin" />
          Verifying your email…
        </div>
      )}
      {status === 'ok' && (
        <div className="flex items-center gap-2 p-4 rounded-lg bg-emerald-950/30 border border-emerald-900/40 text-sm text-emerald-300">
          <MailCheck size={18} />
          Your email is verified. You can now sign in.
        </div>
      )}
      {status === 'error' && (
        <div className="flex items-center gap-2 p-4 rounded-lg bg-red-950/40 border border-red-900/40 text-sm text-red-300">
          <AlertCircle size={18} />
          {error ?? 'Verification failed.'}
        </div>
      )}
    </AuthLayout>
  );
}
