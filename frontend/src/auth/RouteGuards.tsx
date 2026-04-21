import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Loader2, Shield } from 'lucide-react';
import { useAuth } from './useAuth';
import type { UserRole } from './types';

/**
 * <ProtectedRoute> — wraps any page/section that requires a logged-in user.
 *
 * - While the auth context is bootstrapping (initial /auth/refresh in flight)
 *   we render a tiny full-screen loader to prevent a flash of "not found".
 * - When anonymous, we redirect to /login with `state.from` so the login
 *   page can bounce the user back to where they came from.
 * - Optional `roles` enforces RBAC: viewers / operators see a graceful
 *   "no permission" panel rather than being booted to login.
 */
export function ProtectedRoute({
  children,
  roles,
}: {
  children: ReactNode;
  roles?: UserRole[];
}) {
  const { status, user } = useAuth();
  const location = useLocation();

  if (status === 'bootstrapping') {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen text-[#94a3b8]">
        <Loader2 size={28} className="animate-spin text-[#8e51df] mb-4" />
        <span className="text-sm">Restoring session…</span>
      </div>
    );
  }
  if (status !== 'authenticated' || !user) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  if (roles && roles.length > 0 && !roles.includes(user.role)) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-[#94a3b8]">
        <Shield size={48} className="mb-4 opacity-30 text-[#8e51df]" />
        <h2 className="text-xl text-white">Permission required</h2>
        <p className="mt-2 text-sm max-w-md text-center">
          Your role ({user.role}) does not have access to this area. Ask an administrator to elevate your account.
        </p>
      </div>
    );
  }
  return <>{children}</>;
}

/**
 * <PublicRoute> — wraps login / signup / forgot pages.
 * If the user is already authenticated, bounce to the dashboard so they
 * never see the login screen again until they explicitly log out.
 */
export function PublicRoute({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();
  if (status === 'bootstrapping') {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen text-[#94a3b8]">
        <Loader2 size={28} className="animate-spin text-[#8e51df] mb-4" />
        <span className="text-sm">Loading…</span>
      </div>
    );
  }
  if (status === 'authenticated') {
    const target =
      (location.state as { from?: string } | null)?.from && (location.state as { from?: string }).from!.startsWith('/')
        ? (location.state as { from?: string }).from!
        : '/';
    return <Navigate to={target} replace />;
  }
  return <>{children}</>;
}
