import { useContext } from 'react';
import { AuthContext, type AuthContextValue } from './_context';

/**
 * Standalone hook so the AuthContext.tsx file (which exports the provider
 * component) is not flagged by react-refresh's "only export components" rule.
 */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth() must be used inside <AuthProvider>');
  return ctx;
}
