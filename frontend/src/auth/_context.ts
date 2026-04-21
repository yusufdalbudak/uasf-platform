import { createContext } from 'react';
import type { AuthUser } from './types';

/**
 * Internal context surface. Lives in its own non-component module so the
 * provider file can stay React-Refresh-clean.
 */
export interface AuthState {
  status: 'bootstrapping' | 'authenticated' | 'anonymous';
  user: AuthUser | null;
  accessTokenExpiresAt: string | null;
  lastError: string | null;
}

export interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  signup: (input: {
    email: string;
    password: string;
    displayName?: string;
    gdprConsent: boolean;
  }) => Promise<{ pendingVerification: boolean }>;
  logout: () => Promise<void>;
  refreshNow: () => Promise<boolean>;
  setUser: (user: AuthUser | null) => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
