import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  apiFetchJson,
  ApiError,
  registerRefreshHandler,
  registerUnauthenticatedHandler,
  setAccessToken,
} from '../lib/api';
import type { AuthIssuance, AuthUser } from './types';
import { AuthContext, type AuthContextValue, type AuthState } from './_context';

/**
 * AuthProvider — single source of truth for the authenticated user.
 *
 * Lifecycle:
 *   1. On mount we POST /api/auth/refresh: the browser sends the httpOnly
 *      refresh-cookie automatically. If a session is alive we receive a
 *      fresh access token + user payload and the app renders authenticated.
 *      If not, we render unauthenticated so the router can show /login.
 *
 *   2. While authenticated we proactively refresh ~30 s before the access
 *      token expires so the user never sees a flash of 401.
 *
 *   3. We also register a refresh callback with the API client so any
 *      protected request that hits 401 (e.g. server restart, manual revoke)
 *      can be transparently retried after a single refresh attempt.
 *
 *   4. `logout()` calls /api/auth/logout (which clears the cookie + revokes
 *      the session row) and unwinds local state.
 */

const REFRESH_LEAD_MS = 30_000; // refresh 30 s before expiry
const MIN_REFRESH_INTERVAL_MS = 5_000;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    status: 'bootstrapping',
    user: null,
    accessTokenExpiresAt: null,
    lastError: null,
  });
  // Use a ref for the refresh timer so we can cancel it across re-renders
  // without triggering effect re-runs.
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // De-duplicate concurrent refresh attempts (e.g., proactive timer fires
  // while a 401 retry is mid-flight).
  const refreshInflight = useRef<Promise<string | null> | null>(null);

  const clearRefreshTimer = useCallback(() => {
    if (refreshTimer.current) {
      clearTimeout(refreshTimer.current);
      refreshTimer.current = null;
    }
  }, []);

  const applyIssuance = useCallback((issuance: AuthIssuance) => {
    setAccessToken(issuance.accessToken);
    setState({
      status: 'authenticated',
      user: issuance.user,
      accessTokenExpiresAt: issuance.accessTokenExpiresAt,
      lastError: null,
    });
  }, []);

  const clearAuth = useCallback(() => {
    setAccessToken(null);
    setState({
      status: 'anonymous',
      user: null,
      accessTokenExpiresAt: null,
      lastError: null,
    });
  }, []);

  // -------------------------------------------------------------------
  // Refresh primitive — single in-flight, returns the new access token.
  // -------------------------------------------------------------------
  const refresh = useCallback(async (): Promise<string | null> => {
    if (refreshInflight.current) return refreshInflight.current;
    const p = (async () => {
      try {
        const { data } = await apiFetchJson<AuthIssuance>('/auth/refresh', { method: 'POST' });
        applyIssuance(data);
        return data.accessToken;
      } catch {
        clearAuth();
        return null;
      } finally {
        refreshInflight.current = null;
      }
    })();
    refreshInflight.current = p;
    return p;
  }, [applyIssuance, clearAuth]);

  // -------------------------------------------------------------------
  // Boot: try refresh once. If it succeeds we're authenticated; else
  // we land on the login page.
  // -------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await apiFetchJson<AuthIssuance>('/auth/refresh', { method: 'POST' });
        if (cancelled) return;
        applyIssuance(data);
      } catch {
        if (cancelled) return;
        // No live session — render anonymously so the router can show /login.
        setAccessToken(null);
        setState({ status: 'anonymous', user: null, accessTokenExpiresAt: null, lastError: null });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [applyIssuance]);

  // -------------------------------------------------------------------
  // Wire the API client to our refresh / unauth callbacks.
  // -------------------------------------------------------------------
  useEffect(() => {
    registerRefreshHandler(() => refresh());
    registerUnauthenticatedHandler(() => clearAuth());
    return () => {
      registerRefreshHandler(null);
      registerUnauthenticatedHandler(null);
    };
  }, [refresh, clearAuth]);

  // -------------------------------------------------------------------
  // Proactive refresh ~30 s before expiry.
  // -------------------------------------------------------------------
  useEffect(() => {
    clearRefreshTimer();
    if (state.status !== 'authenticated' || !state.accessTokenExpiresAt) return;
    const expiresMs = new Date(state.accessTokenExpiresAt).getTime();
    const wait = Math.max(MIN_REFRESH_INTERVAL_MS, expiresMs - Date.now() - REFRESH_LEAD_MS);
    refreshTimer.current = setTimeout(() => {
      refresh().catch(() => undefined);
    }, wait);
    return clearRefreshTimer;
  }, [state.status, state.accessTokenExpiresAt, refresh, clearRefreshTimer]);

  // -------------------------------------------------------------------
  // Public actions
  // -------------------------------------------------------------------
  const login = useCallback(
    async (email: string, password: string) => {
      try {
        const { data } = await apiFetchJson<AuthIssuance>('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email, password }),
        });
        applyIssuance(data);
      } catch (e) {
        const msg = e instanceof ApiError ? e.message : 'Login failed.';
        setState((s) => ({ ...s, lastError: msg }));
        throw e;
      }
    },
    [applyIssuance],
  );

  const signup = useCallback<AuthContextValue['signup']>(
    async (input) => {
      try {
        const { data, response } = await apiFetchJson<AuthIssuance | { message: string; code: string }>(
          '/auth/signup',
          {
            method: 'POST',
            body: JSON.stringify(input),
          },
        );
        if (response.status === 202) {
          // Pending email verification — caller renders a "check your inbox" screen.
          return { pendingVerification: true };
        }
        applyIssuance(data as AuthIssuance);
        return { pendingVerification: false };
      } catch (e) {
        const msg = e instanceof ApiError ? e.message : 'Signup failed.';
        setState((s) => ({ ...s, lastError: msg }));
        throw e;
      }
    },
    [applyIssuance],
  );

  const logout = useCallback(async () => {
    try {
      await apiFetchJson('/auth/logout', { method: 'POST' });
    } catch {
      // We still want to clear local state even if the server call fails.
    } finally {
      clearAuth();
    }
  }, [clearAuth]);

  const refreshNow = useCallback(async () => {
    const token = await refresh();
    return token !== null;
  }, [refresh]);

  const setUser = useCallback((user: AuthUser | null) => {
    setState((s) => ({ ...s, user }));
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ ...state, login, signup, logout, refreshNow, setUser }),
    [state, login, signup, logout, refreshNow, setUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
