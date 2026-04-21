export type UserRole = 'admin' | 'operator' | 'viewer';
export type UserStatus = 'active' | 'disabled' | 'pending_verification';

export interface AuthUser {
  id: string;
  email: string;
  displayName: string | null;
  role: UserRole;
  emailVerified: boolean;
  status: UserStatus;
  createdAt: string;
  lastLoginAt: string | null;
  gdprConsentVersion: string | null;
  gdprConsentAt: string | null;
}

export interface AuthIssuance {
  user: AuthUser;
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
  sessionId: string;
}

export interface AuthSessionRow {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string;
  current: boolean;
}
