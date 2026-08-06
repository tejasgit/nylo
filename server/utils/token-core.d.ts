export const TOKEN_VERSION: number;
export const DEFAULT_TTL_MS: number;

export interface TokenClaims {
  tenantId: string | number;
  sourceDomain: string;
  destinationDomain: string;
  waiTag: string;
  sessionId: string;
  userId?: string | null;
}

export interface TokenPayload {
  v: number;
  jti: string;
  iat: number;
  exp: number;
  tenantId: string;
  sourceDomain: string;
  destinationDomain: string;
  waiTag: string;
  sessionId: string;
  userId: string | null;
}

export interface VerifyResult {
  valid: boolean;
  payload: TokenPayload | null;
  error: string | null;
}

export function signCrossDomainToken(
  claims: TokenClaims,
  secret: string,
  opts?: { now?: number; ttlMs?: number; jti?: string }
): string;

export function verifyCrossDomainToken(
  token: string,
  secret: string,
  opts?: { now?: number; expectedDestination?: string; expectedTenant?: string | number }
): VerifyResult;

export function hashToken(token: string): string;

export function createInMemoryReplayStore(): {
  isTokenUsed(tokenHash: string): Promise<boolean>;
  markTokenUsed(tokenHash: string, expiresInMs?: number): Promise<void>;
  consumeToken(tokenHash: string, expiresInMs?: number): Promise<boolean>;
};
