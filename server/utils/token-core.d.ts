// SPDX-License-Identifier: LicenseRef-Nylo-Commercial
//
// WTX-1 token format v2 (sign-then-encrypt):
// signCrossDomainToken() HMAC-SHA256-signs a canonical payload, then seals it
// with AES-256-GCM under keys derived per (tenantId, destinationDomain) via
// HKDF-SHA256 from the server secret. The returned string is a base64 envelope
// exposing only routing metadata (v, tid, dst, iv, ct, tag).
// verifyCrossDomainToken() rejects legacy cleartext tokens (UNSUPPORTED_VERSION)
// and returns the decrypted payload only after AEAD + signature + binding checks.
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
