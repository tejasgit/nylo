// SPDX-License-Identifier: MIT
export const GRANT_VERSION: number;
export const DEFAULT_GRANT_TTL_MS: number;
export const MAX_CLOCK_SKEW_MS: number;
export const GRANT_SCOPES: string[];

export interface WriteGrantClaims {
  tenantId: string | number;
  domain: string;
  scopes: string[];
}

export interface WriteGrantPayload {
  gv: number;
  jti: string;
  iat: number;
  exp: number;
  tenantId: string;
  domain: string;
  scopes: string[];
}

export interface GrantVerifyResult {
  valid: boolean;
  payload: WriteGrantPayload | null;
  error: string | null;
}

export function signWriteGrant(
  claims: WriteGrantClaims,
  secret: string,
  opts?: { now?: number; ttlMs?: number; jti?: string }
): string;

export function verifyWriteGrant(
  grant: string,
  secret: string,
  opts?: { now?: number; expectedDomain?: string; requiredScope?: string }
): GrantVerifyResult;
