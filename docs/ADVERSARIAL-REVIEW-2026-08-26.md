# Nylo Post-Remediation Adversarial Review

**Date:** 2026-08-26  
**Scope:** browser SDK, consent/storage, write grants, ingestion, tenant
isolation, WTX-1 generation/verification/replay, DNS authorization, CORS,
examples, adapters, packaging, denial of service, and public claims.

## Executive Result

The fresh review reproduced and fixed the contained critical/high engineering
findings found in the post-remediation code. The tested implementation now
fails closed for deep/cyclic metadata, browser HMAC failures, oversized token
envelopes, invalid token identity claims, reset/withdrawal races, direct route
registrar composition, and persistent-demo registration.

Nylo remains experimental. This review is not a penetration-test certification,
legal opinion, or guarantee about an integrator's deployment.

## Method

The review combined independent static passes with practical regression and
integration attacks:

- conflicting tenant assertions against grant/API-key-derived tenants;
- unauthorized stolen-token verification before replay consumption;
- concurrent replay attempts;
- ciphertext, routing, version, IV, tag, and oversized-envelope mutation;
- cross-origin/domain mismatch and unsafe Host redirect review;
- grant-then-withdraw and reset/withdraw async interleavings;
- shallow, deep, aliased, and cyclic metadata privacy probes;
- URL query/fragment exfiltration probes;
- transient storage failures and retry/dedup behavior;
- missing-secret and missing-durable-replay production startup checks;
- unauthenticated demo identity registration and direct registrar composition.

## Fixed Findings

### F-01 — Deep metadata privacy bypass and cyclic serialization

**Former severity:** High  
**Resolution:** Fixed.

`sanitizeMetadataForTransport` in `src/nylo.js` now replaces over-depth and
cyclic subtrees instead of returning unsanitized values. Regression:
`test/sdk-privacy.test.js`, “deep and cyclic metadata cannot bypass
client-side privacy stripping.”

### F-02 — HMAC failure persisted or activated unverified identity

**Former severity:** High  
**Resolution:** Fixed.

New and cross-domain identity paths now keep candidate identities local until
integrity generation succeeds. Failure discards the identity and prevents
storage/registration/context activation. Evidence: `src/nylo.js`
`generateNewIdentity` and `verifyAndProcessToken`.

### F-03 — Reset/withdrawal stale completion

**Former severity:** High  
**Resolution:** Fixed.

`resetContext` now advances the tracking epoch and passes a cancellation
predicate into identity generation. State mutation occurs only after the async
integrity step and an epoch/consent recheck.

### F-04 — Unbounded WTX-1 envelope decoding and AES work

**Former severity:** High  
**Resolution:** Fixed.

`server/utils/token-core.js` rejects oversized tokens and bounds tenant,
destination, IV, authentication tag, and ciphertext before key derivation or
decryption. Regression: `test/token-core.test.js`, “oversized and malformed
encrypted envelopes are rejected before decryption.”

### F-05 — Token generation accepted malformed identity claims

**Former severity:** High  
**Resolution:** Fixed.

`server/api/waitag-tracking.ts` validates WaiTag/session formats and bounds
optional user IDs before signing. Tenant and domains still come from API-key
lookup and verified domain state.

### F-06 — Persistent demos bypassed grant-gated WaiTag registration

**Former severity:** Critical/High  
**Resolution:** Fixed.

`examples/demo-write-routes.js` supplies one server-mapped grant issuer and
grant/domain/tenant-bound registration route used by SQLite and PostgreSQL
demos. Their ingestion and token verification use the same grant secret.
Regression: `test/demo-write-routes.test.js`.

### F-07 — Demo viewers could be mistaken for production admin APIs

**Former severity:** High  
**Resolution:** Mitigated by enforced boundary.

All demo server variants refuse `NODE_ENV=production`; persistent demos explain
that their event viewers are intentionally unauthenticated. The in-memory demo
also caps retained interactions and registrations. Production deployments must
provide authenticated administrative views separately.

### F-08 — Exported route registrars enabled aggregate middleware bypass

**Former severity:** High  
**Resolution:** Fixed.

`server/index.ts` no longer exports individual route registrars. The supported
public server composition path is `setupNyloRoutes`, which installs centralized
CORS, security headers, request/rate limits, and production fail-closed checks.

## Mitigated or Accepted Operational Risks

- **Sensitive path segments:** URL query strings, fragments, and credentials are
  removed, but origin/path are retained for analytics. Applications must not put
  secrets or direct identifiers in path segments.
- **Storage deletion failure:** browser storage APIs can fail for reasons outside
  SDK control. Withdrawal clears in-memory state and prevents network activity;
  integrators should verify browser-policy behavior in their support matrix.
- **Process-local rate limiting:** useful for development and single-process
  defense, but not represented as distributed abuse prevention.
- **Query-token compatibility mode:** fragment transport is the secure default;
  enabling legacy query transport can expose tokens to HTTP infrastructure and
  is not recommended.
- **Browser-held integrity key:** local HMAC is documented as corruption
  detection, not client authenticity against XSS/extensions.

## Unverified Assumptions

- No external penetration-testing firm independently reproduced this review.
- Patent claim reconstruction, licensing conclusions, trademark status, and
  regulatory interpretation require qualified counsel.
- Production Redis/PostgreSQL/distributed replay implementations were not load-
  or chaos-tested here; the interface and production refusal were tested.
- Edge proxy behavior, TLS termination, distributed quotas, and authenticated
  admin UI are integrator responsibilities.

## Exactly Ten Deferred Collaborator Issues

These are intentionally deferred to the existing collaborator-issue task. They
are lower-priority, externally owned, or require product/legal/platform design.

1. **Clarify market and novelty positioning** — compare WTX-1 accurately with
   established linker mechanisms and avoid claiming identity handoff itself is
   novel.
2. **Complete product-name and trademark due diligence** — resolve collision
   risk with the existing Nylo software framework before broad promotion.
3. **Separate license/package boundaries and obtain counsel review** — move
   mixed-license functionality into unambiguous artifacts and verify example
   licensing.
4. **Replace client-derived “encrypted configuration” with signed configuration
   integrity** — browsers cannot keep execution configuration confidential.
5. **Add distributed abuse controls and anomaly detection** — edge rate limits,
   tenant quotas, connection caps, and event-volume alerts.
6. **Add consent receipts, DSAR/deletion hooks, retention enforcement, and GPC
   integration** — complete the post-collection privacy lifecycle.
7. **Establish CI, browser compatibility, and release gates** — automate full
   cross-browser and cross-domain checks plus dependency/security validation.
8. **Adopt a prerelease version and release policy** — align package versioning
   and maturity signals with the experimental implementation.
9. **Design administrative 2FA, multi-approver, and audit UX** — protect
   high-impact tenant/domain operations in a hosted management plane.
10. **Add recurring DNS verification and key-rotation monitoring** — detect
    ownership drift and stale/compromised credentials over time.

## Validation Evidence

- Full Node test suite: passed after remediation.
- TypeScript: `tsc --noEmit --project tsconfig.json` passed.
- JavaScript syntax checks: SDK, token core, and all modified demo files passed.
- Replay race: concurrent verification tests permit exactly one success.
- Unauthorized token consumption: grant authorization precedes replay consume.
- Tenant isolation: grant/API-key tenant mismatch tests reject caller assertions.
- Privacy: outbound fingerprint aliases, deep values, URL query/fragment data,
  and cycles are covered by regression tests.
- Demo authorization: missing grant and cross-tenant registration are rejected.
