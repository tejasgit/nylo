---
name: Nylo security model
description: Durable security/privacy invariants for the Nylo SDK and servers — preserve these when changing tracking, CORS, or token code.
---

# Nylo security model

- **Consent-gated, default off.** The SDK must create no identity, cookies, storage, or network traffic without granted consent; withdrawal must purge everything the SDK created and stop all tracking. Async startup must be cancellable — re-check consent (via an epoch) at every async continuation, or a grant-then-withdraw race can repopulate identity after withdrawal.
  **Why:** the product's core claim is privacy-first; any post-withdrawal tracking is treated as P0.
  **How to apply:** route new tracking through the consent-guarded queue/send paths and respect the cancellation epoch.

- **Fail closed everywhere.** Missing or invalid tracking configuration disables all features; an unconfigured CORS allowlist denies all cross-origin requests in production (loopback-only in dev). Never reintroduce fail-open defaults or origin reflection with credentials — example/demo servers count as shipped code and must use the same shared middleware and verifiers as the main server.

- **Single source of truth for security logic.** Domain/origin matching and cross-domain token signing/verification live in shared plain-CJS core modules consumed by every server; change rules there, never per-route. Matching must be exact host-boundary (no suffix or substring checks). Tokens carry version, jti, iat, exp and are bound to tenant + source + destination domains, verified for the same tenant at generation and verification, with replay protection.
  **Why:** the runtime here is Node 18 (no direct TS execution), so shared pure logic in CJS keeps the TS server, JS demos, and `node --test` on identical code.

- **Browser writes are grant-authorized; tenants are server-resolved.** Every browser write path (ingestion, WaiTag registration, token verification) requires a short-lived signed write grant (`X-Nylo-Grant`) bound to tenant + domain + scope. Tenant identity comes only from server-side domain→tenant mapping (grant issuance) or API-key lookup — never from browser-supplied customer IDs/headers; conflicting legacy `customerId` is rejected, not reassigned.
  **Why:** browser-asserted tenancy let any page write into any tenant's data.
  **How to apply:** new write endpoints must call `requireWriteGrant` before touching state; authorization checks must complete before consuming replay-protected tokens (unauthorized calls must not burn tokens); production requires a durable atomic replay store (memory stores are dev-only) and refuses to start without it.

- **Privacy minimization is structural, not configurable.** Fingerprint-capable fields (user agent, language, timezone, screen/viewport, click coordinates, capabilities) are never collected by the SDK and are stripped server-side as defense in depth (`stripFingerprintFields`); URLs are reduced to origin + path (`sanitizeUrlForStorage`) with query/fragment dropped unless allowlisted; identity generation/matching never uses browser or device attributes. Stored identity is honestly documented as reversible *encoding* + HMAC tamper evidence, not encryption.
  **Why:** these claims are load-bearing in README/SECURITY/spec and in the patent-alignment work; regressions here are P0 credibility failures.

- Deliberately removed (don't reintroduce): fingerprint-based identity-sync endpoint, the no-op waitag verification endpoint, `Math.random` fallbacks for secure IDs, and raw-`Host`-header HTTPS redirects.
