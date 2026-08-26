# Threat Model

## Project Overview

Nylo is an experimental browser SDK and Node/Express reference server for
consent-gated, pseudonymous identity continuity and analytics across
organization-owned domains. The browser stores a first-party WaiTag after
consent, obtains short-lived server-signed write grants, and can transfer
identity through encrypted, signed, destination-bound WTX-1 tokens.

The project is a reference implementation, not a hosted identity provider.
Production security depends on integrators supplying tenant/domain mappings,
per-tenant API keys, durable storage, atomic replay consumption, TLS, and
authenticated administrative interfaces.

## Assets

- **Pseudonymous identity context** — WaiTags, session IDs, optional linked user
  IDs, and cross-domain continuity. Disclosure or tampering can expose user
  activity or corrupt analytics.
- **Tenant analytics integrity** — events and identity registrations must only
  be written to the tenant authorized for the page domain.
- **Consent state** — no identity, persistence, or tracking traffic may occur
  before consent; withdrawal must stop work and purge SDK-created state.
- **WTX-1 and write-grant secrets** — compromise permits forgery. Secrets must
  remain server-side and be tenant/purpose separated where applicable.
- **Domain ownership state and API keys** — these authorize DNS management and
  server-to-server token generation for a specific tenant.
- **Replay state** — consumed-token records enforce single use and must be
  durable and atomic in production.
- **Privacy claims and protocol evidence** — documentation is security-relevant:
  overstatement can cause unsafe deployments and compliance errors.

## Trust Boundaries

- **Browser to SDK** — page scripts, public SDK calls, metadata, URLs, storage,
  and DOM events are untrusted. Fingerprint-capable fields and excessive data
  must be removed before transport.
- **SDK to server** — CORS is not authentication. Every browser write requires a
  scoped, expiring grant bound to the page domain and server-resolved tenant.
- **Server-to-server API** — token generation and DNS management require a
  tenant-specific API key; request bodies cannot select another tenant.
- **Server to storage** — event writes, domain state, and replay consumption can
  fail or race. Authorization must finish before storage mutation, and token
  replay consumption must be atomic.
- **Source domain to destination domain** — WTX-1 tokens cross an untrusted URL
  transport. Tokens must be encrypted, signed, short-lived, destination- and
  tenant-bound, and removed from the browser URL after processing.
- **Development examples to production deployments** — demo viewers are
  intentionally unauthenticated. All demo servers refuse production mode;
  production consumers must mount `setupNyloRoutes` and build authenticated
  administrative views.
- **Implementation to public claims** — README, SECURITY, protocol, patent, and
  marketing text must distinguish tested behavior from legal conclusions,
  optional deployment controls, and historical submitted drafts.

## Scan Anchors

- Production aggregate entry point: `server/index.ts` (`setupNyloRoutes`)
- Browser security/privacy core: `src/nylo.js`
- Authorization and identity routes: `server/api/`
- Shared cryptographic/security cores: `server/utils/token-core.js`,
  `server/utils/write-grant.js`, `server/utils/security-core.js`
- Contract and exploit regression coverage: `test/` and `tests/`
- Development-only surfaces: `examples/demo-server*.js`

## Threat Categories

### Spoofing

Attackers may forge tenant IDs, page domains, grants, API keys, or WTX-1
envelopes. Tenant identity must come only from a verified grant, API-key lookup,
or server-owned domain mapping. Domain matching must use exact host boundaries,
and production must fail closed when secrets or durable replay storage are
missing.

### Tampering

Attackers may poison events, register arbitrary identifiers, alter token routing
metadata, or race replay consumption. Browser writes require scoped grants;
identity formats and event envelopes are bounded and validated; WTX-1 uses
AES-256-GCM plus an independently derived HMAC key; authorization and token
validity checks occur before one atomic replay consume.

### Repudiation

The reference implementation does not provide a full administrative audit
system. Sensitive DNS and token-generation operations must be attributable to a
tenant API key in production integrations, without logging raw secrets or
identity tokens. Multi-approver and richer audit UX remain platform work.

### Information Disclosure

URLs can contain identifiers, metadata can contain fingerprinting properties,
and analytics viewers expose pseudonymous activity. The SDK and server remove
query strings/fragments and recursively strip fingerprint-capable fields.
Tokens use fragment transport by default and encrypt identity claims. Demo
viewers are development-only; production viewers require separate
authentication and authorization.

### Denial of Service

Attackers may send large bodies/tokens, generate many rate-limit keys, hold SSE
connections, trigger storage failures, or burn stolen tokens. Body, batch,
event, identifier, and token-envelope sizes are bounded. Unauthorized callers
cannot consume tokens. Current rate limits are process-local and are not a
substitute for distributed edge controls, quotas, or anomaly detection.

### Elevation of Privilege

The principal privilege boundary is tenant isolation. Browser-supplied customer
IDs are rejected when conflicting and never establish authority. API keys
resolve their tenant before DNS or token operations. Individual route
registrars are not exported because mounting them directly could bypass the
aggregate middleware and startup checks.

## Required Security Guarantees

- Consent withdrawal invalidates every in-flight identity operation and write.
- No predictable identifier fallback is permitted when Web Crypto fails.
- No unsanitized metadata subtree may bypass privacy filtering because of depth,
  cycles, aliases, or serialization errors.
- No browser request may choose its tenant.
- Invalid or unauthorized token requests must not consume replay state.
- Production replay protection must be durable, shared, and atomic.
- WTX-1 token inputs must be bounded before decoding or cryptographic work.
- Example servers must not be deployable as production analytics viewers.
- Claims must say pseudonymous, not anonymous, except when quoting legal text.
