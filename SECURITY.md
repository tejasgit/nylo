# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Nylo, please report it responsibly.

**Email:** hello@waifind.com

**Subject line:** `[SECURITY] Brief description of the issue`

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation plan within 7 days for critical issues.

**Do not** open a public GitHub issue for security vulnerabilities.

## Scope

The following components are in scope for security reports:

- **Client SDK** (`src/nylo.js`) — XSS, injection, data leakage
- **Server APIs** (`server/`) — authentication bypass, injection, CORS misconfiguration
- **Cross-domain token exchange** — token forgery, replay attacks, identity leakage
- **Encrypted configuration** — key derivation weaknesses, config tampering
- **DNS verification** — verification bypass, spoofing

## Security Practices

Nylo implements the following security measures:

### Write Authorization (Write Grants)
- Browsers never assert tenant identity. The SDK obtains a short-lived, server-signed **write grant** (`POST /api/tracking/grant`); the server resolves the tenant from its own domain→tenant configuration
- Every ingestion, registration, and token-verification request carries the grant (`X-Nylo-Grant`); grants are domain- and scope-bound (`ingest`, `register`) and expire after 10 minutes
- Caller-supplied customer IDs are never trusted — a conflicting `customerId` is rejected, not reassigned
- Server-to-server token generation requires a separately configured API key (`NYLO_API_KEY`); the signing secret is never accepted as an API key

### Input Sanitization
- All string inputs are HTML-entity encoded to prevent XSS
- Inputs are length-limited to 1,000 characters
- Domain names, event types, session IDs, WaiTags, and timestamps are strictly validated — invalid values are rejected, not silently normalized
- Registrable domains are derived with public-suffix-list parsing (no naive TLD splitting)

### Identity Security
- WaiTag identifiers are generated using the Web Crypto API (cryptographically secure random bytes); if secure randomness is unavailable the SDK fails closed instead of degrading to `Math.random`
- No personal information is used in identifier generation
- Identifiers cannot on their own be reverse-engineered to recover personal data
- Identity generation, restoration, matching, and linking never use browser or device attributes
- Stored identity is reversibly **encoded** (not encrypted) with an HMAC-SHA256 integrity check as local tamper evidence — the browser-side HMAC is not authentication, and the server never trusts it

### Cross-Domain Token Security
- Tokens are HMAC-SHA256 signed, versioned, single-use (`jti` + replay store), and bound to tenant + destination domain
- Tokens expire after 5 minutes
- Verification is authorized (write grant for the destination) **before** the token is consumed, so unauthenticated callers cannot burn tokens
- Replay consumption is atomic; production requires a durable, shared replay store and refuses to start without one
- Domain ownership is verified via DNS TXT records before cross-domain features are enabled

### Data Handling
- No IP addresses are stored
- No fingerprint-capable telemetry is collected: user agent, language, timezone, screen/viewport dimensions, click coordinates, and similar fields are absent from SDK payloads and stripped server-side as defense in depth
- URLs are reduced to origin + path before transmission and storage; query strings and fragments are discarded unless individually allowlisted
- No third-party cookies are used; a **first-party cookie (`nylo_wai`)** is set for local identity persistence once consent is granted
- Identifiers (WaiTags) are **pseudonymous, not anonymous** — they are personal data under GDPR-style regimes, and `Nylo.identify()` can link them to an application-level user ID
- Fail-closed consent gating: no tracking, storage, or cross-domain sync occurs before `Nylo.setConsent({ analytics: true })`
- Consent withdrawal aborts in-flight requests, cancels retry timers, invalidates cached grants, and purges queues and storage
- Three-layer storage (first-party cookie, localStorage, sessionStorage) with graceful degradation

### Network Security
- CORS headers are configured per-origin (not wildcard in production) and expose only the headers browsers actually need (`X-Nylo-Grant`, batching metadata) — identity and API-key headers are not part of the browser surface
- HTTP→HTTPS redirects use a configured canonical host and are disabled otherwise; redirect targets are never built from the client-controlled `Host` header
- Batch payloads deduplicate common fields to minimize payload size

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |
