# WTX-1: Cross-Domain Context Preservation Protocol

**Version:** 1.4.0-draft
**Status:** Draft
**Authors:** Ravi Teja Surampudi, Nylo Contributors
**Created:** 2026-02-20
**Updated:** 2026-08-26
**License:** This specification is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

## Abstract

WTX-1 (WaiTag Transfer Protocol, version 1) defines a method for preserving pseudonymous user context across unrelated web domains without third-party cookies, browser fingerprinting, login requirements, or collection of direct identifiers. The protocol uses cryptographically generated pseudonymous identifiers (WaiTags) — pseudonymous, not anonymous: under regulations such as the GDPR, persistent pseudonymous identifiers are generally personal data and consent obligations continue to apply, URL hash fragment transport, server-side verification, and DNS-based domain authorization to enable privacy-respecting cross-domain analytics.

---

## 1. Problem Statement

### 1.1 The Third-Party Cookie Sunset

Third-party cookies have been the primary mechanism for cross-domain user identification since the 1990s. With Safari ITP (2017), Firefox ETP (2019), and Chrome's Privacy Sandbox (2024+), this mechanism is being eliminated across all major browsers.

### 1.2 What Breaks

When a user navigates from `hospital-a.com` to `pharmacy-b.com`, or from `bank.com` to `investment-portal.com`, analytics systems lose the ability to understand that the same visitor made both visits. This creates blind spots in:

- Patient journey analytics across healthcare providers
- Financial customer experience across banking portals
- Government service usage across agency domains
- Multi-brand retail analytics

### 1.3 Existing Solutions and Their Limitations

| Solution | Limitation |
|----------|-----------|
| Third-party cookies | Being eliminated by all major browsers |
| Browser fingerprinting | Ethically problematic, increasingly blocked, legally risky |
| Login-based identity | Requires authentication; excludes anonymous visitors |
| First-party data sharing | Requires business partnerships and PII exchange |
| Privacy Sandbox Topics API | Coarse-grained, advertising-focused, Chrome-only |
| Adobe ECID | Same eTLD+1 only, classified as personal data under GDPR |

### 1.4 Design Goals

WTX-1 is designed to:

1. Preserve visitor context across unrelated domains (different eTLD+1)
2. Never collect, transmit, or derive direct identifiers (name, email, IP address, device fingerprints); identifiers remain pseudonymous unless the implementer links them via an application-level `identify()` call
3. Work without third-party cookies, fingerprinting, or login (first-party cookies are used only for local identity persistence, not for cross-domain token transport)
4. Resist tracking by unauthorized third parties
5. Degrade gracefully when consent is denied
6. Operate within GDPR, CCPA, and ePrivacy frameworks

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **WaiTag** | A pseudonymous identifier generated per-visitor by hashing (SHA-256) a 128-bit cryptographically random value with a timestamp and a domain-specific salt. Format: `wai_<digest_hex[0:19]>_<digest_hex[19:27]>`. Contains no direct identifiers and no readable timestamp; pseudonymous, not anonymous. |
| **Origin Domain** | The domain where the user's session begins and the WaiTag is generated. |
| **Destination Domain** | The domain the user navigates to, which receives and verifies the WaiTag. |
| **Cross-Domain Token** | A time-limited, server-signed **and encrypted** token encoding the WaiTag for transfer between domains. Contents are confidential in transit; only routing metadata is cleartext. |
| **DNS Authorization** | Domain ownership verification via DNS TXT records that authorizes a domain to participate in WTX-1 identity sharing. |
| **Verification Server** | The server-side component that issues, signs, and verifies cross-domain tokens. |
| **Anonymous Mode** | A degraded operating mode where no WaiTag is generated and no identity is preserved. |
| **Early-Cleanup Script** | An inline `<head>` script that strips tokens from the URL before any other scripts execute, minimizing the token visibility window. |

---

## 3. Protocol Overview

### 3.1 High-Level Flow

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Domain A   │         │  Verification │         │   Domain B   │
│  (Origin)    │         │    Server     │         │ (Destination)│
└──────┬───────┘         └──────┬───────┘         └──────┬───────┘
       │                        │                        │
  1. User visits Domain A       │                        │
  2. SDK generates WaiTag       │                        │
  3. SDK registers WaiTag ──────►                        │
       │                   4. Server stores              │
       │                      WaiTag + domain            │
       │                        │                        │
  5. User clicks link           │                        │
     to Domain B                │                        │
       │                        │                        │
  6. SDK requests cross-        │                        │
     domain token ──────────────►                        │
       │                   7. Server verifies            │
       │                      DNS authorization          │
       │                      for Domain B               │
       │◄──────────────────8. Returns signed token       │
       │                        │                        │
  9. SDK appends token          │                        │
     to URL hash fragment       │                        │
       │                        │                        │
       │─ ─ ─ ─ ─ ─ ─ ─ ─ User navigates ─ ─ ─ ─ ─ ─ ─►
       │                        │                        │
       │                        │  10. Early-cleanup     │
       │                        │      script strips     │
       │                        │      token from URL    │
       │                        │                        │
       │                        │  11. SDK reads token   │
       │                        │      from stashed var  │
       │                        │◄──────────────────────12. SDK sends token
       │                        │                        │   for verification
       │                        │  13. Server verifies   │
       │                        │      signature, expiry │
       │                        │      domain authz,     │
       │                        │      replay protection │
       │                        │──────────────────────►14. Returns identity
       │                        │                        │
       │                        │                 15. SDK restores WaiTag
       │                        │                     and session context
```

### 3.2 Step-by-Step

1. **WaiTag Generation** — When a user first visits a participating domain, the SDK generates a WaiTag using the Web Crypto API: 128 bits from `crypto.getRandomValues` are hashed (SHA-256, via `crypto.subtle.digest`) together with a timestamp and a domain-specific salt, and the digest becomes the identifier: `wai_<digest_hex[0:19]>_<digest_hex[19:27]>`.

2. **Identity Registration** — The SDK registers the WaiTag with the verification server via `POST /api/tracking/register-waitag`. The server stores the WaiTag, session ID, originating domain, and timestamp.

3. **Cross-Domain Navigation** — When the user navigates to another participating domain, a cross-domain token must be appended to the destination URL. The mechanism for link decoration is implementation-defined (e.g., server-side link rewriting, client-side click handlers, or manual URL construction).

4. **Token Generation** — The server generates an encrypted, signed, time-limited token encoding the user's WaiTag and session context (Section 6). The server SHOULD verify that the destination domain is DNS-authorized before issuing the token.

5. **Hash Fragment Transport** — The token is appended to the destination URL as a hash fragment (`#nylo_token=<token>`). Hash fragments are never sent to the server in HTTP requests, providing an additional privacy layer.

6. **Early Cleanup** — On the destination domain, an inline `<head>` script executes before any other scripts, reads the token from the hash fragment, stashes it in a short-lived JavaScript variable (`window.__nylo_early_token`), and immediately cleans the URL using `history.replaceState()`. This ensures the token is never visible to third-party page scripts.

7. **Token Verification** — The SDK reads the token from the stashed variable (or from the hash fragment as fallback if the early-cleanup script is not deployed), and sends it to the verification server via `POST /api/tracking/verify-cross-domain-token`.

8. **Identity Restoration** — If verification succeeds (signature valid, not expired, domain authorized, not previously used), the server returns the original WaiTag and session context. The SDK restores the user's pseudonymous identity on the new domain.

---

## 4. WaiTag Format

### 4.1 Structure

```
wai_<digest_hex[0:19]>_<digest_hex[19:27]>
```

The identifier is derived, not assembled:

```
digest = SHA-256( random_hex(16 CSPRNG bytes) | timestamp | "nylo:" + lowercase(hostname) )
```

| Component | Encoding | Length | Source |
|-----------|----------|--------|--------|
| Prefix | ASCII | 4 chars | Literal `wai_` |
| Digest part 1 | Hex | 19 chars | First 19 hex chars of the SHA-256 digest |
| Separator | ASCII | 1 char | Literal `_` |
| Digest part 2 | Hex | 8 chars | Next 8 hex chars of the SHA-256 digest |

Unpredictability comes from the 128-bit CSPRNG input. Because only the one-way digest becomes the identifier, the WaiTag embeds **no readable timestamp** and **no reversible domain marker** — the timestamp and domain salt diversify the derivation but cannot be recovered from the identifier.

### 4.2 Example

```
wai_3f9c2ab81de04c57a6b_9e12f0d4
```

### 4.3 Properties

- **Not reversible on its own** — No component can be reversed to identify a person absent an external mapping (e.g., one created via `identify()`); the digest inputs (timestamp, domain) are likewise unrecoverable
- **Not derived from direct identifiers** — No personal information is used as input; the WaiTag is nonetheless pseudonymous, not anonymous, because it persists and singles out a browser
- **Domain-salted** — The domain participates in the derivation as a salt, so identical random inputs on different domains yield unrelated tags, without exposing any domain fingerprint in the identifier
- **Collision-resistant** — The identifier exposes 108 bits (27 hex chars) of SHA-256 output derived from 128 bits of cryptographic randomness; collision probability for N identifiers is ≈ N²/2¹⁰⁹
- **Fail-closed** — If the Web Crypto API (CSPRNG or SHA-256) is unavailable, no identifier is generated and tracking does not start; there is no predictable fallback format

### 4.4 What a WaiTag is NOT

- It is not a fingerprint (no hardware/software signals are used)
- It is not a cookie (it does not use the `Set-Cookie` / `Cookie` HTTP mechanism for cross-domain transfer; a first-party cookie is used only as a local storage fallback)
- It does not contain direct identifiers (it cannot by itself identify a natural person; as a persistent pseudonymous identifier it may still be classified as personal data under GDPR-style regimes)
- It is not deterministic (the same user on the same device will get different WaiTags across sessions unless identity is restored)

---

## 5. Token Transport

### 5.1 Primary: URL Hash Fragment

The cross-domain token MUST be transported via URL hash fragment:

```
https://destination.com/page#nylo_token=<signed_token>
```

**Rationale:** Hash fragments (the portion of a URL after `#`) are processed entirely client-side. Per [RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5), they are:

- Never included in HTTP requests to the server
- Never logged in server access logs
- Never sent in the `Referer` header
- Not visible to network intermediaries (proxies, CDNs, WAFs)

This provides a stronger privacy guarantee than URL search parameters (`?key=value`), which are transmitted to the server and commonly logged.

### 5.2 Early-Cleanup Script

To minimize the token visibility window, implementations SHOULD deploy an inline early-cleanup script in the `<head>` of every destination page. This script MUST execute before any other scripts (including third-party analytics, tag managers, and ad scripts).

**Behavior:**

1. The script reads the URL hash fragment
2. If a `nylo_token` or `wai_token` parameter is present, the script extracts the token value
3. The token is stored in a short-lived JavaScript variable (`window.__nylo_early_token`)
4. The token is immediately removed from the URL using `history.replaceState()`
5. Any remaining non-token hash parameters are preserved

**Reference implementation:**

```html
<script>
(function(){
  try{
    var h=window.location.hash;
    if(h&&(h.indexOf("nylo_token=")>-1||h.indexOf("wai_token=")>-1)){
      var p=new URLSearchParams(h.substring(1));
      var t=p.get("nylo_token")||p.get("wai_token");
      if(t){
        window.__nylo_early_token=t;
        p.delete("nylo_token");p.delete("wai_token");
        var n=p.toString();
        history.replaceState(null,"",
          window.location.pathname+window.location.search+(n?"#"+n:""));
      }
    }
  }catch(e){}
})();
</script>
```

**Placement requirements:**

- MUST be placed inline in the `<head>` element
- MUST appear before any `<script src="...">` tags (including analytics, tag managers, and the Nylo SDK itself)
- MUST NOT be loaded asynchronously or deferred
- SHOULD be the first `<script>` element in the document

**Why this matters:**

Without the early-cleanup script, the token remains in the URL hash from the moment the page starts loading until the Nylo SDK initializes and cleans it. During this window, any JavaScript on the page — including third-party scripts — can read `window.location.hash` and see the token. The early-cleanup script removes the token from the URL before other scripts execute.

**Important caveat:** The early-cleanup script stashes the token in `window.__nylo_early_token`, which is a globally accessible JavaScript variable. Any script that runs after the early-cleanup script and knows this variable name can read the token. This is a deliberate trade-off: the token must be stored somewhere between early-cleanup and SDK initialization. However, this is significantly more secure than leaving the token in the URL hash because:

1. `window.location.hash` is a well-known, commonly inspected property. `window.__nylo_early_token` is an implementation-specific variable that third-party scripts have no reason to look for.
2. The SDK deletes this variable immediately upon consuming it, further narrowing the exposure window.
3. The token is one-time-use and short-lived, so even if read by another script, it provides minimal value.

The SDK automatically detects whether the early-cleanup script has already processed the token (by checking `window.__nylo_early_token`) and skips redundant URL cleanup.

### 5.3 Opt-In Fallback: URL Search Parameters

Query parameter token transport is **disabled by default**. If hash fragment transport is not feasible (e.g., the destination URL uses hash-based client-side routing that would conflict with the token), the implementation MAY explicitly opt in to search parameter transport:

```
https://destination.com/page?nylo_token=<signed_token>
```

**Opt-in mechanism (reference implementation):**

```html
<script src="nylo.js" data-allow-query-params="true"></script>
```

**Privacy implications of query parameter transport:**

- Query parameters ARE included in HTTP requests to the destination server
- Query parameters ARE logged in server access logs by default
- Query parameters MAY appear in `Referer` headers sent to third parties
- Query parameters ARE visible to network intermediaries

Implementations using search parameter transport MUST:
- Remove the token from the URL immediately after reading it
- Use `history.replaceState()` to clean the URL without a page reload

Implementations using search parameter transport SHOULD:
- Implement server-side log redaction for `nylo_token` and `wai_token` parameters
- Configure `Referrer-Policy: no-referrer` or `Referrer-Policy: same-origin` headers

### 5.4 Parameter Names

Implementations MUST accept both parameter names:
- `nylo_token` (primary)
- `wai_token` (legacy/alternative)

### 5.5 Token Cleanup

Token cleanup operates in two phases:

**Phase 1: Early Cleanup (recommended)**

The inline `<head>` early-cleanup script (Section 5.2) strips the token from the URL hash fragment before any other scripts execute. The token is stashed in `window.__nylo_early_token` for the SDK to consume.

**Phase 2: SDK Cleanup (fallback)**

If the early-cleanup script is not deployed, the SDK MUST remove the token from the URL when it initializes. This cleanup occurs later in the page lifecycle, so a brief visibility window exists between page load and SDK initialization.

After reading the cross-domain token (from either source), the SDK MUST:
- Remove the token from the URL via `history.replaceState()`
- Delete `window.__nylo_early_token` if it was used
- Preserve any non-token hash parameters or search parameters

Token cleanup prevents:
- Accidental sharing of token-bearing URLs
- Token replay from browser history
- Token exposure in analytics tools that capture full URLs

---

## 6. Token Format and Verification

### 6.1 Token Format (WTX-1 Token Format v2: Sign-then-Encrypt)

Tokens are **encrypted and signed**. The construction is sign-then-encrypt:

1. A canonical inner payload is signed with HMAC-SHA256.
2. The signed payload is encrypted with AES-256-GCM.
3. Encryption and MAC keys are **independently derived per tenant and per destination domain** using HKDF-SHA256 from the server token secret — a token minted for `dest-a.com` cannot be decrypted, verified, or replayed as a token for `dest-b.com`, even by the same tenant.

The base64-encoded outer envelope exposes **only routing metadata**:

| Envelope Field | Description |
|-------|-------------|
| `v` | Token format version (`2`; lower versions MUST be rejected) |
| `tid` | Tenant routing identifier |
| `dst` | Destination routing domain (selects the decryption key) |
| `iv` | AES-GCM initialization vector |
| `ct` | Ciphertext of the signed inner payload |
| `tag` | AES-GCM authentication tag |

The tenant and destination routing metadata (`tid`, `dst`), prefixed with a fixed protocol-version constant, are bound as AEAD associated data — altering them breaks decryption. The envelope `v` field is enforced by a pre-decryption version gate (only v2 is accepted), and all routing metadata MUST additionally be cross-checked against the signed inner payload after decryption.

The encrypted inner payload contains:

| Inner Field | Description |
|-------|-------------|
| `waiTag` | The pseudonymous identifier to transfer |
| `sessionId` | The session identifier from the origin domain |
| `userId` | Optional application-level identifier (may constitute personal data if linkable to an individual; requires lawful basis if used) |
| `sourceDomain` | The domain that issued the token |
| `destinationDomain` | The intended recipient domain |
| `tenantId` | The tenant the token belongs to |
| `iat` / `exp` | Issue and expiry timestamps |
| `jti` | Unique per-token identifier for replay protection |
| `sig` | Server-generated HMAC-SHA256 signature over the canonical payload |

Identity and context fields (`waiTag`, `sessionId`, `userId`, `sourceDomain`) are therefore **confidential in transit**: anyone who observes the token (URL bar, browser history, a third-party script that races the cleanup) sees only ciphertext plus routing metadata, and cannot read the identifier without the server secret.

### 6.2 Verification Requirements

The verification server MUST check, in order:

1. **Version** — Only token format v2 is accepted; legacy signed-cleartext (v1 or unversioned) tokens MUST be rejected with `UNSUPPORTED_VERSION`
2. **Decryption / AEAD integrity** — The envelope must decrypt under the key derived for its routing metadata; any ciphertext, IV, tag, or routing tampering fails authentication
3. **Signature validity** — The inner HMAC-SHA256 signature must verify, and the signed payload must agree with the envelope routing metadata
4. **Expiry** — The token has not expired (configurable window, recommended default: 5 minutes) and is not future-dated
5. **Replay protection** — The token has not been previously verified. Each token MUST only be accepted once. The server MUST maintain a record of consumed token identifiers (`jti`) for at least the token expiry window.
6. **Domain authorization** — The destination domain SHOULD be DNS-authorized to receive identities
7. **Destination/tenant binding** — The token's destination domain and tenant MUST match the authenticated verification context

**Error codes:**

| Code | Meaning |
|------|---------|
| `UNSUPPORTED_VERSION` | Token is not format v2 (includes all legacy cleartext tokens) |
| `MALFORMED_TOKEN` | Token is not a decodable envelope |
| `MISSING_SIGNATURE` | Envelope lacks the AES-GCM authentication tag, or the inner payload lacks a signature |
| `TOKEN_EXPIRED` | Token has passed its expiry timestamp |
| `TOKEN_REPLAYED` | Token has already been verified (replay attempt) |
| `INVALID_SIGNATURE` | Decryption or HMAC signature verification failed (covers ciphertext, IV, tag, routing and payload tampering, and wrong-key attempts) |
| `INVALID_IAT` | Token is future-dated beyond clock skew |
| `DOMAIN_MISMATCH` | Token destination does not match the requesting destination |
| `DOMAIN_NOT_AUTHORIZED` | Destination domain is not DNS-authorized |
| `ORIGIN_MISMATCH` | Token origin does not match the requesting domain's referrer |
| `GRANT_REQUIRED` | No write grant accompanied the verification request (401) |
| `GRANT_DOMAIN_MISMATCH` | The write grant was issued for a different domain than requested |
| `TENANT_MISMATCH` | The token's tenant does not match the authenticated grant tenant |

### 6.3 Verification Endpoint

Verification is **authorized before it consumes**: the caller MUST present a
valid write grant (Section 9.11) for the destination domain in the
`X-Nylo-Grant` header. Without this, any unauthenticated party who observed a
token in transit could "verify" it once — burning it and denying the
legitimate destination page its identity handoff. The tenant used for token
binding comes from the signed grant; a `customerId` field in the body is
legacy-optional and, when present, MUST agree with the grant tenant.

```
POST /api/tracking/verify-cross-domain-token
Content-Type: application/json
X-Nylo-Grant: <signed_write_grant>

{
  "token": "<signed_token>",
  "domain": "destination.com",
  "referrer": "https://origin.com/page"
}
```

**Success Response:**

```json
{
  "success": true,
  "identity": {
    "sessionId": "<session_id>",
    "waiTag": "<wai_tag>",
    "userId": null
  }
}
```

**Failure Response:**

```json
{
  "success": false,
  "error": "TOKEN_EXPIRED"
}
```

---

## 7. DNS Domain Authorization

### 7.1 Purpose

Before a domain can receive cross-domain identities, it must prove ownership via a DNS TXT record. This prevents unauthorized domains from requesting or receiving WaiTags.

### 7.2 TXT Record Format

```
_nylo-verify.example.com  TXT  "nylo-domain-verify=<verification_code>"
```

### 7.3 Verification Flow

1. Domain owner adds the TXT record to their DNS configuration
2. Domain owner calls the verification endpoint: `POST /api/domains/verify`, authenticated with their API key (`X-API-Key` header). Caller-supplied customer IDs MUST NOT be accepted as authentication for verification management endpoints.
3. The server performs a DNS lookup for `_nylo-verify.<domain>`
4. If the TXT record matches the expected verification code, the domain is authorized
5. Authorization is cached server-side and periodically re-verified

### 7.4 Subdomain Inheritance

If `example.com` is DNS-verified, subdomains (`blog.example.com`, `shop.example.com`) inherit authorization automatically. Implementations MAY provide configuration to exclude specific subdomains.

---

## 8. Client-Side Storage

### 8.1 Three-Layer Strategy

The SDK stores identity data locally using three mechanisms for resilience. These storage mechanisms are used exclusively for **local identity persistence** on a single domain — they are never used for cross-domain token transport (which uses URL hash fragments as defined in Section 5).

| Layer | Mechanism | Persistence | ITP Impact |
|-------|-----------|-------------|------------|
| 1 | First-party cookie (`nylo_wai`) | 24 hours (JS-set under ITP) | Capped at 7 days, 24h if JS-set |
| 2 | `localStorage` | Until cleared | Partitioned by eTLD+1 under ITP |
| 3 | `sessionStorage` | Tab lifetime | Unaffected by ITP |

### 8.2 Storage Read Priority

When restoring identity, the SDK reads in order: cookie → localStorage → sessionStorage. The first valid result is used.

### 8.3 Data Stored

```json
{
  "sessionId": "<secure_id>",
  "waiTag": "<wai_tag>",
  "userId": null,
  "domain": "example.com",
  "createdAt": "2026-02-20T12:00:00.000Z",
  "lastUsedAt": "2026-02-20T12:00:00.000Z",
  "integrity": "<hash>"
}
```

The `integrity` field is an HMAC-SHA256 computed over `sessionId + ':' + domain + ':' + waiTag + ':' + customerId` using the Web Crypto API (`crypto.subtle.sign`). The HMAC key is derived from the `customerId`. This provides cryptographic tamper detection — any modification to the stored identity data (via browser developer tools, cookie editors, or XSS) will cause the integrity check to fail on the next read.

**Integrity verification on read:**

When the SDK reads stored identity data from any storage layer, it verifies the HMAC integrity hash before using the data:

1. If the HMAC is valid (64-character hex string matching the expected signature), the data is accepted.
2. If the HMAC is invalid or missing, the data is rejected and the storage layer is cleared.
3. If all three storage layers contain invalid data, the SDK generates a fresh identity.
4. Legacy integrity hashes (pre-HMAC, using djb2) are automatically detected and migrated to HMAC on first read.

**Limitations:** The HMAC key (`customerId`) is present in client-side JavaScript. An attacker with full script execution (XSS) can extract the key and forge valid integrity hashes. The integrity check is designed to prevent **casual tampering** (dev tools, cookie editors, browser extensions) and **cross-site cookie injection**, not to withstand a full XSS compromise. See Section 9.5 for the honest XSS threat model.

### 8.4 Obfuscation at Rest

Data stored in `localStorage` is encoded with a customer-specific salt and timestamp to prevent casual inspection. This is obfuscation, not cryptographic security — it prevents trivial reading of identity data via browser developer tools but does not provide protection against a determined attacker with page-level JavaScript access.

### 8.5 Retention: Time-Limited Identifiers with Automatic Expiry

Stored identifiers are time-limited. The reference implementation enforces, on **every storage read**:

| Rule | Default | Behavior |
|------|---------|----------|
| Absolute lifetime | 180 days from `createdAt` | Identifier expires regardless of activity |
| Unused expiry | 30 days from `lastUsedAt` | Identifier expires when not used (sliding window) |

- **Use** means restoration for active tracking; `lastUsedAt` is updated ("touched") on each such read. Passive inspection via the context-view API does not extend retention.
- Expired records are **deleted from all storage layers on read and never resurrected** — a fresh, unlinked identifier is minted instead.
- Records without parseable timestamps (legacy formats) fail closed into expiry.
- Both windows are integrator-configurable (`data-identity-max-age-days`, `data-identity-unused-expiry-days`), clamped to sane bounds; invalid values keep the defaults.
- Enforcement happens at read time, so shortening a policy applies retroactively to already-stored records.

The first-party cookie layer additionally expires via its own `max-age` (24 hours under ITP-style JavaScript cookie capping); the retention policy above governs the longer-lived `localStorage` layer.

---

## 9. Security Threat Model and Mitigations

### 9.1 Threat Summary

| Threat | Severity | Mitigation | Residual Risk |
|--------|----------|------------|---------------|
| Token interception by destination server | High | Hash fragment transport — tokens are never sent in HTTP requests | None (when using hash transport) |
| Token interception by third-party page scripts | High | Early-cleanup `<head>` script removes token from URL hash before other scripts execute; token stashed in implementation-specific global variable | Low — token accessible via `window.__nylo_early_token` if script knows the variable name; mitigated by one-time-use and short expiry |
| Token interception by browser extensions | Medium | Short expiration + one-time-use verification | Low (see Section 9.3) |
| Token replay | High | One-time-use verification with server-side nonce tracking | None |
| Token forgery (unsigned tokens) | Critical | Mandatory HMAC-SHA256 signature on all tokens; unsigned tokens rejected with `MISSING_SIGNATURE` error; server refuses to verify tokens if signing secret is not configured | None |
| Token tampering | High | AES-256-GCM authenticated encryption + inner HMAC-SHA256 signature verification | None |
| Token contents read by URL observers (history, copied links, racing scripts) | Medium | AES-256-GCM encryption — identity and context fields are ciphertext; only routing metadata (tenant ID, destination domain) is cleartext | Low — routing metadata itself is visible |
| Token redirected to another destination | High | Per-destination HKDF key separation + AEAD-bound routing metadata + signed inner destination binding | None |
| Token expiration bypass | High | Server-side timestamp validation (default 5 minutes) | None |
| Stored identity tampering | Medium | HMAC-SHA256 integrity validation on every storage read; tampered data is rejected and cleared | Low — attacker with XSS can extract HMAC key from client-side code |
| Token exposure via URL sharing | Medium | Early-cleanup removes token before page renders + short expiration + one-time-use | Negligible |
| Unauthorized domain participation | High | DNS TXT record verification | None |
| Referrer header leakage | Low | Hash fragments are not included in `Referer` headers per browser spec; `Referrer-Policy: no-referrer` recommended | Negligible |
| Query parameter exposure to servers | High | Query parameter transport is disabled by default; opt-in only | None (when using default hash transport) |
| DNS spoofing of authorization records | Medium | DNSSEC recommended; verification over secure channels | Low |
| Server-side HMAC key compromise | High | Key rotation policies; secure key storage | Organizational |
| Brute-force token verification | Medium | Rate limiting on verification endpoints | None (when rate limiting is deployed) |

### 9.2 Early-Cleanup Script: Defense in Depth

The early-cleanup script (Section 5.2) is the primary defense against token exposure to unauthorized JavaScript. Here is the detailed execution timeline showing what each actor can see at each stage of page load:

```
Timeline: Page Load with Cross-Domain Token
═══════════════════════════════════════════════

   t0: Browser receives HTML response
       URL bar shows: destination.com/page#nylo_token=eyJ3...
       ┌─────────────────────────────────────────────────┐
       │ No scripts have executed yet.                   │
       │ The token exists only in the URL bar.           │
       │ Browser extensions with "run_at": "document_    │
       │ start" MAY have access (see Section 9.3).       │
       └─────────────────────────────────────────────────┘

   t1: Early-cleanup <head> script executes (synchronous)
       ┌─────────────────────────────────────────────────┐
       │ 1. Reads window.location.hash                   │
       │ 2. Extracts token → window.__nylo_early_token   │
       │ 3. Calls history.replaceState() to clean URL    │
       │ URL bar now shows: destination.com/page          │
       │ Duration: < 1ms                                 │
       └─────────────────────────────────────────────────┘

   t2: Other <head> scripts execute (tag managers, analytics, etc.)
       ┌─────────────────────────────────────────────────┐
       │ window.location.hash is EMPTY                   │
       │ These scripts cannot see the token in the URL.  │
       │ window.__nylo_early_token exists and is          │
       │ technically accessible to any script that knows  │
       │ the variable name, but it is an implementation-  │
       │ specific variable that third-party scripts have  │
       │ no reason to look for. The token is also one-    │
       │ time-use, so reading it provides limited value.  │
       └─────────────────────────────────────────────────┘

   t3: DOM begins rendering
       ┌─────────────────────────────────────────────────┐
       │ URL bar is clean — user never sees the token.   │
       │ If user copies URL, no token is included.       │
       └─────────────────────────────────────────────────┘

   t4: Nylo SDK initializes (DOMContentLoaded or script load)
       ┌─────────────────────────────────────────────────┐
       │ 1. Reads window.__nylo_early_token              │
       │ 2. Deletes window.__nylo_early_token            │
       │ 3. Sends token to verification server           │
       │ 4. Server checks: signature ✓ expiry ✓          │
       │    replay ✓ domain ✓                            │
       │ 5. Identity restored                            │
       └─────────────────────────────────────────────────┘

   t5: Token fully consumed
       ┌─────────────────────────────────────────────────┐
       │ Token no longer exists anywhere on the page:    │
       │ - Not in URL bar                                │
       │ - Not in window.__nylo_early_token              │
       │ - Not in browser history (replaceState)         │
       │ - Invalidated server-side (one-time-use)        │
       └─────────────────────────────────────────────────┘
```

### 9.3 Browser Extension Limitation: Detailed Analysis

Browser extensions represent the one token interception vector that **cannot be fully mitigated** at the application layer. This section provides a thorough analysis of the threat, its practical severity, and the layered defenses that limit its impact.

#### 9.3.1 Why Extensions Can See the Token

Browser extensions with content script access can declare `"run_at": "document_start"` in their manifest. This tells the browser to inject the extension's content script before the page's own `<head>` scripts execute. At this point, the extension has access to `window.location.hash`, which still contains the token.

The browser's execution order is:

```
1. Browser parses HTML <head>
2. Browser injects content scripts with "run_at": "document_start"  ← Extension sees hash
3. Browser executes inline <head> scripts                           ← Early-cleanup runs
4. Browser continues parsing and executing remaining scripts
```

Step 2 happens before step 3. This is by design — it is how the browser extension model works. No application-layer JavaScript can execute before a `document_start` content script.

#### 9.3.2 Why This Is a Limited Threat

Despite extensions having theoretical access, the practical risk is low for the following reasons:

**1. Extensions must be explicitly installed by the user**

Unlike third-party page scripts (which are loaded by the site operator and run on every visit), browser extensions are software that the user has personally chosen to install. A malicious extension capable of intercepting WTX-1 tokens would need to:
- Be published on the Chrome Web Store, Firefox Add-ons, or equivalent marketplace
- Pass the marketplace's review process
- Be discovered and installed by the target user
- Specifically target WTX-1 tokens (a niche protocol) rather than more valuable targets

An extension with `document_start` content script access and the ability to read `window.location.hash` on all pages already has far more powerful capabilities than intercepting a WTX-1 token — it could read passwords, form data, authentication tokens, and any other page content.

**2. Tokens are one-time-use**

Even if an extension captures the token, it must race to verify it before the Nylo SDK does. The verification server accepts each token exactly once. In practice, the SDK sends the verification request within milliseconds of initialization, leaving an extremely narrow window for an extension to submit the token first.

If the extension does manage to verify the token first, the SDK's verification will fail, and no identity will be restored — the user simply gets a fresh session on the destination domain. No data is compromised.

**3. Tokens expire in 5 minutes**

A captured token that is not immediately verified becomes useless within 5 minutes. The extension cannot store it for later use or transmit it to a remote server for delayed exploitation.

**4. Token contents are encrypted, and the underlying data is pseudonymous**

A captured token is ciphertext: the extension can read only routing metadata (tenant ID, destination domain). To learn anything else it must win the verification race against the SDK. Even then, it obtains only:
- A WaiTag (pseudonymous identifier containing no direct identifiers)
- A session ID (random string)
- An optional application-level user ID
- The origin domain name

None of this data identifies a real person. The extension gains the ability to correlate visits across two domains — which is the same capability that the authorized site operator already has. No new privacy harm is introduced.

**5. The same user installed the extension**

The user whose token is intercepted is the same user who installed the extension. This is fundamentally different from third-party tracking, where a remote party tracks users without their knowledge. If a user installs a malicious extension, they have already granted that extension broad access to their browsing activity — intercepting a WTX-1 token provides negligible additional data.

#### 9.3.3 Comparison to Other Protocols

This limitation is not unique to WTX-1. Every web-based protocol that uses client-side state is subject to extension interception:

| Protocol | Extension Access |
|----------|-----------------|
| OAuth 2.0 redirect tokens | Extensions can read `?code=` from redirect URLs |
| SAML assertions | Extensions can read POST body data |
| JWT in localStorage | Extensions can read `localStorage` |
| Session cookies | Extensions can read `document.cookie` |
| WTX-1 tokens | Extensions can read `window.location.hash` |

WTX-1's one-time-use + short expiry model provides **stronger** protection against extension interception than most of these alternatives, which use long-lived tokens or persistent storage.

#### 9.3.4 What Would Fully Solve This

The only way to fully eliminate extension access to the token would be a **browser-native API** that mediates the token transport:

```
// Hypothetical future browser API
navigator.crossDomainContext.receive()
  .then(token => { /* extension cannot intercept */ });
```

Such an API would allow the browser itself to handle token transport without exposing the token to any JavaScript (page or extension). If WTX-1 gains adoption, this explainer can serve as the basis for proposing such a browser API to the W3C.

Until then, the combination of early-cleanup, one-time-use, short expiration, and the pseudonymous nature of the token data makes extension interception a low-severity residual risk.

### 9.4 HTTPS Requirement

All token transport and verification MUST occur over HTTPS. The protocol MUST NOT be used over unencrypted HTTP. Without TLS, tokens are visible to network intermediaries regardless of hash fragment or query parameter transport.

### 9.5 Cross-Site Scripting (XSS) — Honest Threat Model

If the destination page is vulnerable to XSS, an attacker's injected script could read the hash fragment or `window.__nylo_early_token` before the SDK consumes it. Implementations MUST:
- Sanitize all token data before use
- Never insert token values into the DOM without proper escaping
- Follow OWASP XSS prevention guidelines

The early-cleanup script mitigates this partially by reducing the window, but an XSS vulnerability on the destination page undermines all client-side security guarantees, not just WTX-1.

**What the SDK protects against:**

| Attack Vector | Protected? | Mechanism |
|---------------|------------|-----------|
| Casual cookie/storage tampering (dev tools, cookie editors) | Yes | HMAC-SHA256 integrity validation on read |
| Cross-site cookie injection | Yes | HMAC integrity check rejects cookies not signed with the correct `customerId` |
| Token forgery (crafting unsigned cross-domain tokens) | Yes | Server rejects all unsigned tokens; HMAC-SHA256 signature is mandatory |
| Token replay | Yes | Server-side one-time-use nonce tracking |
| Token interception via network | Yes | Hash fragment transport (never in HTTP requests) + HTTPS requirement |
| Token interception via third-party page scripts | Mostly | Early-cleanup narrows window to <1ms; token is one-time-use |

**What the SDK does NOT protect against (with XSS):**

| Attack Vector | Why Not | Mitigation |
|---------------|---------|------------|
| XSS attacker reading stored identity (cookie, localStorage, sessionStorage) | All three storage layers are accessible to page JavaScript; `HttpOnly` on the cookie would only protect one of three copies | Prevent XSS; deploy CSP headers (see Section 9.9) |
| XSS attacker forging integrity hashes | The HMAC key (`customerId`) is present in client-side code | Prevent XSS; `customerId` is not a secret |
| XSS attacker reading `window.__nylo_early_token` before SDK consumes it | Global variable is accessible to any page script | Prevent XSS; token is one-time-use and short-lived |

**Design rationale for not using HttpOnly cookies:**

The SDK's identity cookie (`nylo_wai`) is intentionally set via client-side JavaScript (`document.cookie`) rather than via a server `Set-Cookie` header with `HttpOnly`. This decision is based on three factors:

1. **The SDK is designed to work without a server dependency for local identity persistence.** Requiring a server roundtrip to set or read the identity cookie would break the zero-dependency, "drop a script tag" deployment model.
2. **HttpOnly would protect only one of three storage copies.** The same identity data is stored in `localStorage` and `sessionStorage`, both fully accessible to JavaScript. Protecting the cookie alone provides negligible additional security against XSS.
3. **The real defense is preventing XSS.** No amount of cookie flag hardening can protect a page with an active XSS vulnerability. The recommended approach is Content Security Policy (see Section 9.9) and standard XSS prevention practices.

### 9.6 DNS Spoofing

DNS TXT record verification is subject to DNS spoofing attacks. An attacker who can spoof DNS responses could cause the verification server to authorize an unauthorized domain. Implementations SHOULD:
- Use DNSSEC where available
- Validate DNS responses over secure channels (DNS-over-HTTPS or DNS-over-TLS)
- Cache DNS authorization results and re-verify periodically

### 9.7 Server-Side Key Management

The server-side token secret (`NYLO_TOKEN_SECRET`) — from which per-tenant, per-destination encryption and MAC keys are independently derived via HKDF-SHA256 — MUST be stored securely on participating servers. Implementations SHOULD:
- Rotate HMAC keys periodically (recommended: every 90 days)
- Support multiple active keys during rotation periods
- Use hardware security modules (HSMs) or key management services where available
- Never log or expose HMAC keys in error messages or debug output

### 9.8 Rate Limiting

Verification endpoints MUST implement rate limiting to prevent:
- Token brute-force attacks (guessing valid tokens)
- Denial-of-service attacks against the verification server
- Nonce table exhaustion from rapid replay attempts

Recommended limits: 100 verification requests per IP per minute, with exponential backoff on failures.

### 9.9 Content Security Policy (CSP) Recommendations

Sites deploying WTX-1 SHOULD implement Content Security Policy headers to mitigate XSS attacks. The following CSP directives are recommended:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  connect-src 'self' https://your-verification-server.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
```

**Notes:**

- `script-src 'unsafe-inline'` is required for the early-cleanup `<head>` script (Section 5.2). If nonce-based CSP is used, the early-cleanup script MUST include the nonce: `<script nonce="<random>">`.
- `connect-src` MUST include the verification server domain to allow the SDK's `fetch()` calls.
- `frame-ancestors 'none'` prevents the page from being embedded in iframes, reducing clickjacking risk.
- Sites using strict CSP with hash-based script allowlisting can compute the SHA-256 hash of the early-cleanup script and add it to `script-src`.

### 9.10 Mandatory Token Encryption, Signing, and Issuance Controls

All cross-domain tokens MUST use the sign-then-encrypt construction of Section 6.1: an HMAC-SHA256-signed canonical payload sealed with AES-256-GCM. Unsigned tokens MUST be rejected with `MISSING_SIGNATURE`; legacy signed-cleartext (pre-v2) tokens MUST be rejected with `UNSUPPORTED_VERSION`.

**Encryption requirements:**

1. Encryption and MAC keys MUST be derived independently per `(tenantId, destinationDomain)` pair via HKDF-SHA256 from `NYLO_TOKEN_SECRET`; the raw secret MUST NOT be used directly as either key.
2. The cleartext envelope MUST carry only routing metadata (version, tenant ID, destination domain, IV, ciphertext, tag). Identity and context fields MUST appear only inside the ciphertext.
3. Tenant and destination routing metadata MUST be bound as AEAD associated data (the AAD input includes a fixed protocol-version constant); the envelope version field MUST be enforced by a pre-decryption gate, and all routing metadata MUST be cross-checked against the signed inner payload after decryption.
4. Each token MUST use a fresh random IV; AES-GCM key+IV pairs MUST never repeat.

**Server configuration requirements:**

1. The `NYLO_TOKEN_SECRET` environment variable MUST be set at startup. If not configured, the server MUST NOT register cross-domain token endpoints (verify, generate) and MUST log a clear startup error.
2. The server MUST NOT fall back to accepting unsigned tokens under any circumstances.
3. For demo/development environments, the server MAY generate an ephemeral random secret per session, but MUST log a prominent warning that tokens will not survive server restarts.

**Token issuance access control:**

1. The token generation endpoint (`/api/tracking/generate-cross-domain-token`) MUST require authentication via an API key (`X-API-Key` header) validated against `NYLO_API_KEY`. Unauthenticated requests MUST be rejected with `401 Unauthorized`.
2. The `destinationDomain` field MUST be required when generating tokens — tokens without a destination domain binding MUST be rejected.
3. When domain verification is available, the server SHOULD verify that the authenticated customer owns the destination domain before issuing tokens.

**Domain binding enforcement:**

1. Tokens MUST include a `domain` field specifying the intended destination.
2. During verification, if both the request `domain` and the token `domain` are present, the server MUST reject tokens where they do not match (403 `DOMAIN_MISMATCH`).
3. This prevents token reuse across unrelated domains even if the token signature is valid.

**Verification access control:**

1. The verification endpoint MUST require a valid write grant (Section 9.11) for the destination domain before performing any token processing.
2. Unauthorized verification attempts MUST NOT consume the token — replay-protection state may only change after every authorization check has passed. This prevents token-burning denial of service by unauthenticated observers.
3. The tenant used for `TENANT_MISMATCH` checks MUST come from the authenticated grant, never from caller-supplied fields.

**Replay-protection storage requirements:**

1. Replay consumption MUST be atomic (`consumeToken`-style check-and-set): of N concurrent verifications of the same token, exactly one may succeed.
2. In production, the replay store MUST be durable and shared across all server processes (e.g., a database or distributed cache). In-memory stores are development-only; a production deployment without a durable store MUST refuse to start.

### 9.11 Write Grants — Browser Write Authorization

Browsers never assert tenant identity. All browser write paths (event
ingestion, WaiTag registration, token verification) MUST be authorized by a
short-lived, server-signed **write grant**:

1. The page requests a grant from `POST /api/tracking/grant`, sending only the page's domain. The server resolves the tenant from **server-side configuration** (domain→tenant mapping); requests for unmapped domains MUST be rejected.
2. When a browser `Origin` header is present, it MUST match the requested domain. In production, the `Origin` header MUST be required.
3. Grants are HMAC-SHA256-signed structures binding `{ tenantId, domain, scopes, iat, exp, jti }`. Scopes are limited to `ingest` and `register`. The RECOMMENDED lifetime is 10 minutes; the maximum is 24 hours.
4. Every write request carries the grant in the `X-Nylo-Grant` header. Servers MUST verify signature, expiry, scope, and domain binding, and MUST derive the tenant exclusively from the grant.
5. Caller-supplied tenant assertions (`customerId` fields, identity headers) MUST NOT be trusted. When present for legacy compatibility, they MUST be checked for agreement with the grant and rejected on conflict (403 `TENANT_MISMATCH`) — never silently reassigned.
6. Grants authorize **writes only**. They MUST NOT be accepted as authentication for reading, linking, or exporting identity data.

---

## 10. Privacy Considerations

### 10.1 Pseudonymous Identifiers and GDPR

Under GDPR, pseudonymous identifiers are considered personal data when they can be attributed to a natural person using additional information (Article 4(5)). WaiTags are pseudonymous personal data — they contain no direct identifiers, but an organization can maintain a mapping linking WaiTags to real identities; the reference implementation's `identify()` API creates such a linkage when called, and the linked data must then be treated as fully personal data with an appropriate lawful basis.

WTX-1 does not define or require such a mapping. Implementors who create such mappings take on the full obligations of a GDPR data controller, including lawful basis, data subject rights, and data protection impact assessments.

Implementors SHOULD NOT create WaiTag-to-identity mappings unless they have a clear lawful basis and have completed a DPIA.

### 10.2 Data Minimization

Cross-domain tokens contain only the minimum fields necessary for identity verification. No behavioral data, page content, interaction history, device information, or browsing history is included in the token.

### 10.3 User Control and Consent

Implementations MUST provide:
- **Consent API** — Ability to grant or revoke consent for cross-domain identity
- **Anonymous mode** — When consent is denied, no WaiTag is generated, no tokens are created, and only aggregate anonymous analytics are collected
- **Data clearing** — Ability to clear WaiTag and all associated data
- **Transparency** — Ability to view what data has been collected
- **Deletion** — Ability to request deletion of all data associated with a WaiTag (GDPR Article 17)

The reference implementation exposes these as public SDK APIs: `getStoredContext()` (passive view of everything stored in the browser, including expiry projections — does not extend retention), `resetContext()` (delete stored identity and mint a fresh unlinked one), and `revokeContext()` (withdraw consent, abort pending work, and purge all storage). It also dispatches a `nyloContextPreserved` DOM event whenever context is restored from storage or across domains, enabling a user-visible continuity indicator.

### 10.4 Consent-Gated Degradation

When consent is denied:
- No WaiTag is generated or stored
- No cross-domain tokens are created or accepted
- Events are tracked with a random per-session identifier only
- No data persists beyond the current page session
- The SDK operates in a fully anonymous mode with no cross-domain capability

### 10.5 Identifier Expiry and Rotation

Stored identifiers MUST NOT persist indefinitely. The reference implementation enforces automatic expiry on every read — 180 days absolute lifetime and 30 days unused expiry by default, both configurable (Section 8.5); expired identifiers are deleted and replaced with fresh, unlinked ones. This bounds the maximum duration over which a single pseudonymous identifier can be used to correlate cross-domain visits. Implementations MAY additionally rotate identifiers more aggressively (e.g., every 90 days regardless of use).

---

## 11. Consent Model

### 11.1 API

```javascript
// Grant consent — enables cross-domain identity
nylo.setConsent({ analytics: true });

// Revoke consent — degrades to anonymous mode
nylo.setConsent({ analytics: false });

// Check current consent state
nylo.getConsent();
// Returns: { analytics: true } or { analytics: false }
```

### 11.2 Default State

The default consent state is implementation-defined. Implementations operating in jurisdictions that require prior consent (e.g., EU under GDPR/ePrivacy) SHOULD default to `analytics: false` and require explicit opt-in. Implementations in jurisdictions that allow opt-out models MAY default to `analytics: true`.

### 11.3 Consent Revocation

When consent is revoked:
1. The WaiTag is deleted from all storage layers
2. The user ID is cleared
3. Cross-domain sync state is reset
4. The SDK switches to anonymous mode
5. No further cross-domain tokens are generated or accepted

---

## 12. Compatibility

### 12.1 Browser Support

WTX-1 uses standard web APIs available in all modern browsers:
- `crypto.getRandomValues()` (Web Cryptography API)
- `localStorage` / `sessionStorage` (Web Storage API)
- `history.replaceState()` (History API)
- `URLSearchParams` (URL API)
- `fetch()` (Fetch API)

No browser-specific APIs or vendor prefixes are required.

### 12.2 Tracking Prevention Interaction

WTX-1 does not use third-party cookies, third-party storage, redirect-based tracking, or bounce tracking patterns. It should not trigger Safari ITP, Firefox ETP, or Chrome's bounce tracking mitigations. However, this has not been formally verified with all browser vendors, and future tracking prevention heuristics could potentially flag hash-fragment-based token transport.

### 12.3 Hash-Based Routing Compatibility

Single-page applications using hash-based routing (e.g., `#/page/123`) may conflict with hash fragment token transport. In this case, implementations may need to opt in to query parameter transport (Section 5.3) or implement a custom token extraction strategy that operates before the router initializes.

### 12.4 Progressive Adoption

Sites can adopt WTX-1 incrementally:
1. **Single-domain tracking** works without any DNS configuration
2. **Cross-domain identity** activates only when DNS authorization records are configured
3. **Early-cleanup script** can be deployed independently before full SDK integration

---

## 13. References

### Normative References

- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) — HMAC: Keyed-Hashing for Message Authentication
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) — Key words for use in RFCs to Indicate Requirement Levels
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) — Uniform Resource Identifier (URI): Generic Syntax
- [W3C Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)

### Informative References

- [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) — General Data Protection Regulation
- [CCPA](https://oag.ca.gov/privacy/ccpa) — California Consumer Privacy Act
- [ePrivacy Directive](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32002L0058) — Directive 2002/58/EC
- [Intelligent Tracking Prevention](https://webkit.org/blog/7675/intelligent-tracking-prevention/) — Apple WebKit
- [Enhanced Tracking Protection](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop) — Mozilla Firefox
- [Privacy Sandbox](https://privacysandbox.com/) — Google Chrome
- [IETF Internet-Draft: draft-surampudi-wtx1-00](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)

### Reference Implementation

- [Nylo SDK](https://github.com/tejasgit/nylo) — dual-licensed (MIT core; cross-domain identity features under a commercial license — see the repository's LICENSING.md; licensing boundary provisional pending attorney review)
- [WTX-1 Protocol Repository](https://github.com/tejasgit/wtx-1)

---

## 13. Measurable Security Properties

This section defines quantifiable security claims that can be independently verified through measurement. Each claim includes its expected value, measurement methodology, and the SDK API for programmatic verification.

### 13.1 Logging Surface Reduction

**Claim (structural guarantee):** When using hash fragment transport (default), cross-domain tokens appear in 0 out of 6 standard HTTP logging fields. This is a structural property of HTTP per RFC 3986, not a runtime measurement.

| Logging Field | Query Parameter Transport | Hash Fragment Transport |
|---------------|--------------------------|------------------------|
| Server access log (request URI) | Token visible | Token absent |
| `Referer` header to third parties | Token visible | Token absent |
| Proxy/CDN request logs | Token visible | Token absent |
| WAF (Web Application Firewall) logs | Token visible | Token absent |
| Browser `Referer` to destination server | Token visible | Token absent |
| Network packet inspection (pre-TLS) | Token visible (in URI) | Token absent (not in request) |

**Measurement methodology:**

1. Configure a destination server to log all request headers and the full request URI
2. Navigate to `destination.com/page#nylo_token=test_token`
3. Verify that `test_token` does not appear in any server-side log entry
4. Repeat with `destination.com/page?nylo_token=test_token` and verify it appears in all 6 fields

**SDK verification:**

```javascript
var timings = Nylo.getTimingMetrics();
console.log(timings.transport.loggingSurface);
// Hash transport: "0/6 standard HTTP log fields (structural guarantee per RFC 3986)"
// Query transport: "6/6 standard HTTP log fields"
console.log(timings.transport.httpBytesLeaked);
// Hash transport: 0
// Query transport: "token_transmitted_in_http_request"
```

Note: These values are derived from the transport method used, not from runtime measurement. The 0/6 claim for hash fragment transport is a structural guarantee of HTTP, verifiable through packet capture (see measurement methodology above).

### 13.2 Token Visibility Window

**Claim:** With the early-cleanup `<head>` script deployed, the token is typically visible in `window.location.hash` for less than 1 millisecond (measured via `performance.now()`). The actual duration depends on script execution speed, URL parsing, and `history.replaceState()` performance. Without early-cleanup, the token is visible for the entire duration from page load to SDK initialization (typically 200–800ms depending on page complexity).

| Configuration | Expected Visibility Window |
|---------------|---------------------------|
| Early-cleanup script deployed | < 1ms |
| SDK-only cleanup (no early-cleanup) | 200–800ms (varies by page load time) |
| No cleanup (misconfigured) | Indefinite |

**Measurement methodology:**

The early-cleanup script captures `performance.now()` timestamps at three points:
1. Script execution start
2. Token extraction complete
3. `history.replaceState()` complete (URL cleaned)

The visibility window is the duration between point 1 and point 3.

**SDK verification:**

```javascript
var timings = Nylo.getTimingMetrics();
console.log(timings.earlyCleanup.detected);    // true if early-cleanup ran
console.log(timings.earlyCleanup.durationMs);  // e.g., 0.142 (milliseconds)
console.log(timings.tokenVisibilityWindowMs);  // e.g., 0.142 (with early-cleanup)
                                                //       523.7 (without early-cleanup)
```

### 13.3 Token Entropy

**Claim:** Each WaiTag is derived from 128 bits of cryptographic entropy from the Web Crypto API, exposed through 108 bits (27 hex chars) of a SHA-256 digest.

| Component | Entropy Source | Bits |
|-----------|---------------|------|
| CSPRNG input | `crypto.getRandomValues(new Uint8Array(16))` | 128 |
| Timestamp + domain salt (digest inputs) | Deterministic diversifiers (not entropy) | 0 |
| Digest output used in identifier | 27 hex chars of SHA-256(inputs) | 108 exposed |

**Measurement methodology:**

1. Generate 10,000 WaiTags and verify no collisions
2. Verify identifiers match `wai_[0-9a-f]{19}_[0-9a-f]{8}` and are uniformly distributed across the hex character space
3. Verify the randomness source is `crypto.getRandomValues` (not `Math.random`) and the digest is computed via `crypto.subtle.digest`
4. Verify no substring of the identifier decodes to a timestamp, and that identifiers generated in the same millisecond on the same domain differ

**Expected collision probability:** For the 108-bit exposed digest, the probability of collision in a set of N identifiers is approximately N²/2¹⁰⁹. For 1 billion identifiers: ~1.5 × 10⁻¹⁵.

### 13.4 Token Lifetime and Replay Surface

**Claim:** Each token is valid for exactly one verification attempt and expires after a configurable window (default: 300 seconds / 5 minutes).

| Property | Value |
|----------|-------|
| Maximum token lifetime | 300 seconds (configurable) |
| Maximum verification attempts | 1 (one-time-use) |
| Server-side nonce retention | ≥ token lifetime |
| Replay after first verification | Rejected with `TOKEN_REPLAYED` |
| Replay after expiry | Rejected with `TOKEN_EXPIRED` |

**Measurement methodology:**

1. Generate a cross-domain token
2. Submit it for verification — expect success
3. Submit the same token again — expect `TOKEN_REPLAYED` error
4. Generate a new token, wait >300 seconds, submit — expect `TOKEN_EXPIRED` error

### 13.5 Token Verification Latency

**Claim:** End-to-end token verification (from SDK token detection to server response) completes in under 100ms on typical network conditions.

| Phase | Expected Duration |
|-------|-------------------|
| Token detection (SDK) | < 1ms |
| Token extraction and URL cleanup | < 1ms |
| Network round-trip to verification server | 20–80ms (varies by network) |
| Server-side verification (signature + replay + expiry) | < 5ms |
| Identity restoration (SDK) | < 1ms |
| **Total** | **< 100ms typical** |

**SDK verification:**

```javascript
var timings = Nylo.getTimingMetrics();
console.log(timings.tokenVerification.durationMs);  // e.g., 47.23 (milliseconds)
console.log(timings.tokenVerification.source);       // "early_cleanup", "hash", or "search"
console.log(timings.sdkInitDurationMs);              // e.g., 12.45 (total SDK init time)
```

### 13.6 HTTP Data Leakage

**Claim:** With hash fragment transport, exactly 0 bytes of token data are transmitted in any HTTP request from the client to the destination server.

This is a structural guarantee, not a runtime measurement. Per RFC 3986 Section 3.5, the fragment component of a URI is not sent in HTTP requests. This behavior is implemented by all conforming HTTP user agents and cannot be overridden by JavaScript or server configuration.

**Measurement methodology:**

1. Set up a packet capture (tcpdump/Wireshark) on the destination server
2. Navigate to `destination.com/page#nylo_token=test_value`
3. Inspect the HTTP GET request — verify `test_value` does not appear in the request line, headers, or body
4. Verify `test_value` does not appear in any subsequent `Referer` headers to third-party resources

### 13.7 Storage Integrity Validation

**Claim:** All stored identity data (cookie, localStorage, sessionStorage) is validated with HMAC-SHA256 on every read. Tampered data is rejected and cleared.

| Property | Value |
|----------|-------|
| Integrity algorithm | HMAC-SHA256 via Web Crypto API |
| HMAC key derivation | `customerId` (client-side, not a secret) |
| Validation frequency | Every storage read |
| Tampered data behavior | Rejected, storage layer cleared |
| All layers invalid behavior | Fresh identity generated |
| Legacy hash migration | Automatic (djb2 → HMAC on first read) |

**Measurement methodology:**

1. Initialize the SDK and note the stored identity in `nylo_wai` cookie
2. Modify the `waiTag` field in the cookie via browser developer tools
3. Reload the page — the SDK should reject the tampered cookie and generate a new identity
4. Verify the old `waiTag` is no longer in use

### 13.8 Mandatory Token Encryption and Signing

**Claim:** The verification server rejects 100% of unencrypted or unsigned cross-domain tokens. No cleartext token can pass verification regardless of payload contents, and no ciphertext token missing its authentication tag can pass.

**Measurement methodology:**

1. Create a valid-looking legacy cleartext payload: `btoa(JSON.stringify({waiTag:"wai_test_1234", sessionId:"test", exp:9999999999999}))`
2. Submit it to `/api/tracking/verify-cross-domain-token` — verify the server rejects it with `UNSUPPORTED_VERSION`
3. Craft a v2-shaped envelope without its `tag` field — verify the server rejects it with `MISSING_SIGNATURE`
4. Flip one ciphertext byte of a genuine v2 token — verify rejection with `INVALID_SIGNATURE`
5. Only a genuine v2 token (encrypted + signed by the server) should succeed, exactly once

### 13.9 Summary Table

| Property | Measurable Claim | Measurement Method |
|----------|------------------|--------------------|
| Logging surface (hash transport) | 0/6 HTTP log fields contain token | Server log inspection |
| Logging surface (query transport) | 6/6 HTTP log fields contain token | Server log inspection |
| Token visibility window (early-cleanup) | < 1ms | `Nylo.getTimingMetrics().earlyCleanup.durationMs` |
| Token visibility window (SDK-only) | 200–800ms | `Nylo.getTimingMetrics().tokenVisibilityWindowMs` |
| Cryptographic entropy | 128 bits | Source code audit of `crypto.getRandomValues` call |
| Token lifetime | 300 seconds (configurable) | Clock-based expiry test |
| Replay attempts accepted | 1 (one-time-use) | Sequential verification test |
| HTTP bytes leaked (hash transport) | 0 | Packet capture |
| Verification latency | < 100ms typical | `Nylo.getTimingMetrics().tokenVerification.durationMs` |
| Cleartext/unsigned token acceptance rate | 0% (all rejected) | Submit legacy cleartext and tag-stripped tokens, verify rejection |
| Token payload confidentiality | Identity fields unreadable without server secret | Decode envelope, verify only routing metadata is cleartext |
| Storage integrity validation | HMAC-SHA256 on every read | Tamper cookie, verify rejection on reload |

---

## Changelog

### v1.4.0-draft (2026-08-26)

- **SECURITY:** Token format v2 — tokens are now **encrypted and signed** (sign-then-encrypt: HMAC-SHA256 inner signature, AES-256-GCM envelope, per-tenant/per-destination HKDF-SHA256 key derivation, AEAD-bound routing metadata). Legacy signed-cleartext tokens are rejected with `UNSUPPORTED_VERSION` (Sections 6.1, 6.2, 9.10, 13.8)
- **PRIVACY:** WaiTag generation is now digest-based — SHA-256 over CSPRNG randomness, timestamp, and a domain salt; identifiers no longer embed a readable timestamp or domain hash (Sections 2, 4, 13.3)
- **PRIVACY:** Stored identifiers are time-limited with automatic expiry — 180-day absolute / 30-day unused defaults, configurable, enforced on every read; legacy records without timestamps fail closed (new Section 8.5, updated 10.5)
- **PRIVACY:** User-facing context controls specified — `getStoredContext()` / `resetContext()` / `revokeContext()` and the `nyloContextPreserved` transparency event (Section 10.3)
- **SECURITY FIX:** Domain verification management endpoints require API-key authentication; caller-supplied customer IDs are no longer accepted (Section 7.3)
- **SECURITY FIX:** Added Section 9.11 Write Grants — browser write paths (ingestion, registration, verification) are authorized by short-lived server-signed grants; tenant identity is resolved from server-side domain→tenant configuration, never from caller-supplied customer IDs or headers
- **SECURITY FIX:** Verification is authorized before consumption — unauthorized verification attempts can no longer burn tokens (denial-of-service fix)
- **SECURITY FIX:** Replay consumption is atomic, and production deployments MUST use a durable shared replay store or refuse to start
- **PRIVACY:** Fingerprint-capable telemetry (user agent, language, timezone, screen/viewport, click coordinates, and similar) removed from the SDK and stripped server-side as defense in depth; identity generation and matching never use browser/device attributes
- **PRIVACY:** URLs are reduced to origin + path before transmission and storage; query strings and fragments are discarded unless individually allowlisted
- Identity storage helpers renamed to reflect reality: stored identity is reversibly *encoded* (with a separate HMAC for tamper evidence), not encrypted
- Registrable-domain handling uses public-suffix-list parsing; invalid event types, domains, session IDs, WaiTags, and out-of-window timestamps are rejected rather than normalized

### v1.3.0-draft (2026-03-18)

- **SECURITY FIX:** Mandatory token signing — unsigned cross-domain tokens are now rejected with `MISSING_SIGNATURE` error; servers refuse to verify tokens if `NYLO_TOKEN_SECRET` is not configured
- **SECURITY FIX:** Storage integrity upgraded from djb2 hash to HMAC-SHA256 via Web Crypto API; all stored identity data validated on every read
- Added Section 9.5 expanded XSS threat model: honest tables of what the SDK protects against and what it does not
- Added Section 9.9: Content Security Policy (CSP) recommendations
- Added Section 9.10: Mandatory Token Signing specification
- Added Section 13.7: Storage Integrity Validation measurable claim
- Added Section 13.8: Mandatory Token Signing measurable claim
- Updated Section 8.3: Documented HMAC integrity with verification-on-read behavior and limitations
- Updated threat model table: added token forgery and stored identity tampering rows
- Added design rationale for not using HttpOnly cookies
- Token generation endpoint requires API key authentication (`X-API-Key` header) and mandatory `destinationDomain` binding
- Domain mismatch enforcement on verification (403 `DOMAIN_MISMATCH`)
- Cross-domain endpoints not registered at startup if `NYLO_TOKEN_SECRET` is missing (fail-loud)
- Legacy djb2 integrity hashes automatically migrated to HMAC on first read

### v1.2.0-draft (2026-03-02)

- Added Section 13: Measurable Security Properties with 7 quantifiable claims
- SDK instrumented with `performance.now()` timing capture for all token lifecycle phases
- Added `Nylo.getTimingMetrics()` API for programmatic security measurement verification
- Early-cleanup script now captures timing data (`window.__nylo_early_token_timing`)
- Added measurement methodology for each security claim (reproducible by third parties)
- Created IETF Internet-Draft draft-01 with measurable claims and PEARG-relevant framing
- Created PEARG discussion document for IRTF Privacy Enhancements and Assessments Research Group

### v1.1.0-draft (2026-02-22)

- Added Section 5.2: Early-Cleanup Script specification with reference implementation
- Changed query parameter transport to opt-in only (Section 5.3), disabled by default
- Added replay protection as a MUST requirement in Section 6.2
- Added `nonce` field to token format (Section 6.1) for replay protection
- Added error codes table to Section 6.2
- Added Section 9: Security Threat Model and Mitigations (comprehensive)
- Added Section 9.3: Detailed browser extension limitation analysis
- Added Section 10: Privacy Considerations (expanded from implicit references)
- Added Section 11: Consent Model specification
- Added Section 12: Compatibility notes
- Clarified first-party cookie usage in Section 4.4 and Section 8.1
- Updated protocol flow diagram to include early-cleanup and replay protection steps
- Updated version from 1.0.0-draft to 1.1.0-draft
