# WTX-1: Cross-Domain Context Preservation Protocol

A Proposal of the [Privacy Community Group](https://privacycg.github.io/).

**Authors:** Ravi Teja Surampudi (Nylo Project)

**Specification:** [IETF Internet-Draft: draft-surampudi-wtx1-00](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)

**Reference Implementation:** [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo) (MIT License)

**Protocol Specification:** [github.com/tejasgit/wtx-1](https://github.com/tejasgit/wtx-1)

**Issue Tracker:** https://github.com/tejasgit/wtx-1/issues

---

## Table of Contents

- [Introduction](#introduction)
- [Goals](#goals)
- [Non-Goals](#non-goals)
- [Motivating Use Cases](#motivating-use-cases)
- [Protocol Overview](#protocol-overview)
  - [WaiTag Identifiers](#waitag-identifiers)
  - [DNS Domain Authorization](#dns-domain-authorization)
  - [Token Transport via Hash Fragments](#token-transport-via-hash-fragments)
  - [Token Verification](#token-verification)
  - [Consent and Anonymous Mode](#consent-and-anonymous-mode)
- [Key Scenarios](#key-scenarios)
- [Detailed Design Discussion](#detailed-design-discussion)
  - [Why Hash Fragments](#why-hash-fragments)
  - [Why DNS TXT Records](#why-dns-txt-records)
  - [Why Not a Browser API](#why-not-a-browser-api)
  - [Token Security Model](#token-security-model)
  - [Storage Strategy](#storage-strategy)
- [Privacy Considerations](#privacy-considerations)
  - [Pseudonymous Identifiers and GDPR](#pseudonymous-identifiers-and-gdpr)
  - [Data Minimization](#data-minimization)
  - [User Control](#user-control)
  - [Residual Risks](#residual-risks)
- [Considered Alternatives](#considered-alternatives)
- [Security Considerations](#security-considerations)
- [Deployment and Compatibility](#deployment-and-compatibility)
- [Stakeholder Feedback / Opposition](#stakeholder-feedback--opposition)
- [References and Acknowledgments](#references-and-acknowledgments)

---

## Introduction

The deprecation of third-party cookies eliminates the most widely used mechanism for cross-domain identity on the web. While this is a significant win for user privacy, it creates a gap for legitimate analytics use cases where site operators need to understand user journeys across domains they own or operate.

WTX-1 (WaiTag Transfer Protocol, version 1) defines a protocol for preserving pseudonymous context across navigations between cooperating, DNS-authorized domains. It achieves this without third-party cookies, fingerprinting, login requirements, or PII collection. (A first-party cookie is used only as a local storage fallback for WaiTag persistence on the same domain.)

The protocol is designed to work within existing web platform constraints — it requires no new browser APIs, no browser vendor cooperation, and no changes to HTTP. It operates entirely within current web standards using URL hash fragments, DNS TXT records, and client-side JavaScript.

## Goals

1. **Enable privacy-preserving cross-domain analytics** — Allow site operators to understand user journeys across domains they own (e.g., `blog.example.com` → `shop.example.com`) without resorting to fingerprinting or PII collection.

2. **Work without third-party cookies** — Provide a mechanism that functions in browsers with full third-party cookie blocking (Safari ITP, Firefox ETP, Chrome Privacy Sandbox).

3. **Require no login** — Preserve context for anonymous visitors who have not created accounts or signed in.

4. **Respect user consent** — Degrade gracefully to fully anonymous analytics when consent is denied, with no residual tracking capability.

5. **Limit scope via domain authorization** — Ensure only domains explicitly authorized via DNS records can participate in identity sharing, preventing unauthorized tracking networks.

6. **Minimize data exposure** — Tokens contain only the minimum fields necessary for identity verification, with no behavioral data, page content, or interaction history.

7. **Avoid new browser APIs** — Operate entirely within existing web standards so that adoption does not depend on browser vendor implementation timelines.

## Non-Goals

1. **Replacing third-party cookies for advertising** — WTX-1 is not designed for ad targeting, real-time bidding, or cross-publisher audience building. It is scoped to first-party analytics across domains under common administrative control.

2. **User identification** — WTX-1 does not identify users. WaiTags are pseudonymous and contain no PII. The protocol does not define or require a mapping between WaiTags and real-world identities.

3. **Cross-browser identity** — WTX-1 operates within a single browser instance. It does not attempt to correlate identities across different browsers or devices.

4. **Replacing the Storage Access API** — WTX-1 does not request or use third-party storage access. It is complementary to the Storage Access API, not a replacement.

5. **Circumventing tracking prevention** — WTX-1 is designed to work *within* browser tracking prevention policies, not around them. It uses no mechanisms that tracking prevention features are designed to block.

## Motivating Use Cases

### 1. Multi-Domain Publisher Analytics

A media company operates `news.example.com`, `sports.example.com`, and `video.example.com`. They want to understand how readers move between properties to optimize content strategy. Today, with third-party cookies blocked, each domain appears as an isolated silo with no visibility into cross-domain journeys.

### 2. E-Commerce Conversion Attribution

An online retailer runs marketing content on `blog.retailer.com` and sells products on `shop.retailer.com`. They need to attribute conversions (purchases) to content that drove the visit. Without cross-domain context, attribution models break down.

### 3. Healthcare Patient Portal Navigation

A hospital operates `info.hospital.org` (public information) and `portal.hospital.org` (patient portal). They need to understand how patients navigate from information pages to the portal for UX improvement, but HIPAA prohibits PII collection in analytics. WTX-1's pseudonymous identifiers satisfy this requirement.

### 4. Government Service Discovery

A government agency operates multiple service domains. Citizens navigate between them to complete tasks (e.g., `benefits.gov.example` → `apply.gov.example`). The agency needs to optimize these journeys but cannot collect PII or use fingerprinting per government IT policy.

### 5. A/B Testing Across Subdomains

A SaaS company runs experiments that span their marketing site and product application on different domains. They need consistent experiment assignment across the navigation boundary.

## Protocol Overview

### WaiTag Identifiers

A WaiTag is a pseudonymous identifier generated client-side:

```
wai_[timestamp-hex]_[random-hex]_[checksum]
```

**Generation requirements:**
- Random component MUST use `crypto.getRandomValues()` (Web Cryptography API)
- Minimum 128 bits of entropy in the random component
- No PII, device signals, or derivable real-world identity encoded
- Stored in `localStorage` (primary), with `sessionStorage` and cookie fallbacks

**Example:** `wai_18d4f2a1b3c_a7f2e9d1c4b8_3k`

### DNS Domain Authorization

Domains must publish a DNS TXT record to participate in cross-domain identity sharing:

```
_nylo.example.com TXT "v=nylo1; domains=blog.example.com,shop.example.com; key=abc123"
```

**Fields:**
- `v=nylo1` — Protocol version
- `domains=` — Comma-separated list of authorized peer domains
- `key=` — Shared key identifier for token verification

**Properties:**
- Only the domain administrator can create DNS TXT records
- Authorization is explicit and enumerated (no wildcards)
- Records can be revoked by removing the TXT record
- Subdomain inheritance: a record on `example.com` covers `*.example.com`

### Token Transport via Hash Fragments

When a user navigates from an authorized source domain to an authorized destination domain, the source appends a token to the URL hash fragment:

```
https://shop.example.com/product/123#nylo_token=eyJ3...
```

**Why hash fragments:**
- Per [RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5), the fragment component is not sent to the server in HTTP requests
- The token is only accessible to client-side JavaScript on the destination page
- The client reads the token, sends it to a verification endpoint via a dedicated API call, and immediately cleans up the URL using `history.replaceState()`

**Opt-in fallback:** URL query parameters (`?nylo_token=...`) are available as an opt-in fallback (disabled by default) for environments where hash fragments are unreliable. Query parameters are visible to the destination server in HTTP requests and server logs, so this option trades some privacy for compatibility. Implementors who enable it SHOULD implement server-side log redaction.

### Token Verification

Tokens are HMAC-SHA256 signed and contain:

| Field | Description |
|---|---|
| `waiTag` | The pseudonymous identifier |
| `sessionId` | Current session identifier |
| `userId` | Optional application-level identifier (may constitute personal data; requires lawful basis if used) |
| `sourceDomain` | The originating domain |
| `exp` | Expiration timestamp (default: 5 minutes) |
| `sig` | HMAC-SHA256 signature |

**Verification requirements:**
- Token MUST NOT be expired
- Signature MUST be valid
- Source domain MUST be in the destination's DNS-authorized domain list
- Replay protection: each token MUST only be accepted once

### Consent and Anonymous Mode

The protocol defines a consent API:

```javascript
// Grant consent — enables cross-domain identity
nylo.setConsent(true);

// Revoke consent — degrades to anonymous mode
nylo.setConsent(false);

// Check current consent state
nylo.hasConsent();
```

**Anonymous mode behavior:**
- No WaiTag is generated or stored
- No cross-domain tokens are created or accepted
- Events are tracked with a random per-session identifier only
- No data persists beyond the current page session

## Key Scenarios

### Scenario 1: Cross-Domain Navigation with Consent

```
1. User visits blog.example.com, consents to analytics
2. Nylo SDK generates WaiTag: wai_18d4f2a1b3c_a7f2e9d1c4b8_3k
3. User clicks link to shop.example.com
4. SDK checks DNS authorization: blog.example.com ↔ shop.example.com ✓
5. SDK appends token to URL hash fragment
6. User arrives at shop.example.com#nylo_token=eyJ3...
7. Destination SDK reads token from hash fragment
8. SDK sends token to verification endpoint via API call
9. Verification: signature valid, not expired, domain authorized ✓
10. SDK cleans URL using history.replaceState()
11. Same WaiTag now active on both domains
```

### Scenario 2: Cross-Domain Navigation without Consent

```
1. User visits blog.example.com, denies consent
2. No WaiTag is generated
3. User clicks link to shop.example.com
4. No token is appended to the URL
5. User arrives at shop.example.com (clean URL)
6. Anonymous-only analytics on destination domain
```

### Scenario 3: Unauthorized Domain

```
1. User visits blog.example.com with active WaiTag
2. User clicks link to evil-tracker.com
3. SDK checks DNS authorization: blog.example.com ↔ evil-tracker.com ✗
4. No token is appended to the URL
5. No cross-domain context is shared
```

## Detailed Design Discussion

### Why Hash Fragments

Hash fragments were chosen as the primary transport mechanism for several reasons:

1. **Not sent to servers:** Per RFC 3986, the fragment component is processed by the client only. The destination server never sees the token in the HTTP request, server logs, or referrer headers.

2. **Distinct from cookie mechanisms:** Hash fragments are not cookies and do not use the Set-Cookie/Cookie HTTP mechanism. Whether this distinction affects consent requirements under the ePrivacy Directive depends on jurisdiction and interpretation.

3. **Universal browser support:** Hash fragments work identically across all browsers, including those with aggressive tracking prevention (Safari ITP, Firefox ETP).

4. **Immediate cleanup:** The token can be removed from the URL immediately using `history.replaceState()` without triggering a page reload.

**Trade-off:** Some browser extensions with content script access could read the hash fragment before cleanup. This is mitigated by:
- **Early-cleanup script:** An inline `<head>` script that executes before any other scripts, extracting the token into a short-lived JavaScript variable and immediately cleaning the URL. This eliminates the visibility window for third-party scripts.
- **One-time-use verification:** Each token is only accepted once server-side, so an intercepted token cannot be replayed.
- **Short expiration:** Tokens default to 5-minute expiry.

### Why DNS TXT Records

DNS TXT records were chosen for domain authorization because:

1. **Administrative control:** Only domain administrators can create DNS records, ensuring that domains cannot be added to a tracking network without the owner's consent.

2. **Machine-readable:** DNS records can be verified programmatically without human intervention.

3. **Precedent:** DNS TXT records are widely used for domain verification (SPF, DKIM, DMARC, Google Search Console, Let's Encrypt).

4. **Revocable:** Authorization can be revoked by removing the DNS record.

**Alternative considered:** `.well-known` URIs were considered but require a running web server on the domain, which may not always be available. DNS records work for any domain, including those without web servers.

### Why Not a Browser API

WTX-1 intentionally does not propose a new browser API because:

1. **Deployment speed:** Browser API standardization takes years. WTX-1 can be deployed immediately using existing web standards.

2. **No vendor dependency:** Site operators can adopt WTX-1 without waiting for browser vendors to implement new APIs.

3. **Compatibility:** WTX-1 works with all current browsers, including older versions that won't receive new API implementations.

**Future possibility:** If WTX-1 gains adoption, a dedicated browser API could provide additional privacy guarantees (e.g., browser-mediated token transport that prevents extension access). This explainer can serve as the basis for such a future API proposal.

### Token Security Model

**Threat model:**

| Threat | Mitigation |
|---|---|
| Token interception by destination server | Hash fragment transport (not sent in HTTP requests) |
| Token replay | One-time-use verification with server-side nonce tracking |
| Token tampering | HMAC-SHA256 signature verification |
| Token expiration bypass | Server-side timestamp validation (default 5 min) |
| Unauthorized domain participation | DNS TXT record verification |
| Referrer header leakage | Recommended `Referrer-Policy: no-referrer` header |
| Browser extension access | Short token lifetime + immediate cleanup |

### Storage Strategy

WaiTags are stored using a three-layer strategy for resilience:

1. **Primary:** `localStorage` — persistent across sessions
2. **Secondary:** `sessionStorage` — survives page reloads within a session
3. **Tertiary:** First-party cookie (HttpOnly where possible) — fallback for contexts where Web Storage is unavailable

All stored data is obfuscated (not encrypted) to prevent casual inspection. No PII is ever stored.

## Privacy Considerations

### Pseudonymous Identifiers and GDPR

Under GDPR, pseudonymous identifiers are considered personal data when they can be attributed to a natural person using additional information (Article 4(5)). WaiTags are pseudonymous — they contain no PII, but an organization could theoretically maintain a separate mapping table linking WaiTags to real identities.

**Protocol position:** WTX-1 does not define or require such a mapping. Implementors who create such mappings take on the full obligations of a GDPR data controller, including lawful basis, data subject rights, and data protection impact assessments.

**Recommendation:** Implementors SHOULD NOT create WaiTag-to-identity mappings unless they have a clear lawful basis and have completed a DPIA.

### Data Minimization

Cross-domain tokens contain only the minimum fields necessary for identity verification:

- WaiTag (pseudonymous identifier)
- Session ID
- Optional user ID (application-level; may constitute personal data if linkable to an individual)
- Source domain
- Expiration timestamp
- HMAC signature

No behavioral data, page content, interaction history, device information, or browsing history is included in the token.

### User Control

Implementations SHOULD provide users with:

1. **Opt-out:** Ability to opt out of cross-domain identity while retaining single-domain analytics
2. **Data clearing:** Ability to clear WaiTag and all associated data
3. **Transparency:** Ability to view what data has been collected
4. **Deletion:** Ability to request deletion of all data associated with their WaiTag (GDPR Article 17)

### Residual Risks

1. **Server-side correlation:** Organizations operating multiple authorized domains can correlate WaiTags server-side. The protocol limits correlation to DNS-authorized domains but cannot prevent the authorizing organization from performing it.

2. **Token visibility to browser extensions:** The early-cleanup `<head>` script eliminates the visibility window for third-party page scripts. However, browser extensions with content script access may execute before the early-cleanup script. This risk is mitigated by one-time-use token verification and short expiration (default 5 minutes).

3. **Referrer leakage:** While modern browsers generally do not include hash fragments in `Referer` headers, implementations SHOULD set `Referrer-Policy: no-referrer` or `Referrer-Policy: same-origin` to mitigate edge cases.

4. **Long-lived identifiers:** WaiTags stored in `localStorage` persist until explicitly cleared. Implementations SHOULD implement rotation policies (e.g., regenerate WaiTag every 90 days) to limit the window of potential correlation.

5. **Query parameter opt-in:** If an implementor enables query parameter token transport (disabled by default), tokens become visible to the destination server in HTTP request logs. Implementors who enable this option SHOULD ensure server-side log redaction of token parameters.

## Considered Alternatives

### 1. First-Party Sets / Related Website Sets

**What it is:** Chrome's proposal to declare a set of related domains that can share state.

**Why WTX-1 differs:**
- First-Party Sets is Chrome-specific and not adopted by Safari or Firefox
- It requires browser-level enforcement and API support
- WTX-1 works across all browsers without vendor-specific APIs
- DNS TXT records are a more universal authorization mechanism than browser-maintained lists

### 2. Storage Access API

**What it is:** A browser API that allows embedded iframes to request access to first-party storage.

**Why WTX-1 differs:**
- Storage Access API requires user interaction with an embedded iframe
- It's designed for the embedded third-party use case, not top-level navigation
- WTX-1 operates at the navigation level, not the embedding level
- The two approaches are complementary, not competing

### 3. Server-Side Identity Stitching

**What it is:** Correlating users server-side using IP addresses, user agents, and login timestamps.

**Why WTX-1 differs:**
- Server-side stitching is probabilistic and inaccurate
- It often involves PII (IP addresses are personal data under GDPR)
- WTX-1 provides deterministic, consent-gated identity with no PII

### 4. Federated Credential Management (FedCM)

**What it is:** A browser API for federated identity without third-party cookies.

**Why WTX-1 differs:**
- FedCM requires user login and account creation
- It's designed for authentication, not analytics
- WTX-1 works for anonymous visitors without login

### 5. Google Privacy Sandbox Topics API

**What it is:** A browser API that provides coarse-grained interest-based signals for advertising.

**Why WTX-1 differs:**
- Topics API is for ad targeting, not analytics
- It provides interest categories, not cross-domain journey continuity
- It's Chrome-specific and not adopted by other browsers
- WTX-1 provides deterministic context preservation, not probabilistic interest signals

## Security Considerations

Beyond the token security model described above, implementors should consider:

1. **HTTPS requirement:** All token transport and verification MUST occur over HTTPS. The protocol MUST NOT be used over unencrypted HTTP.

2. **Cross-site scripting (XSS):** If the destination page is vulnerable to XSS, an attacker could read the hash fragment before cleanup. Implementations SHOULD sanitize all token data before use and MUST NOT insert token values into the DOM without proper escaping.

3. **DNS spoofing:** DNS TXT record verification is subject to DNS spoofing attacks. Implementations SHOULD use DNSSEC where available and MUST validate DNS responses over secure channels.

4. **Server-side key management:** The shared HMAC key used for token signing must be stored securely on participating servers. Key rotation policies SHOULD be implemented.

5. **Rate limiting:** Verification endpoints SHOULD implement rate limiting to prevent token brute-force attacks and denial-of-service.

## Deployment and Compatibility

- **Browser compatibility:** WTX-1 uses standard web APIs (`crypto.getRandomValues`, `localStorage`, `history.replaceState`, `URL` parsing) available in all modern browsers. No browser-specific APIs are required.
- **Tracking prevention interaction:** The protocol does not use third-party cookies, third-party storage, or redirect-based tracking patterns. It should not trigger Safari ITP, Firefox ETP, or similar tracking prevention features, though this has not been formally verified with all browser vendors.
- **Progressive enhancement:** Sites can adopt WTX-1 incrementally — single-domain tracking works without DNS authorization setup. Cross-domain features activate only when DNS records are configured.
- **Existing analytics integration:** WTX-1 can operate alongside existing analytics solutions (Google Analytics, Adobe Analytics, etc.) as a supplementary identity layer.

## Stakeholder Feedback / Opposition

| Stakeholder | Anticipated Feedback |
|---|---|
| Privacy advocates | Likely supportive of the consent-gated, no-PII, no-fingerprinting approach. May raise concerns about pseudonymous tracking scope and the token visibility window. |
| Browser vendors | No formal feedback received. Protocol does not require browser changes, so adoption is not dependent on vendor support. |
| Analytics industry | Anticipated interest as a potential approach for cross-domain analytics without deprecated cookie mechanisms. |
| Regulated industries | Healthcare, finance, and government sectors are anticipated audiences given their need for privacy-preserving analytics that satisfy regulatory requirements (HIPAA, FedRAMP, etc.). |
| Ad tech industry | Not the target audience. WTX-1 is scoped to first-party analytics, not cross-publisher ad targeting. |

**Note:** This proposal has not yet received formal feedback from any stakeholder group. The above represents anticipated positions based on the protocol's design goals. The author is seeking community feedback and potential champions.

## References and Acknowledgments

### Normative References

- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) — HMAC: Keyed-Hashing for Message Authentication
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) — Key words for use in RFCs to Indicate Requirement Levels
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) — Uniform Resource Identifier (URI): Generic Syntax
- [W3C Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)

### Informative References

- [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) — General Data Protection Regulation
- [CCPA](https://oag.ca.gov/privacy/ccpa) — California Consumer Privacy Act
- [Intelligent Tracking Prevention](https://webkit.org/blog/7675/intelligent-tracking-prevention/) — Apple WebKit
- [Enhanced Tracking Protection](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop) — Mozilla Firefox
- [Privacy Sandbox](https://privacysandbox.com/) — Google Chrome

### Acknowledgments

WTX-1 was developed as part of the Nylo project to address the analytics gap created by the deprecation of third-party cookies, with a focus on privacy-respecting solutions for regulated industries including healthcare, finance, and government.

The protocol design was informed by analysis of existing Privacy CG proposals, including Bounce Tracking Protection, Storage Access API, and the broader discussion around cross-domain identity in a post-cookie web.
