# WTX-1: Privacy Analysis of Cross-Domain Context Preservation via Hash Fragment Transport

> License: This document is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

**Submitted to:** PEARG (Privacy Enhancements and Assessments Research Group)
**Mailing list:** pearg@ietf.org
**Authors:** Ravi Teja Surampudi (Nylo Project)
**Date:** 2026-03-02
**Internet-Draft:** [draft-surampudi-wtx1-01](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)
**Protocol specification:** [WTX-1-SPEC.md](https://github.com/tejasgit/wtx-1)
**Reference implementation:** [Nylo SDK](https://github.com/tejasgit/nylo) (dual-licensed: MIT core, commercial license for cross-domain identity features — see LICENSING.md in the repository)

---

## 1. Problem Statement

The deprecation of third-party cookies across major browsers (Safari ITP 2017, Firefox ETP 2019, Chrome Privacy Sandbox 2024+) eliminates the primary mechanism for cross-domain user identification on the web. While this is a significant privacy improvement, it creates a gap for legitimate analytics use cases where site operators need to understand pseudonymous user journeys across domains under their administrative control.

Existing alternatives each carry significant limitations:

- **Browser fingerprinting** — privacy-invasive, increasingly blocked, ethically and legally problematic
- **Login-gated identity** — excludes anonymous visitors, requires PII collection
- **First-party data sharing** — requires business partnerships and PII exchange
- **Privacy Sandbox APIs** — Chrome-only, advertising-focused, coarse-grained

There is currently no standardized, privacy-respecting mechanism for preserving pseudonymous context across navigations between cooperating, DNS-authorized domains without requiring new browser APIs.

This falls squarely within PEARG's charter of conducting "privacy analysis of proposed and deployed technologies." We present WTX-1 as a concrete protocol for evaluation and invite the research group's critique.

---

## 2. Protocol Summary

WTX-1 (WaiTag Transfer Protocol, version 1) preserves pseudonymous visitor context across navigations between cooperating domains. The full protocol is specified in [draft-surampudi-wtx1-01](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/) and [WTX-1-SPEC.md](https://github.com/tejasgit/wtx-1). A brief summary follows.

**Core components:**

1. **WaiTag identifiers** — Pseudonymous identifiers generated client-side by hashing (SHA-256) 128 bits of `crypto.getRandomValues()` entropy with a timestamp and a domain-specific salt. Format: `wai_<digest_hex[0:19]>_<digest_hex[19:27]>` — only digest fragments form the identifier, so no timestamp or domain marker is readable from it. No direct identifiers, device signals, or derivable real-world identity is encoded; the identifier is pseudonymous, not anonymous.

2. **DNS domain authorization** — Participating domains must publish DNS TXT records to authorize cross-domain identity sharing. Only explicitly authorized domain pairs can exchange tokens.

3. **Hash fragment token transport** — Cross-domain tokens are appended to the destination URL as hash fragments (`#nylo_token=<token>`). Per RFC 3986 Section 3.5, hash fragments are never sent to the server in HTTP requests, never logged in server access logs, and never included in Referer headers.

4. **Early-cleanup script** — An inline `<head>` script executes before any other page scripts, extracts the token from the hash fragment, stashes it in a short-lived JavaScript variable, and immediately cleans the URL via `history.replaceState()`. This reduces the token visibility window to sub-millisecond durations.

5. **One-time-use verification** — Tokens are HMAC-SHA256 signed and AES-256-GCM encrypted (keys derived per tenant and destination domain via HKDF-SHA256, so contents are confidential in transit), expire after a configurable window (default: 5 minutes), and are accepted exactly once by the verification server (nonce-based replay protection).

6. **Consent-gated degradation** — When user consent is denied, no identifiers are generated, no tokens are created, and the SDK operates in a fully anonymous mode.

---

## 3. Privacy Properties with Measurable Claims

A key contribution of this work is defining quantifiable, independently reproducible privacy claims. Each claim below includes a concrete measurement and methodology. Full details are in Section 13 of the [protocol specification](https://github.com/tejasgit/wtx-1).

### 3.1 HTTP Logging Surface Reduction

| Transport Method | HTTP Log Fields Containing Token (out of 6) |
|------------------|----------------------------------------------|
| Query parameters | 6/6 (request URI, Referer, proxy logs, CDN logs, WAF logs, packet inspection) |
| Hash fragments (WTX-1 default) | 0/6 |

**Methodology:** Configure a destination server to log all request headers and the full request URI. Navigate using hash fragment transport and verify the token is absent from all server-side log entries.

### 3.2 Token Visibility Window

| Configuration | Token Visible in `window.location.hash` |
|---------------|-----------------------------------------|
| Early-cleanup script deployed | < 1ms |
| SDK-only cleanup | 200–800ms |
| No cleanup | Indefinite |

**Methodology:** The early-cleanup script captures `performance.now()` timestamps at script start, token extraction, and URL cleanup completion. The SDK exposes these via `Nylo.getTimingMetrics()`.

### 3.3 Token Entropy

Each WaiTag is derived from 128 bits of cryptographic entropy sourced from `crypto.getRandomValues(new Uint8Array(16))`, hashed (SHA-256) with a timestamp and domain salt; the identifier exposes 108 bits (27 hex characters) of the digest. Collision probability for 1 billion identifiers: ~1.5 x 10^-15.

**Methodology:** Generate 10,000 WaiTags, verify no collisions, verify the `wai_[0-9a-f]{19}_[0-9a-f]{8}` format and uniform distribution across the hex character space, and verify no substring decodes to a timestamp.

### 3.4 Replay Attack Surface

Each token is accepted exactly once. Server-side nonce tracking ensures replay attempts are rejected with `TOKEN_REPLAYED`. Nonces are retained for at least the token expiry window.

**Methodology:** Submit a token for verification (expect success), submit the same token again (expect rejection).

### 3.5 HTTP Data Leakage

With hash fragment transport, exactly 0 bytes of token data are transmitted in any HTTP request from client to destination server. This is a structural guarantee per RFC 3986 Section 3.5, not a runtime behavior.

**Methodology:** Packet capture (tcpdump/Wireshark) on the destination server verifies the token does not appear in any HTTP request.

### 3.6 Summary

| Property | Measurable Claim |
|----------|------------------|
| HTTP log fields containing token (hash transport) | 0/6 |
| Token visibility window (early-cleanup) | < 1ms |
| Token visibility window (SDK-only) | 200–800ms |
| Cryptographic entropy | 128 bits |
| Token lifetime | 300 seconds (configurable) |
| Replay attempts accepted | 1 (one-time-use) |
| HTTP bytes leaked (hash transport) | 0 |
| Verification latency | < 100ms typical |

---

## 4. Threat Model Summary with Residual Risks

### 4.1 Mitigated Threats

| Threat | Mitigation |
|--------|------------|
| Token interception by destination server | Hash fragment transport (0 bytes in HTTP requests) |
| Token interception by third-party page scripts | Early-cleanup script strips token before other scripts execute |
| Token replay | One-time-use with server-side nonce tracking |
| Token tampering | HMAC-SHA256 signature verification |
| Token expiration bypass | Server-side timestamp validation |
| Unauthorized domain participation | DNS TXT record verification |
| Referrer header leakage | Hash fragments excluded from Referer per browser spec |
| Query parameter server exposure | Query parameter transport disabled by default |

### 4.2 Residual Risks

**Browser extensions:** Extensions declaring `"run_at": "document_start"` in their manifest execute before the early-cleanup script and can read `window.location.hash`. This is inherent to the browser extension model and affects all application-layer protocols (OAuth redirect tokens, SAML assertions, JWTs in localStorage, session cookies). WTX-1's mitigations (one-time-use, 5-minute expiry, pseudonymous-only data) make extension interception lower impact than equivalent attacks on most authentication protocols.

**Server-side correlation:** Organizations operating multiple DNS-authorized domains can correlate WaiTags server-side. The protocol limits correlation scope to explicitly authorized domain pairs but cannot prevent the authorizing organization from performing correlation across its own domains. This is analogous to first-party cookie correlation within a single eTLD+1.

**XSS on destination page:** If the destination page is vulnerable to XSS, injected scripts could read the token before cleanup. This is not unique to WTX-1 — XSS compromises all client-side security guarantees.

**DNS spoofing:** DNS TXT record verification is subject to spoofing. DNSSEC and DNS-over-HTTPS mitigate this.

---

## 5. Open Questions for PEARG

We invite PEARG's evaluation of the following research questions:

### Q1: Is hash fragment transport a sufficient privacy boundary?

WTX-1 relies on RFC 3986 Section 3.5's guarantee that hash fragments are not sent in HTTP requests. While this is universally implemented by conforming user agents, is reliance on this behavior an adequate privacy property for a cross-domain identity protocol? Are there edge cases (non-conforming clients, protocol downgrades, future browser changes) that weaken this guarantee?

### Q2: What is the real-world token visibility window?

We claim < 1ms with the early-cleanup script. Has PEARG evaluated similar inline-script-based cleanup patterns in other protocols? What are the failure modes (e.g., script parsing delays on low-powered devices, race conditions with Service Workers)?

### Q3: How should pseudonymous identifier scope be bounded?

WTX-1 scopes correlation to DNS-authorized domain pairs. Is DNS TXT record authorization a sufficient administrative boundary? Should there be additional limits on the number of domains in a single authorization group, or time-based restrictions on authorization validity?

### Q4: What privacy guarantees are lost without browser mediation?

WTX-1 operates entirely at the application layer. A browser-native API could provide stronger guarantees (e.g., preventing extension access, enforcing consent at the platform level). What specific privacy properties are sacrificed by the application-layer approach, and how significant are they in practice?

### Q5: How does the protocol interact with emerging tracking prevention?

Browser tracking prevention features (ITP, ETP, Bounce Tracking Protection) are continually evolving. WTX-1 does not use any mechanisms currently targeted by these features (no third-party cookies, no redirect chains, no link decoration patterns that match existing heuristics). However, could future heuristics flag hash-fragment-based token transport? What would the implications be?

### Q6: Is the consent-gated degradation model adequate?

When consent is denied, WTX-1 generates no identifiers and preserves no cross-domain context. Is this degradation complete? Are there information leaks in the "denied" path (e.g., timing side channels from the absence of token processing)?

---

## 6. Comparison with Existing Privacy CG Work

### Storage Access API

The Storage Access API allows embedded iframes to request access to first-party storage. WTX-1 operates at the top-level navigation boundary, not the embedding boundary. The two are complementary: Storage Access API handles the embedded third-party case, while WTX-1 handles the navigation case. WTX-1 does not request or use third-party storage access.

### Bounce Tracking Protection

Bounce Tracking Protection targets redirect-chain-based tracking patterns where an intermediate domain sets cookies during a brief redirect. WTX-1 does not use redirects — the token is appended to the final destination URL's hash fragment, and the user navigates directly. There is no intermediate domain, no redirect chain, and no third-party cookie setting.

### Related Website Sets (formerly First-Party Sets)

Related Website Sets allow domains to declare a relationship via a browser-maintained list, enabling limited cross-domain storage access. WTX-1 uses DNS TXT records instead, which do not require browser vendor cooperation or inclusion in a centralized list. WTX-1 also works cross-browser, while Related Website Sets are currently Chrome-specific.

### CHIPS (Cookies Having Independent Partitioned State)

CHIPS partitions third-party cookies by top-level site. WTX-1 does not use third-party cookies at all — it uses URL hash fragments for cross-domain transport and first-party cookies only for local persistence on the same domain.

---

## 7. Suggested Agenda Items for PEARG Meeting

1. **Privacy analysis of hash fragment transport** (15 min) — Review whether RFC 3986 Section 3.5 provides an adequate privacy boundary for cross-domain token transport, including edge cases and failure modes.

2. **Measurable privacy claims methodology** (10 min) — Discuss the approach of defining quantifiable, reproducible privacy claims for protocol specifications. Is this a useful pattern for other privacy-sensitive protocols?

3. **Application-layer vs. browser-mediated identity** (10 min) — Evaluate what privacy properties are gained or lost by operating at the application layer versus proposing a new browser API.

4. **DNS-based domain authorization model** (10 min) — Assess whether DNS TXT records are an appropriate authorization mechanism for bounding cross-domain identity scope, and what additional constraints might be needed.

5. **Open discussion and critique** (15 min) — General feedback on the protocol design, threat model, and residual risks.

---

## Summary

WTX-1 is a concrete protocol proposal for privacy-preserving cross-domain context preservation that operates within existing web standards. We submit it to PEARG not as a finished solution but as a research contribution for privacy analysis. The protocol defines measurable security properties, acknowledges specific residual risks, and poses open questions that we believe are within PEARG's expertise to evaluate.

We welcome critique, counter-proposals, and suggestions for strengthening the protocol's privacy guarantees. All materials are open source and the specification is released under CC BY 4.0.

**Contact:** Ravi Teja Surampudi — pearg@ietf.org
**Full specification:** [draft-surampudi-wtx1-01](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)
**Reference implementation:** [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo)
