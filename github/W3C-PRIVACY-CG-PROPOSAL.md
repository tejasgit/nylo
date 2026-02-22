# W3C Privacy Community Group — Proposal Issue

> **Title:** WTX-1: Privacy-Preserving Cross-Domain Context Preservation Without Third-Party Cookies or Fingerprinting
>
> **Repository:** [privacycg/proposals](https://github.com/privacycg/proposals/issues/new)
>
> **Copy the content below into a new GitHub issue.**

---

## Problem

Third-party cookies are being deprecated across major browsers. Site operators who need cross-domain analytics — such as understanding a user journey from `blog.example.com` to `shop.example.com` — currently have limited options:

1. **Fingerprinting** — collects hardware/software signals, declining browser support, privacy-invasive.
2. **Login-gating** — requires PII collection and account creation, excludes anonymous visitors.
3. **Third-party cookies** — deprecated/blocked, triggers consent requirements.
4. **Accepting data loss** — losing visibility into cross-domain journeys entirely.

There is no standardized, privacy-respecting mechanism for preserving pseudonymous context across navigations between cooperating domains.

## Proposed Solution: WTX-1 Protocol

WTX-1 (WaiTag Transfer Protocol, version 1) is a protocol for preserving pseudonymous context across navigations between cooperating domains, without third-party cookies, fingerprinting, or PII collection.

### How it works

1. **Pseudonymous identifiers (WaiTags):** A cryptographically random identifier is generated client-side using `crypto.getRandomValues()`. It contains no PII, no device signals, no derivable real-world identity.

2. **DNS domain authorization:** Domains must publish DNS TXT records to opt in to cross-domain identity sharing. Only domains under the same administrative control can participate — no open enrollment, no wildcards.

3. **Hash fragment token transport:** When navigating between authorized domains, a short-lived token (default: 5 minutes) is appended to the URL hash fragment. Hash fragments are *not* sent to servers in HTTP requests ([RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5)), so the destination server never sees the token passively. The client reads the fragment, sends it to a verification endpoint via a dedicated API call, and cleans up the URL.

4. **Cryptographic verification:** Tokens are HMAC-signed and verified server-side. Expired, replayed, or tampered tokens are rejected.

5. **Consent-gated degradation:** When consent is denied, the protocol degrades to fully anonymous mode — no tokens are generated, no cross-domain context is preserved, and only aggregate analytics are collected.

### What it explicitly does NOT do

- No PII collection or derivation
- No fingerprinting (no hardware, software, or behavioral signals)
- No third-party cookies or cross-domain Set-Cookie/Cookie mechanism (first-party cookie used only as local storage fallback)
- No login requirement
- No server-side cookie syncing
- No probabilistic ID matching

### Security mitigations

- **Early-cleanup script:** An inline `<head>` script strips tokens from the URL hash fragment before any other scripts (including third-party scripts) execute. The token is stashed in a short-lived JavaScript variable and the URL is cleaned via `history.replaceState()`, reducing the visibility window to near-zero.
- **Hash-only transport by default:** Query parameter token transport is disabled by default. Hash fragments are never sent to servers ([RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5)). Query parameter fallback is available as an opt-in for environments where hash fragments are unreliable, with the understanding that query parameters are visible to servers.
- **One-time-use tokens:** Each token can only be verified once server-side. Even if a token is exposed (e.g., via URL sharing before cleanup), it is invalidated after first use.
- **Short expiration:** Tokens expire after 5 minutes by default, limiting the window for any exposure.

### Remaining limitations

- **Browser extensions:** Extensions with content script access can still read the hash fragment before the early-cleanup script runs, though the short expiration and one-time-use mitigate the impact.
- **Scope:** This is an application-layer protocol, not a browser platform feature. It does not provide the same guarantees a browser-mediated mechanism could offer.

## Relationship to existing Privacy CG work

WTX-1 is complementary to several active Privacy CG proposals:

- **Bounce Tracking Protection (#6):** WTX-1 does not use redirects or bounce tracking patterns. Token transport via hash fragments is fundamentally different from redirect-based tracking.
- **Storage Access API (#41):** WTX-1 operates without third-party storage access, so it doesn't conflict with Storage Access API restrictions.
- **Third-party Cookie Heuristics (#42):** WTX-1 provides a deterministic, standards-based alternative to heuristic-based cookie access exceptions.

## Specification

An IETF Internet-Draft has been submitted: [`draft-surampudi-wtx1-00`](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)

Reference implementation (Nylo SDK): [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo) (MIT License)

Protocol specification: [github.com/tejasgit/wtx-1](https://github.com/tejasgit/wtx-1)

## Questions for the group

1. Does the Privacy CG see value in standardizing a non-cookie, non-fingerprinting mechanism for cross-domain context preservation?
2. Are there privacy concerns with the hash fragment transport mechanism that we haven't addressed?
3. Should DNS TXT record authorization be replaced or supplemented with a different domain authorization mechanism (e.g., `.well-known` endpoint)?
4. How should this interact with browser tracking prevention features (ITP, ETP, Privacy Sandbox)?

## Champion

Ravi Teja Surampudi ([@tejasgit](https://github.com/tejasgit)), Nylo Project
