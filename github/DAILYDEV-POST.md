# Project Nylo — Privacy-first cross-domain analytics without cookies or fingerprinting

Third-party cookies are dead (Safari ITP, Firefox ETP, Chrome Privacy Sandbox). If you track users across multiple domains, you've lost cross-domain identity. The alternatives — fingerprinting, login walls, PII sharing — all have serious privacy or legal problems.

**WTX-1** is an open protocol that solves this using pseudonymous identifiers and URL hash fragments.

## The core idea

Generate a random ID (WaiTag) with zero PII. When the user navigates cross-domain, pass it via hash fragment (`#nylo_token=<token>`). Hash fragments are never sent to the server per RFC 3986 — no server logs, no `Referer` headers, no network visibility.

Tokens are HMAC-signed, expire in 5 minutes, and are one-time-use with server-side replay protection. Destination domains must be pre-authorized via DNS TXT records (like SPF for email).

## What makes it different

- **No cookies** for cross-domain transport (first-party cookie only used as local storage fallback)
- **No fingerprinting** — identifier is pure cryptographic randomness
- **No PII** — WaiTag can't identify a person
- **Hash fragment transport** — invisible to servers, proxies, CDNs
- **Early-cleanup `<head>` script** — strips token from URL before third-party scripts execute
- **DNS domain authorization** — unauthorized domains can't participate
- **Consent API** with graceful degradation to fully anonymous mode

## Links

- **Protocol spec:** [github.com/tejasgit/wtx-1](https://github.com/tejasgit/wtx-1) (CC BY 4.0)
- **Reference SDK:** [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo) (MIT — zero dependencies)
- **IETF Draft:** [draft-surampudi-wtx1-01](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)
- **W3C Privacy CG proposal:** submitted for community review

## Looking for feedback on

- Security review of the threat model
- GDPR pseudonymity analysis — do WaiTags qualify as non-personal data?
- Browser vendor perspective — would hash fragment transport trigger ITP/ETP?
- Protocol design issues before standardization

Run the demo: `cd examples && npm install && npm start`
