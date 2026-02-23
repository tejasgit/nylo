# Project Nylo: What If Cross-Domain Analytics Didn't Require Tracking People?

## The internet has a broken identity problem

Here's a scenario most product teams face: a patient visits a hospital website, reads about a procedure, and clicks through to a partner pharmacy. Two different domains. Two completely separate analytics sessions. The hospital has no idea the pharmacy visit is related.

This used to be solved by third-party cookies. A shared cookie let analytics platforms quietly connect the dots. But that era is over. Safari blocked third-party cookies in 2017. Firefox followed in 2019. Chrome is in the process of doing the same through its Privacy Sandbox initiative.

For organizations that operate across multiple domains — healthcare networks, financial services, government agencies, multi-brand retailers — this creates a real gap. The user journey doesn't stop at a domain boundary, but analytics does.

## The alternatives aren't great

The industry's response has mostly been to find new ways to identify people:

**Browser fingerprinting** builds a profile from your screen resolution, installed fonts, GPU renderer, and dozens of other signals. It works, but it's invasive by design, increasingly blocked by browsers, and carries significant legal risk under GDPR and ePrivacy regulations.

**Login-based identity** requires users to authenticate before you can track them. This works for products with logged-in experiences, but most analytics needs extend to anonymous visitors — the people browsing, comparing, exploring before they ever create an account.

**First-party data sharing** means two organizations exchange user data directly. This requires legal agreements, data processing contracts, and the exchange of personally identifiable information between parties.

All of these approaches share a common assumption: that cross-domain analytics requires knowing who the user is. I think that assumption is wrong.

## A different question

What if you could know that the same *visitor* went from site A to site B, without knowing anything about *who* they are?

That's the premise behind **Project Nylo** and its underlying protocol, **WTX-1** (WaiTag Transfer Protocol). Instead of tracking people, it tracks visits using pseudonymous identifiers that contain zero personal information.

## How WTX-1 works

When a visitor first arrives at a participating website, the Nylo SDK generates a **WaiTag** — a random identifier created from 128 bits of cryptographic randomness. It looks like this:

```
wai_0g0e161m0a0i0r0b0h0_1a2b3c4d
```

No name, no email, no device fingerprint, no IP address goes into creating this. It's pure randomness with a one-way hash of the domain name appended. You can't reverse-engineer it to identify anyone.

When the visitor clicks a link to another domain, the protocol kicks in:

**Step 1:** The origin domain requests a signed, time-limited token from a verification server.

**Step 2:** The server checks that the destination domain has opted in by publishing a DNS TXT record — similar to how email uses SPF records to verify sender domains.

**Step 3:** The token is appended to the destination URL as a hash fragment:

```
https://pharmacy.com/prescriptions#nylo_token=eyJhbGciOi...
```

**Step 4:** On the destination site, the token is verified server-side and the pseudonymous identity is restored.

The critical detail is in step 3. The token travels via a **URL hash fragment** — the part of a URL after the `#` symbol. Under the HTTP specification (RFC 3986), hash fragments are processed entirely by the browser. They are never included in HTTP requests to the server, never appear in server access logs, and never show up in `Referer` headers sent to third parties.

The token exists in the browser's address bar for a fraction of a second before being cleaned up. No server ever sees it in transit.

## Layered security, not security theater

A protocol that makes privacy claims needs to back them up technically. Here's how WTX-1 handles the hard problems:

### The visibility window

The hash fragment is visible in the URL from the moment the page starts loading until JavaScript cleans it up. During that window, any script on the page could read it.

To shrink this window to near-zero, the protocol specifies an inline cleanup script placed first in the page's `<head>`. It runs synchronously — before tag managers, before analytics scripts, before anything else — reads the token, stashes it in a temporary variable, and cleans the URL using `history.replaceState()`. By the time third-party scripts execute, the hash is already empty.

Is this perfect? No. The token sits in a JavaScript variable briefly, and a script specifically looking for that variable could find it. But the difference between a well-known API like `window.location.hash` (which many scripts routinely inspect) and an implementation-specific variable name is significant in practice. More importantly, the token is one-time-use — reading it doesn't help if you can't verify it first.

### Replay protection

Every token is hashed with SHA-256 and tracked server-side. Once it's been verified, it can never be used again. Combined with a 5-minute expiration window, this means:

- A URL shared accidentally with a token in it is harmless — the token is already consumed or expired
- Browser back-button navigation can't replay the identity transfer
- A captured token has a very narrow window of usefulness

### DNS domain authorization

Domains don't automatically participate. To receive cross-domain identities, a domain must publish a DNS TXT record proving ownership and opting in. This prevents an attacker from setting up a rogue domain to harvest tokens.

### Consent with graceful degradation

The SDK includes a consent API. When consent is denied, no WaiTag is generated, no tokens are created, and only anonymous aggregate analytics are collected. The system doesn't break — it degrades to a privacy-maximizing mode.

## The honest limitation

There is one attack vector the protocol cannot fully mitigate, and I think it's important to be transparent about it.

Browser extensions that request early execution access (`"run_at": "document_start"`) can inject JavaScript before any page scripts run — including the cleanup script. At that moment, the extension can read the hash fragment.

This is a fundamental constraint of the browser extension model, not a flaw in the protocol. Every web-based authentication and identity system — OAuth, SAML, JWT — is subject to the same limitation. An extension with content script access can read anything on the page.

What limits the practical impact:

- The user chose to install the extension. It already has access to everything on the page — passwords, form data, cookies. A pseudonymous token adds negligible value.
- The token contains no personally identifiable information.
- The token is one-time-use. The extension would have to race the SDK to verify it first, and the SDK typically wins that race within milliseconds.
- Even if the extension captures and verifies the token, all it learns is that a random identifier visited two domains. It can't tie that to a real person.

The only complete fix would be a browser-native API that mediates the transfer without exposing the token to any JavaScript. That's one of the reasons I've submitted this protocol to the W3C Privacy Community Group — to begin a conversation about what browser-native support could look like.

## Open source, open protocol

The Nylo SDK is MIT-licensed for core single-domain tracking. The cross-domain identity features (WaiTag transfer, DNS verification) require a commercial license for production use, but are free for development and testing. The WTX-1 protocol specification itself is published under CC BY 4.0.

The SDK is zero-dependency — a single JavaScript file that works in all modern browsers. You can have the demo running in under a minute:

```bash
git clone https://github.com/tejasgit/nylo
cd nylo/examples && npm install && npm start
```

## Where it stands

- The protocol specification is published at [github.com/tejasgit/wtx-1](https://github.com/tejasgit/wtx-1)
- The reference implementation is at [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo)
- An IETF Internet-Draft has been submitted ([draft-surampudi-wtx1-00](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/))
- A proposal has been submitted to the W3C Privacy Community Group

I'm actively looking for security review, privacy analysis, and feedback from anyone working in browser privacy, web standards, or analytics infrastructure. If the GDPR pseudonymity argument has holes, I'd rather find them now. If there are attack vectors I've missed, I want to know.

The protocol is designed to be an open standard, not a proprietary solution. The more scrutiny it gets, the better it becomes.

---

*Ravi Teja Surampudi is the creator of Project Nylo and the WTX-1 protocol. The project is open for contributions at [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo).*
