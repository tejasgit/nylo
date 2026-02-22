# I built a cross-domain analytics protocol that works without third-party cookies, fingerprinting, or login walls

Third-party cookies are dying. Safari killed them in 2017 (ITP), Firefox in 2019 (ETP), and Chrome's been slowly following with Privacy Sandbox. If you run analytics across multiple domains — say a hospital site that links to a pharmacy portal, or a bank that links to an investment dashboard — you've lost the ability to know the same person visited both.

The existing alternatives are all terrible:

- **Browser fingerprinting**: Ethically gross, increasingly blocked, legally radioactive under GDPR
- **Login-based identity**: Forces users to authenticate just to be counted — excludes everyone who's just browsing
- **First-party data sharing**: Requires business partnerships and PII exchange between organizations
- **Privacy Sandbox Topics API**: Chrome-only, advertising-focused, coarse-grained
- **Adobe ECID**: Only works on same eTLD+1, classified as personal data under GDPR

So I built **WTX-1** — an open protocol for cross-domain identity that's designed around a simple idea: **you don't need to know who someone is to know they visited two pages.**

---

## How it works

The protocol generates a **WaiTag** — a pseudonymous identifier made from 128 bits of cryptographic randomness plus a one-way domain hash. No personal information goes in, none comes out. Format: `wai_<random_base36>_<domain_hash>`.

When a user navigates from Domain A to Domain B:

1. Domain A's SDK requests a signed, time-limited token from a verification server
2. The server checks that Domain B is authorized via a DNS TXT record (like email SPF records)
3. The token gets appended to the URL as a **hash fragment**: `destination.com/page#nylo_token=<token>`
4. Domain B reads the token, verifies it server-side, and restores the pseudonymous identity

The key technical decision: **hash fragments are never sent to the server** (RFC 3986 §3.5). They don't appear in HTTP requests, server logs, `Referer` headers, or network traffic. The token exists only in the browser's address bar, briefly, before it's cleaned up.

---

## The security model I'm most proud of

The protocol uses layered defenses that I think are genuinely interesting from a security perspective:

### Early-cleanup inline script

The biggest risk with hash fragment transport is the window between page load and SDK initialization — during that time, any JavaScript on the page can read `window.location.hash`. To fix this, I spec'd an inline `<head>` script that runs before any other scripts:

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

This runs synchronously before tag managers, analytics scripts, or anything else. The token gets stashed in a variable and the URL is cleaned via `history.replaceState()`. By the time Google Tag Manager or any third-party script executes, the hash is empty.

**Honest caveat:** The stashed variable (`window.__nylo_early_token`) is technically readable by any script that knows its name. But `window.location.hash` is a well-known property every script checks — an implementation-specific variable name is not. And the token is one-time-use anyway.

### One-time-use tokens with replay protection

The server tracks consumed token hashes (SHA-256) and rejects any token that's already been verified. Combined with a 5-minute expiry, this means:

- Captured tokens can't be replayed
- Shared URLs with tokens are harmless (token's already been used or expired)
- Browser history replay doesn't work

### Query params are opt-in only

Hash fragments are the only transport by default. Query parameter fallback (for hash-routing SPAs) requires explicit opt-in via `data-allow-query-params="true"`. This prevents accidental server-side logging of tokens.

---

## The one thing I can't fix (and why I'm honest about it)

Browser extensions with `"run_at": "document_start"` in their manifest execute before any page JavaScript — including the early-cleanup script. The browser's execution order is:

```
1. Browser parses HTML <head>
2. Extensions with "document_start" inject content scripts  ← here
3. Inline <head> scripts execute                            ← early-cleanup runs here
4. Everything else
```

An extension at step 2 can read the hash before step 3 cleans it. This is unfixable at the application layer.

But here's why I don't lose sleep over it:

1. **The user installed the extension.** An extension with content script access on all pages can already read passwords, form data, cookies, localStorage — everything. A pseudonymous analytics token is the least valuable thing it could steal.

2. **Every web protocol has this problem.** OAuth redirect codes, SAML assertions, JWTs in localStorage — extensions can see all of them. WTX-1's one-time-use + 5-minute expiry actually makes it *harder* to exploit than most of these.

3. **The token contains no PII.** Even if intercepted and somehow verified, the extension gets a random string and a domain name. It can't identify anyone.

4. **The extension has to race the SDK.** The SDK verifies the token within milliseconds. If the extension submits first, the SDK's request simply fails and the user gets a fresh session. No data leaks.

The only real fix would be a browser-native API like `navigator.crossDomainContext.receive()` that handles token transport internally without exposing it to any JavaScript. That's one of the reasons I submitted this to the W3C Privacy Community Group — to start a conversation about browser-native support.

---

## What the spec covers

The full protocol spec ([github.com/tejasgit/wtx-1](https://github.com/tejasgit/wtx-1)) covers:

- **WaiTag format and generation** — Cryptographic construction, collision resistance, what it is and isn't
- **Token transport** — Hash fragments, early-cleanup script, opt-in query param fallback
- **Token verification** — HMAC-SHA256 signatures, replay protection, expiry, DNS domain authorization
- **DNS authorization** — TXT record format, verification flow, subdomain inheritance
- **Client-side storage** — Three-layer strategy (cookie/localStorage/sessionStorage), ITP impact
- **Complete threat model** — Every attack vector I could think of, with mitigations and honest residual risk assessments
- **Privacy considerations** — GDPR pseudonymity analysis, data minimization, consent model
- **Consent API** — `setConsent({ analytics: true/false })` with graceful degradation to anonymous mode

---

## The licensing split

The SDK ([github.com/tejasgit/nylo](https://github.com/tejasgit/nylo)) is dual-licensed:

- **MIT** — Core single-domain tracking, event batching, all the basics. Free for any use.
- **Commercial** — Cross-domain identity (WaiTag transfer, DNS verification, encrypted config). Free for development and testing; commercial license required for production cross-domain features.

The protocol spec itself is CC BY 4.0.

---

## What I'm looking for

I'm not looking for stars or hype. I'm genuinely looking for:

1. **Security review** — Are there attack vectors I missed? Is the threat model realistic?
2. **Privacy analysis** — Does the GDPR pseudonymity argument hold up? I believe WaiTags aren't personal data under normal use, but they become personal data if you build a mapping table — is this framing accurate?
3. **Browser vendor perspective** — Would this actually trigger ITP/ETP heuristics? The protocol doesn't use third-party cookies, redirects, or bounce tracking, but hash fragment transport is novel enough that I'm not sure how Safari would classify it.
4. **Standards feedback** — I've submitted proposals to the W3C Privacy CG and drafted an IETF Internet-Draft. Is the protocol solid enough to justify standardization, or are there fundamental design issues?

The reference implementation is zero-dependency, works in all modern browsers, and you can run the demo with `npm start` in the examples directory.

**Protocol spec:** [github.com/tejasgit/wtx-1](https://github.com/tejasgit/wtx-1)
**Reference implementation:** [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo)
**IETF Draft:** [draft-surampudi-wtx1-00](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)

Happy to answer any questions about the protocol design, the security model, or the standards submission process.
