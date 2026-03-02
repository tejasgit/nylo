# Project Nylo — I built an open protocol for cross-domain analytics without cookies or fingerprinting

Third-party cookies are dead. Safari killed them in 2017 (ITP), Firefox in 2019 (ETP), and Chrome's been slowly following with Privacy Sandbox. If you run analytics across multiple domains — a hospital site linking to a pharmacy portal, a bank linking to an investment dashboard — you've lost the ability to know the same visitor made both visits.

The existing alternatives all have problems:

| Solution | Problem |
|----------|---------|
| Browser fingerprinting | Ethically questionable, increasingly blocked, legally risky under GDPR |
| Login-based identity | Forces authentication just to be counted — excludes anonymous visitors |
| First-party data sharing | Requires business partnerships and PII exchange |
| Privacy Sandbox Topics API | Chrome-only, advertising-focused, coarse-grained |
| Adobe ECID | Same eTLD+1 only, classified as personal data under GDPR |

So I built **Nylo** — an open-source SDK and protocol (**WTX-1**) designed around a simple idea: **you don't need to know who someone is to know they visited two pages.**

---

## How it works in 30 seconds

The SDK generates a **WaiTag** — a pseudonymous identifier made from 128 bits of cryptographic randomness plus a one-way domain hash. No personal information goes in, none comes out.

When a user navigates from Domain A to Domain B:

1. Domain A requests a signed token from a verification server
2. Server checks Domain B is authorized via DNS TXT record (like SPF for email)
3. Token is appended as a **URL hash fragment**: `destination.com/page#nylo_token=<token>`
4. Domain B verifies the token server-side and restores the pseudonymous identity

The key insight: **hash fragments are never sent to the server** (RFC 3986 §3.5). No server logs, no `Referer` headers, no network visibility. The token lives only in the browser, briefly, before cleanup.

---

## The security model

This is the part I think developers will find most interesting.

### Early-cleanup inline script

The biggest risk with hash fragments is the window between page load and SDK initialization — during that time, any script can read `window.location.hash`. To close this gap, an inline `<head>` script runs before everything else:

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

This executes synchronously before tag managers, analytics, or any third-party scripts. The token is stashed in a variable and the URL is cleaned via `history.replaceState()`. By the time Google Tag Manager runs, the hash is empty.

**Honest caveat:** The stashed variable is technically accessible to any script that knows its name. But `window.location.hash` is something every script checks — an obscure variable name is not. And the token is one-time-use anyway.

### One-time-use tokens with replay protection

Every token gets a SHA-256 hash tracked server-side. Once verified, it's dead. Combined with 5-minute expiry:

- Captured tokens can't be replayed
- Shared URLs with tokens are harmless
- Browser history replay doesn't work

### Query params are opt-in only

Hash fragments are the only transport by default. Query parameter fallback (for hash-routing SPAs) requires explicit opt-in. No accidental server-side token logging.

---

## The one limitation I can't fix

Browser extensions with `"run_at": "document_start"` execute before any page JavaScript — including the early-cleanup script:

```
1. Browser parses HTML <head>
2. Extensions with "document_start" inject    ← extensions see the hash
3. Inline <head> scripts execute              ← early-cleanup runs here
```

This is unfixable at the application layer. But it's a low-severity risk because:

- **The user installed the extension.** If it has content script access, it can already read passwords, cookies, localStorage — a pseudonymous token is the least valuable target.
- **Every web protocol has this.** OAuth codes, SAML assertions, JWTs — extensions see them all. WTX-1's one-time-use + short expiry makes it harder to exploit.
- **The token has no PII.** Even if captured, the extension gets a random string and a domain name.
- **The extension has to race the SDK.** The SDK verifies within milliseconds. If the extension wins, the SDK simply fails and the user gets a fresh session.

The real fix would be a browser-native API — which is one reason I've submitted this to the W3C Privacy Community Group.

---

## What's in the spec

The full WTX-1 protocol spec covers:

- **WaiTag format** — Cryptographic construction, what it is and isn't
- **Token transport** — Hash fragments, early-cleanup, opt-in query param fallback
- **Verification** — HMAC-SHA256, replay protection, 5-minute expiry
- **DNS authorization** — TXT records, subdomain inheritance
- **Threat model** — Every attack vector with mitigations and residual risks
- **Privacy** — GDPR pseudonymity analysis, data minimization
- **Consent API** — `setConsent({ analytics: true/false })` with anonymous mode fallback

---

## Try it

```bash
git clone https://github.com/tejasgit/nylo
cd nylo/examples && npm install && npm start
# Open http://localhost:5000/demo.html
```

Zero dependencies in the client SDK. Works in all modern browsers.

---

## Links

- **GitHub (SDK):** [github.com/tejasgit/nylo](https://github.com/tejasgit/nylo) — MIT license
- **GitHub (Protocol):** [github.com/tejasgit/wtx-1](https://github.com/tejasgit/wtx-1) — CC BY 4.0
- **IETF Draft:** [draft-surampudi-wtx1-01](https://datatracker.ietf.org/doc/draft-surampudi-wtx1/)
- **W3C Privacy CG:** proposal submitted for community review

---

## Feedback welcome

I'm looking for:

- **Security review** — Attack vectors I missed?
- **Privacy analysis** — Does the GDPR pseudonymity argument hold?
- **Browser vendor take** — Would hash fragment transport trigger ITP/ETP?
- **Standards feedback** — Protocol solid enough for standardization?

Happy to answer questions in the comments.
