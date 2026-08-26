<p align="center">
  <strong>Nylo</strong><br>
  Privacy-first cross-domain analytics. No third-party cookies. No login. No direct identifiers collected by default.
</p>

<p align="center">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-MIT%20%2B%20Commercial-blue.svg" alt="Dual License"></a>
  <img src="https://img.shields.io/badge/status-experimental-orange" alt="Experimental">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/client_SDK-~12KB-green" alt="SDK size">
</p>

---

> **⚠️ Experimental / pre-alpha.** Nylo is under active development and has not completed its security and compliance hardening backlog. Do not use it in production, especially in regulated environments, until a stable release is published.

---

Google killed third-party cookies. Your cross-domain analytics broke. The industry says you have two options: force users to log in (UID 2.0, LiveRamp) or lose individual-level data (Google Topics API).

**Nylo is a third option.** It tracks user behavior across your domains using pseudonymous identifiers. No third-party cookies, no fingerprinting, and no direct identifiers (name, email, IP address) collected by default. Note that pseudonymous identifiers are still considered personal data under regulations such as the GDPR — pseudonymous is not anonymous — so consent and compliance obligations still apply.

## What Nylo Is / Is Not

| | |
|---|---|
| **Is** | Pseudonymous continuity across domains without login or direct identifiers |
| **Is** | A zero-dependency client SDK (~12KB) with server-side event ingestion |
| **Is** | Privacy-by-design: all 23 event-tracking features default to **off**, and nothing runs until you call `Nylo.setConsent({ analytics: true })`. Note: once consent is granted, the SDK establishes and persists a pseudonymous WaiTag and processes incoming cross-domain tokens even if no event features are enabled |
| **Is not** | Fingerprinting users (no canvas, font, WebGL, or device fingerprints) |
| **Is not** | Storing IP addresses or resolving identity to a person by default (`identify()` can link a user ID — see below) |
| **Is not** | A replacement for consent — pseudonymous identifiers are personal data under GDPR, and Nylo is fail-closed: it does not track without explicit consent |
| **Works best when** | You control the collection server and verify domains via DNS TXT |
| **Works best when** | You need cross-domain analytics without forcing user login |

## How It Works

```
User visits site-a.com        User clicks to site-b.com
        |                              |
   +----v----+                    +----v----+
   |  Nylo   |   token exchange   |  Nylo   |
   |  SDK    | ------------------>|  SDK    |
   |         |   (pseudonymous)   |         |
   +----+----+                    +----+----+
        |                              |
        v                              v
   Same pseudonymous ID on both domains
   No direct identifiers. No login. No third-party cookies.
```

The SDK generates a **WaiTag** -- a pseudonymous identifier derived by hashing (SHA-256) a 128-bit cryptographically random value together with a timestamp and a domain-specific salt. Only the digest becomes the identifier — it embeds no readable timestamp and no reversible domain marker, and no personal information is used as an input, so the identifier cannot on its own be reverse-engineered to a person. It is **pseudonymous, not anonymous**: it persists across sessions (via a first-party cookie, localStorage, and sessionStorage), and if you call `Nylo.identify()` it becomes linked to your application-level user ID. When a user navigates between your domains, a secure token exchange preserves the identifier so you get unified analytics across properties.

## Quick Start

### 1. Add the script tag

```html
<script src="https://your-server.com/nylo.js" data-customer-id="1" async></script>
```

The SDK initializes automatically but is **fail-closed**: no events are tracked, no identifiers are stored, and no cross-domain sync occurs until consent is granted:

```javascript
Nylo.setConsent({ analytics: true });
```

After consent is granted, the SDK (a) generates/restores and persists the pseudonymous WaiTag, registers it with your server, and processes incoming cross-domain tokens — this identity layer is active regardless of feature toggles — and (b) tracks only the event types you enable via feature configuration (all 23 default off).

### 2. Use the API

```javascript
Nylo.track('signup_click', { plan: 'pro' });

Nylo.trackConversion('purchase', 49.99);

Nylo.getSession();
// { sessionId, waiTag, userId, customerId, queueSize, crossDomainSynced }

// identify() links the pseudonymous WaiTag to YOUR user ID. After this call the
// identifier is no longer merely pseudonymous from your perspective — the linked
// data is personal data and requires an appropriate lawful basis. Requires consent.
Nylo.identify('user-123');

Nylo.flush();

Nylo.getMetrics();

Nylo.getFeatures();

// Privacy controls — expose these to your users:
Nylo.getStoredContext();  // view everything stored in this browser, incl. expiry
Nylo.resetContext();      // delete stored identity, mint a fresh unlinked one
Nylo.revokeContext();     // withdraw consent: stop tracking, purge all data

Nylo.destroy();
```

The SDK also dispatches a `nyloContextPreserved` event on `window` whenever
context is restored (from first-party storage or across domains), so pages can
show users a visible context-continuity indicator:

```javascript
window.addEventListener('nyloContextPreserved', (e) => {
  // e.detail: { source: 'first_party_storage' | 'cross_domain', waiTag, preservedAt, ... }
});
```

### 3. Set up the server

```typescript
import express from 'express';
import { setupNyloRoutes } from 'nylo/server';

const app = express();
app.use(express.json());

const storage = new YourStorageImplementation();
setupNyloRoutes(app, storage);

app.listen(3000);
```

The server needs a storage implementation that satisfies this interface:

```typescript
interface NyloStorage {
  createInteraction(data: any): Promise<any>;
  getCustomer(id: number): Promise<any>;
  getCustomerByApiKey(apiKey: string): Promise<any>;
  parseDomain(domain: string): { mainDomain: string; subdomain: string | null };

  // DNS domain verification (required for cross-domain features)
  getDomainVerification(domain: string, customerId: number): Promise<any | null>;
  createDomainVerification(data: { domain: string; customerId: number; token: string; status: string }): Promise<any>;
  updateDomainVerification(domain: string, customerId: number, data: any): Promise<any>;
  isDomainVerified(domain: string, customerId: number): Promise<boolean>;
}
```

See the [examples/](examples/) folder for a complete working setup:

```bash
git clone https://github.com/tejasgit/nylo.git
cd nylo

# Interactive demo with live event dashboard
cd examples && npm install && npm start
# Open http://localhost:5000/demo.html

# Minimal example (requires tsx and root dependencies)
cd .. && npm install
npx tsx examples/server.ts
# Open http://localhost:3000/basic.html
```

## What Gets Tracked

23 event types, each individually toggled. All 23 default to **off**, and nothing is tracked until explicit consent is granted via `Nylo.setConsent({ analytics: true })` (fail-closed by design). Note that the `trackCrossDomain` toggle gates cross-domain *event reporting* only — once consent is granted, WaiTag identity persistence and cross-domain token verification are active independently of these feature toggles:

| Category | Events |
|----------|--------|
| Navigation | Page views, link clicks, external links, referrers |
| Interaction | Clicks, buttons, forms, hovers, scroll depth |
| Media | Video interactions, file downloads |
| Search | On-site search queries |
| Performance | Page load timing, element visibility |
| Engagement | Bounce rate, return visitors, user engagement |
| Conversion | Custom conversions with value tracking |
| Identity | Cross-domain sync, return visitors |

## Architecture

```
nylo/
├── src/
│   └── nylo.js                    # Client SDK (~1,000 lines, zero dependencies)
├── server/
│   ├── index.ts                   # Express.js integration entry point
│   ├── api/
│   │   ├── tracking.ts            # Batch event ingestion
│   │   ├── waitag-tracking.ts     # WaiTag registration + cross-domain verification
│   │   └── dns-verify.ts          # DNS TXT record domain ownership verification
│   └── utils/
│       ├── secure-id.ts           # Cryptographic ID generation
│       ├── input-validation.ts    # Input validation
│       ├── security.ts            # XSS prevention, origin validation
│       └── dns-verification.ts    # DNS TXT record domain verification
├── examples/
│   ├── demo.html                  # Interactive demo dashboard
│   ├── demo-server.js             # Self-contained Express demo server
│   ├── demo-server-sqlite.js      # Demo server with SQLite persistence
│   ├── storage-sqlite.js          # SQLite reference storage adapter
│   ├── demo-server-postgres.js    # Demo server with PostgreSQL persistence
│   ├── storage-postgres.js        # PostgreSQL reference storage adapter
│   ├── basic.html                 # Minimal client-side integration
│   └── server.ts                  # TypeScript Express server example
├── docs/
│   ├── WTX-1-SPEC.md              # WTX-1 protocol specification
│   ├── RFC-0001.md                # Draft RFC
│   ├── W3C-EXPLAINER.md           # W3C-format explainer
│   └── ietf/                      # IETF Internet-Draft files
├── LICENSE                        # MIT License
├── COMMERCIAL-LICENSE             # Commercial License for cross-domain features
├── LICENSING.md                   # MIT vs commercial scope breakdown
└── SECURITY.md                    # Security policy and vulnerability reporting
```

### Client-Side Modules

- **Security** -- Input sanitization (HTML entity encoding, 1,000-char limits, XSS prevention)
- **Cross-Domain Identity** -- WTX-1 protocol: token exchange, WaiTag generation, three-layer storage (cookie, localStorage, sessionStorage)
- **Event Batching** -- Queues events and dispatches in configurable batches. Compression reduces payload by extracting common fields
- **Retry & Circuit Breaker** -- Exponential backoff (1s, 2s, 4s) with circuit breaker (30s cooldown after 3 failures)
- **Encrypted Configuration** -- AES-GCM encrypted feature toggles via `data-config` attribute
- **Performance Monitoring** -- Self-monitoring via the browser Performance API

### Privacy Properties

The WaiTag identifier is **pseudonymous** and satisfies four structural properties:

1. **No direct identifiers as input** -- No component is derived from personal information. Random entropy comes from the Web Crypto API.
2. **Non-reversibility by default** -- Nylo maintains no server-side mapping to a personal identity. Calling `Nylo.identify()` creates such a linkage; disclose it and secure a lawful basis before using it.
3. **Behavioral consistency** -- Persists across sessions via a three-layer storage hierarchy (first-party cookie `nylo_wai`, localStorage, sessionStorage). Because it persists and singles out a browser, it is personal data under GDPR-style regimes.
4. **Unilateral deletion** -- Clearing browser storage destroys the identifier. No server coordination needed.
5. **Time-limited by default** -- Stored identifiers expire automatically: 180 days after creation, or after 30 days without use (both configurable). Expired records are deleted on read, never resurrected. Users can inspect (`getStoredContext()`), reset (`resetContext()`), or revoke (`revokeContext()`) their stored context at any time.

No IP addresses are stored. No user agents, languages, timezones, screen/viewport dimensions, or click coordinates are collected — fingerprint-capable fields are absent from the SDK's payloads and additionally stripped server-side as defense in depth. URLs are reduced to origin + path before transmission and storage; query strings and fragments (which routinely carry tokens, emails, and search terms) are discarded unless a parameter is explicitly allowlisted. All strings are sanitized and length-limited. Nylo does not reduce your consent obligations — obtain consent where the law requires it; the SDK will not track until you signal consent via `Nylo.setConsent()`.

### Write Authorization

Browsers never assert who they are. Tenant identity is resolved **server-side**: the SDK requests a short-lived signed **write grant** from `POST /api/tracking/grant` for the page's domain, and the server maps that domain to a tenant using its own configuration (`getTenantIdForDomain`). Every ingestion, registration, and token-verification request carries the grant in the `X-Nylo-Grant` header. Grants are domain- and scope-bound (`ingest`, `register`), expire after 10 minutes, and are signed with `NYLO_TOKEN_SECRET`. Customer IDs supplied by a browser are never trusted — a conflicting `customerId` is rejected, not reassigned.

## Domain Verification

Nylo uses DNS TXT records to verify domain ownership before allowing cross-domain tracking. This is the same pattern used by Google Search Console and Stripe -- you prove you own a domain by adding a DNS record.

### How It Works

All three endpoints authenticate with your API key (`X-API-Key` header).
Customer IDs in a request body are never accepted as authentication.

```
1. Request verification token
   POST /api/domains/request-verification    (X-API-Key: <your key>)
   { "domain": "example.com" }
   → { "token": "a1b2c3...", "dnsRecord": { "type": "TXT", "value": "nylo-verify=a1b2c3..." } }

2. Add TXT record to your DNS
   example.com  TXT  "nylo-verify=a1b2c3..."

3. Trigger verification
   POST /api/domains/verify                  (X-API-Key: <your key>)
   { "domain": "example.com" }
   → { "status": "verified", "method": "direct_txt" }

4. Check status anytime
   GET /api/domains/status?domain=example.com   (X-API-Key: <your key>)
   → { "status": "verified", "verifiedAt": "2026-02-17T..." }
```

### Subdomain Inheritance

Subdomains inherit verification from their parent domain. If `example.com` is verified in storage, `blog.example.com` is automatically authorized. The server first checks the subdomain's own TXT record, then falls back to checking the parent domain's verification status.

### Enforcement

Cross-domain token verification (`/api/tracking/verify-cross-domain-token`) checks DNS verification status when `isDomainVerified` is implemented in your storage. Unverified domains receive a `403` response and cannot use cross-domain identity features. Single-domain tracking works without domain verification.

## Cross-Domain Setup

To track users across `site-a.com` and `site-b.com`:

1. Verify both domains via DNS TXT records (see above)
2. Deploy Nylo on both domains pointing to the same server
3. Configure the domain allowlist in your encrypted configuration
4. The SDK handles token exchange automatically when users navigate between domains

Tokens travel in the URL **hash fragment** (never sent to servers or logged; query-parameter transport is a separate explicit opt-in). Each token is encrypted **and** signed (WTX-1 token format v2: HMAC-SHA256 signature sealed inside AES-256-GCM, keys derived per tenant + destination domain), expires after 5 minutes, and is single-use.

## Configuration

### Script Attributes

| Attribute | Required | Description |
|-----------|----------|-------------|
| `data-customer-id` | No | Local key for encrypted-config decryption and storage-integrity HMAC only. **Never used as tenant identity** — the server derives the tenant from signed write grants |
| `data-api` | No | Custom API endpoint URL (defaults to script origin) |
| `data-config` | No | AES-GCM encrypted feature configuration |
| `data-security` | No | Encrypted domain authorization allowlist |
| `data-debug` | No | Enable console logging (`"true"` / `"false"`) |
| `data-embed-id` | No | Embed identifier for multi-instance deployments |
| `data-allowed-params` | No | Comma-separated allowlist of query parameters to collect (everything else never leaves the browser) |
| `data-allow-query-params` | No | Opt in to query-parameter token transport (`"true"`; default is hash-fragment only) |
| `data-identity-max-age-days` | No | Absolute lifetime of a stored identifier in days (default `180`, max `3650`) |
| `data-identity-unused-expiry-days` | No | Days without use before a stored identifier expires (default `30`, max `3650`) |

### Batch Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Batch size | 25 events | Events per batch dispatch |
| Batch interval | 12 seconds | Time between dispatches |
| Max retries | 3 | Retries before circuit breaker |
| Circuit breaker cooldown | 30 seconds | Cooldown after max retries |

### Server Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `TRACKING_DEDUP_WINDOW_SECONDS` | `60` | Time window in seconds for server-side event deduplication |

## Browser Support

| Browser | Version | Notes |
|---------|---------|-------|
| Chrome | 80+ | Full support |
| Firefox | 78+ | Full support |
| Safari | 14+ | Full support; localStorage may be partitioned under ITP |
| Edge | 80+ | Full support |

Requires Web Crypto API and localStorage. Falls back gracefully when storage layers are unavailable.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities responsibly.

## License

Nylo is **dual-licensed** — the package as a whole is *not* plain MIT. Every source file carries an SPDX header identifying its license. See [LICENSING.md](LICENSING.md) for the full file-by-file breakdown of what's MIT vs commercial. The licensing structure has not yet undergone attorney review; treat the boundary as provisional until it does.

**MIT License** -- Core tracking (page views, clicks, forms, events, batching, retry logic). Free for personal **and** commercial use, no restrictions.

**Commercial License** -- Cross-domain identity features only (WTX-1 protocol, WaiTag system, encrypted configuration, domain authorization). Required for production commercial use. Free for personal, academic, and evaluation use.

| Use Case | License | Cost |
|----------|---------|------|
| Single-domain tracking (personal or commercial) | MIT | Free |
| Single-domain tracking in a SaaS product | MIT | Free |
| Cross-domain features for personal/academic use | Commercial (free tier) | Free |
| Cross-domain features in commercial production | Commercial | [Contact us](mailto:hello@waifind.com) |
| Integrating WTX-1 into your product | Commercial | [Contact us](mailto:hello@waifind.com) |

For licensing inquiries: hello@waifind.com

## Academic Research

Nylo's cross-domain identity system is the subject of peer-reviewed research:

> **Pseudonymous Sufficiency as Decision Support Infrastructure: A Design Science Approach to Privacy-Preserving Cross-Domain Marketing Analytics**
>
> Manuscript submitted to *Decision Support Systems* (IF 6.8). The paper introduces pseudonymous sufficiency as a mid-range design theory specifying when pseudonymous identifiers are analytically equivalent to personal identifiers for marketing decision support.

The cross-domain identity technology is the subject of a U.S. Non-Provisional Patent Application.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. By contributing, you agree that your contributions will be licensed under the MIT License.
