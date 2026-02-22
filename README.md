<p align="center">
  <strong>Nylo</strong><br>
  Privacy-first cross-domain analytics. No third party cookies. No login. No PII.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/client_SDK-~12KB-green" alt="SDK size">
</p>

---

Google killed third-party cookies. Your cross-domain analytics broke. The industry says you have two options: force users to log in (UID 2.0, LiveRamp) or lose individual-level data (Google Topics API).

**Nylo is a third option.** It tracks user behavior across your domains using pseudonymous identifiers that never resolve to personal information. No third party cookies, no fingerprinting, no PII. Individual-level resolution without knowing who anyone is.

## What Nylo Is / Is Not

| | |
|---|---|
| **Is** | Pseudonymous continuity across domains without login or PII |
| **Is** | A zero-dependency client SDK (~12KB) with server-side event ingestion |
| **Is** | Privacy-by-design: all 23 tracking features default to **off** |
| **Is not** | Fingerprinting users (no canvas, font, WebGL, or device fingerprints) |
| **Is not** | Storing IP addresses or resolving identity to a person |
| **Is not** | A replacement for consent — it reduces the *need* for it |
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
   No PII. No login. No third-party cookies.
```

The SDK generates a **WaiTag** -- a pseudonymous identifier built from a timestamp, cryptographic random bytes, and a one-way domain hash. It contains zero personal information and cannot be reverse-engineered to identify anyone. When a user navigates between your domains, a secure token exchange preserves the identifier so you get unified analytics across properties.

## Quick Start

### 1. Add the script tag

```html
<script src="https://your-server.com/nylo.js" data-customer-id="1" async></script>
```

That's it. The SDK initializes automatically and starts tracking page views and clicks.

### 2. Use the API

```javascript
Nylo.track('signup_click', { plan: 'pro' });

Nylo.trackConversion('purchase', 49.99);

Nylo.getSession();
// { sessionId, waiTag, userId, customerId, queueSize, crossDomainSynced }

Nylo.identify('user-123');

Nylo.flush();

Nylo.getMetrics();

Nylo.getFeatures();

Nylo.destroy();
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

23 event types, each individually toggled. All default to **off** (privacy by design):

| Category | Events |
|----------|--------|
| Navigation | Page views, link clicks, external links, referrers |
| Interaction | Clicks, buttons, forms, hovers, scroll depth |
| Media | Video interactions, file downloads |
| Search | On-site search queries |
| Performance | Page load timing, element visibility |
| Engagement | Bounce rate, return visitors, user engagement |
| Conversion | Custom conversions with value tracking |
| Identity | Cross-domain sync, device info, browser info |

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
│   │   ├── tracking-sync.ts       # Cross-domain identity synchronization
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

The WaiTag identifier satisfies four structural privacy guarantees:

1. **PII absence** -- No component derived from personal information. Random entropy from Web Crypto API.
2. **Non-reversibility** -- No server-side mapping to personal identity. Cannot be linked to a person.
3. **Behavioral consistency** -- Persists across sessions via three-layer storage hierarchy.
4. **Unilateral deletion** -- Clearing browser storage destroys the identifier. No server coordination needed.

No IP addresses are stored. User agents are hashed. All strings are sanitized and length-limited.

## Domain Verification

Nylo uses DNS TXT records to verify domain ownership before allowing cross-domain tracking. This is the same pattern used by Google Search Console and Stripe -- you prove you own a domain by adding a DNS record.

### How It Works

```
1. Request verification token
   POST /api/domains/request-verification
   { "domain": "example.com", "customerId": 1 }
   → { "token": "a1b2c3...", "dnsRecord": { "type": "TXT", "value": "nylo-verify=a1b2c3..." } }

2. Add TXT record to your DNS
   example.com  TXT  "nylo-verify=a1b2c3..."

3. Trigger verification
   POST /api/domains/verify
   { "domain": "example.com", "customerId": 1 }
   → { "status": "verified", "method": "direct_txt" }

4. Check status anytime
   GET /api/domains/status?domain=example.com&customerId=1
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

The token exchange uses URL parameters (primary) or `postMessage` (iframe fallback). Tokens expire after 5 minutes. All exchanges are audit-logged.

## Configuration

### Script Attributes

| Attribute | Required | Description |
|-----------|----------|-------------|
| `data-customer-id` | Yes | Your customer/organization identifier |
| `data-api` | No | Custom API endpoint URL (defaults to script origin) |
| `data-config` | No | AES-GCM encrypted feature configuration |
| `data-security` | No | Encrypted domain authorization allowlist |
| `data-debug` | No | Enable console logging (`"true"` / `"false"`) |
| `data-embed-id` | No | Embed identifier for multi-instance deployments |

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

Nylo is dual-licensed. See [LICENSING.md](LICENSING.md) for the full breakdown of what's free vs commercial.

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
