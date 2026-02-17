# Nylo Licensing

Nylo uses a **dual-license model**. The core tracking SDK is fully open source under the MIT License — free for personal **and** commercial use, no restrictions. Cross-domain identity features (WTX-1 protocol, WaiTag system) require a commercial license for production commercial use.

## MIT License — Core Tracking (Free for Everyone)

Everything needed for single-domain analytics is MIT-licensed with no restrictions:

- **Client SDK** (`src/nylo.js`) — event tracking, page views, clicks, forms, scroll depth, conversions, batching, retry logic, performance monitoring
- **Server integration** (`server/api/tracking.ts`) — batch event ingestion API
- **Input validation and security utilities** (`server/utils/`) — sanitization, XSS prevention
- **Examples** (`examples/`) — demo app, basic integration, server setup

You can use, modify, distribute, and build commercial products with these components. No license fee, no attribution requirement beyond the standard MIT notice. See [LICENSE](LICENSE).

## Commercial License — Cross-Domain Identity Features

Cross-domain identity features are covered by patent-pending claims and require a commercial license for production commercial use:

| Feature | Files | Description |
|---------|-------|-------------|
| **WTX-1 Protocol** | `src/nylo.js` (CrossDomainIdentity module) | Cross-domain token exchange and verification |
| **WaiTag System** | `src/nylo.js` (Security.generateWaiTag), `server/api/waitag-tracking.ts` | Pseudonymous identifier generation and registration |
| **Cross-Domain Sync** | `server/api/tracking-sync.ts` | Identity synchronization across domains |
| **Encrypted Configuration** | `src/nylo.js` (parseEncryptedConfig) | AES-GCM encrypted feature toggles |
| **DNS Domain Verification** | `server/api/dns-verify.ts`, `server/utils/dns-verification.ts` | Domain ownership verification for cross-domain auth |

### When You Need a Commercial License

- Using cross-domain features in a commercial product or service (paid or free)
- Internal business use of cross-domain features processing more than 10,000 events/month
- Integrating cross-domain features into a proprietary analytics platform

### When You Don't

- **Using core tracking for any purpose** — personal, commercial, enterprise (MIT, always free)
- Personal or non-commercial use of cross-domain features
- Academic research and education
- Evaluation and testing in non-production environments
- Open-source projects with fewer than 10,000 monthly events
- Contributing improvements back to Nylo

See [COMMERCIAL-LICENSE](COMMERCIAL-LICENSE) for full terms.

## Quick Reference

| What you're doing | License | Cost |
|-------------------|---------|------|
| Single-domain tracking (personal or commercial) | MIT | Free |
| Single-domain tracking in a SaaS product | MIT | Free |
| Cross-domain features for personal/academic use | Commercial (free tier) | Free |
| Cross-domain features for evaluation/testing | Commercial (free tier) | Free |
| Cross-domain features in commercial production | Commercial | [Contact us](mailto:hello@waifind.com) |
| Integrating WTX-1 into your product | Commercial | [Contact us](mailto:hello@waifind.com) |

## Contact

For licensing questions, pricing, or enterprise inquiries:

**Email:** hello@waifind.com
