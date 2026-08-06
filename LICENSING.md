# Nylo Licensing

> **⚠️ Provisional:** This licensing structure has **not yet been reviewed by an attorney**. Attorney review is a required open action before any commercial licensing activity. Until then, treat the MIT/commercial boundary described here as provisional.

Nylo uses a **dual-license model**. The npm package as a whole is therefore **not plain MIT** — `package.json` declares `"license": "SEE LICENSE IN LICENSING.md"`, and every source file carries an SPDX header identifying its license. The core tracking SDK is fully open source under the MIT License — free for personal **and** commercial use, no restrictions. Cross-domain identity features (WTX-1 protocol, WaiTag system) require a commercial license for production commercial use.

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

## File-by-File License Boundary

SPDX identifiers used:

- `MIT` — standard MIT License ([LICENSE](LICENSE))
- `LicenseRef-Nylo-Commercial` — Nylo Commercial License ([COMMERCIAL-LICENSE](COMMERCIAL-LICENSE))
- `LicenseRef-Nylo-Dual` — a mixed-license file: the core tracking modules are offered under the MIT License, while the cross-domain identity modules within the same file (CrossDomainIdentity, WaiTag generation in `Security.generateWaiTag`, and `parseEncryptedConfig`) are offered only under the Nylo Commercial License. Splitting these modules into separate files (so each file carries a single license) is a planned improvement and part of the pending attorney review.

| File | SPDX License |
|------|--------------|
| `src/nylo.js` | `LicenseRef-Nylo-Dual` (see definition above — module-level boundary within one file) |
| `server/index.ts` | `MIT` |
| `server/api/tracking.ts` | `MIT` |
| `server/api/waitag-tracking.ts` | `LicenseRef-Nylo-Commercial` |
| `server/api/dns-verify.ts` | `LicenseRef-Nylo-Commercial` |
| `server/utils/dns-verification.ts` | `LicenseRef-Nylo-Commercial` |
| `server/utils/token-core.js` (+ `.d.ts`) | `LicenseRef-Nylo-Commercial` |
| `server/utils/secure-id.ts` | `MIT` |
| `server/utils/input-validation.ts` | `MIT` |
| `server/utils/security.ts` | `MIT` |
| `server/utils/security-core.js` (+ `.d.ts`) | `MIT` |
| `shared/**` | `MIT` |
| `examples/**` (source files) | `MIT` |
| `test/**` and `tests/**` | `MIT` |
| `docs/*.md` (WTX-1 spec, RFC, W3C, PEARG documents) | CC BY 4.0 (noted in each document) |
| `docs/ietf/**` (Internet-Draft artifacts) | IETF Trust legal provisions (BCP 78/79), as stated in each draft |

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
