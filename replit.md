# Nylo SDK

## Overview
Nylo is a privacy-first cross-domain analytics SDK. It tracks user behavior across multiple domains using pseudonymous identifiers (WaiTags) without cookies, fingerprinting, or PII collection. The project is dual-licensed: MIT for core tracking, commercial license for cross-domain identity features.

## Project Architecture

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
│   ├── basic.html                 # Minimal client-side integration
│   └── server.ts                  # TypeScript Express server example
├── LICENSE                        # MIT License
└── COMMERCIAL-LICENSE             # Commercial License for cross-domain features
```

## Key Components

### Client SDK (src/nylo.js)
- Zero-dependency browser script loaded via `<script>` tag
- Generates WaiTag pseudonymous identifiers
- Batches events and dispatches to server
- Cross-domain identity via WTX-1 protocol (commercial feature)
- Encrypted configuration via AES-GCM (commercial feature)

### Server Integration (server/)
- Express.js middleware for tracking API endpoints
- WaiTag registration and verification
- DNS domain ownership verification
- Cross-domain identity synchronization

### Demo App (examples/)
- `demo-server.js` — Self-contained Express server, no external dependencies beyond Express
- `demo.html` — Interactive dashboard showcasing all SDK features
- Runs on port 5000 by default, configurable via PORT env var

## Running the Demo
```bash
npm install
node examples/demo-server.js
# Open http://localhost:5000/demo.html
```

## Licensing
- Core tracking: MIT License (free)
- Cross-domain features: Commercial License required for production
- Contact: hello@waifind.com

## Recent Changes
- 2026-02-17: Created interactive demo app (demo-server.js + demo.html)
- 2026-02-17: Fixed LICENSE file for GitHub detection (clean MIT format)
- 2026-02-17: Updated licensing contact to hello@waifind.com
- 2026-02-17: Added .replit to .gitignore
