# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Nylo, please report it responsibly.

**Email:** hello@waifind.com

**Subject line:** `[SECURITY] Brief description of the issue`

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation plan within 7 days for critical issues.

**Do not** open a public GitHub issue for security vulnerabilities.

## Scope

The following components are in scope for security reports:

- **Client SDK** (`src/nylo.js`) — XSS, injection, data leakage
- **Server APIs** (`server/`) — authentication bypass, injection, CORS misconfiguration
- **Cross-domain token exchange** — token forgery, replay attacks, identity leakage
- **Encrypted configuration** — key derivation weaknesses, config tampering
- **DNS verification** — verification bypass, spoofing

## Security Practices

Nylo implements the following security measures:

### Input Sanitization
- All string inputs are HTML-entity encoded to prevent XSS
- Inputs are length-limited to 1,000 characters
- Domain names are validated against a strict regex pattern

### Identity Security
- WaiTag identifiers are generated using the Web Crypto API (cryptographically secure random bytes)
- No personal information is used in identifier generation
- Identifiers cannot be reverse-engineered to recover personal data
- Session IDs include domain-bound hashes for integrity verification

### Cross-Domain Token Security
- Tokens expire after 5 minutes
- All token exchanges are audit-logged
- Domain ownership is verified via DNS TXT records before cross-domain features are enabled
- Origin validation on all API endpoints

### Data Handling
- No IP addresses are stored
- User agents are hashed, not stored in plain text
- No third-party cookies are used; a **first-party cookie (`nylo_wai`)** is set for local identity persistence once consent is granted
- Identifiers (WaiTags) are **pseudonymous, not anonymous** — they are personal data under GDPR-style regimes, and `Nylo.identify()` can link them to an application-level user ID
- Fail-closed consent gating: no tracking, storage, or cross-domain sync occurs before `Nylo.setConsent({ analytics: true })`
- Three-layer storage (first-party cookie, localStorage, sessionStorage) with graceful degradation

### Network Security
- CORS headers are configured per-origin (not wildcard in production)
- CSRF token generation for sensitive operations
- Batch payloads support compression to reduce attack surface on transit

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |
