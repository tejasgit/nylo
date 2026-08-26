# Claim Alignment Evidence Bundle — U.S. Application 19/246,046

**Application:** 19/246,046 — "A System and Method for Secure, Privacy-Compliant Cross-Domain User Context Management"
**Art Unit:** 2498 · **Filed:** 2025-06-23 · **Office Action:** August 2026 (Notice of Allowability; claims 1–17 allowed)
**Prepared by:** Engineering (Nylo reference implementation) · **Date:** 2026-08-26

---

> ## ⚠️ NOT A LEGAL OPINION — COUNSEL REVIEW REQUIRED
>
> This document is an **engineering work product**. It maps claim language to
> observable implementation behavior (code, tests, documentation) so that
> patent counsel can assess alignment. It is **not** a legal opinion on claim
> construction, validity, infringement, enforceability, or coverage, and it
> makes **no** representation that the implementation "practices the claims."
>
> - The clean claim set in §4 is an **engineering reconstruction** of the
>   examiner's amendments applied to the filed claims. Counsel must verify it
>   against the official record (and against the issued patent, when printed)
>   before relying on it for any purpose.
> - Claim 1 was interpreted by the examiner under 35 U.S.C. §112(f). What the
>   claims cover therefore depends on the corresponding specification
>   structures and their equivalents — a legal determination engineering
>   cannot make.
> - Where this document says "implemented," it means *the described behavior
>   exists and is tested in the reference implementation* — not that the
>   behavior satisfies the limitation as legally construed.

---

## 1. Sources of record

| Source | Location | Role |
|--------|----------|------|
| Filed specification + claims (DOCX) | `attached_assets/Cross_Domain_User_Context_Management_Specification_19:246,046_1787730053606.docx` | Original claims 1–17 as filed (historical) |
| August 2026 Office Action (scan, 14 pp.) | `attached_assets/0_Nylo-Allowed-Claims_1787730715356.pdf` | Controlling allowance record: examiner's amendment, §112(f) interpretation, allowance of claims 1–17, reasons for allowance |
| Reference implementation | This repository (`src/nylo.js`, `server/`, `docs/`, `test/`) | Evidence of implemented behavior |

Key facts from the Office Action:

- Claims 1–17 were presented and are **allowed over the prior art of record** ("Allowable Subject Matter," ¶8).
- The allowance includes an **Examiner's Amendment** (37 CFR 1.312 notice): claims 1–5, 7, 8, 10, 11, 13, and 15 are "Currently Amended"; claims 6, 9, 12, 14, 16, and 17 were not shown amended.
- Claim 1 is interpreted under **35 U.S.C. §112(f)** (¶¶2–6): the "generator," "manager," "protocol," "system," "engine," and "compliance layer" elements are construed to cover the corresponding structures in the specification (¶¶0010, 0023, 0038–0039; Fig. 1 blocks 102, 110, 112) and equivalents.
- Reasons for allowance (¶9, paraphrased — **counsel to verify against the record**): the examiner distinguished the prior art (e.g., Shrivastava, US 2024/0430092 A1) on the combination of encrypted cross-domain contextual tokens, verified domain relationships/access controls, behavioral/fuzzy context synchronization, consent + context-continuity indicators + user controls, first-party-only storage, and elimination of persistent identifiers.

---

## 2. Examiner's amendments — redline reconstruction

Reconstructed from the scanned amendment section (OA pp. 5–8). ~~Strikethrough~~ = deleted; **bold** = inserted. Claims not listed were not shown amended.

**Claim 1 (Currently Amended)**
- "…configured to securely store **the** identifiers in browser storage;"
- "…provides user controls for managing ~~shared~~ **the user** context;"
- "…securely transmits the token between domains, validates ~~&~~ **and** synchronizes the context…"

**Claim 2** — "…the cryptographically signed ~~tokens~~ **anonymous user identifiers** are generated using domain-specific encryption keys…"

**Claim 3** — "…the ~~time-limited tokens~~ **time-limited anonymous user identifiers** are configured to expire after a predefined period…"

**Claim 4** — "…the first-party storage manager stores ~~contextual tokens~~ **the anonymous user identifiers** exclusively in browser storage mechanisms such as local Storage, IndexedDB or secure HTTP-only cookies."

**Claim 5** — "…to manage access to the **encrypted** contextual tokens and ensure privacy."

**Claim 7** — "…the context synchronization engine utilizes **the** fuzzy matching algorithms…"

**Claim 8** — "…the secure handshaking protocol transmits the cryptographically signed ~~tokens~~ **anonymous user identifiers** between domains…"

**Claim 10** — "…enables users to view, reset or revoke ~~cross-domain context~~ **the user context**, ensuring user autonomy…"

**Claim 11** — "…automatically expires ~~unused contextual data~~ **the anonymous user identifiers when unused**, according to time-limited retention policies…"

**Claim 13 (Currently Amended)**
- "generating an anonymous identifier at ~~[[a]]~~ **the** first domain;"
- "storing the anonymous identifier in **a** first-party storage of the web browser;"
- **New step inserted:** "**encrypting the cryptographically secure time-limited token;**"
- "storing the validated ~~anonymous identifier~~ **token** in ~~web browser first-party storage~~ **the first-party storage of the web browser**."

**Claim 15** — "…comprises verifying ~~the token's~~ cryptographic signature **of the token** to ensure it is generated by the first domain."

---

## 3. Filed claims (historical, superseded where amended)

The originally filed claims 1–17 are preserved verbatim in the DOCX source (CLAIMS section). They remain the historical record; the operative language is the reconstruction in §4. (Text omitted here for brevity — see the DOCX or Appendix B extraction command.)

---

## 4. Proposed clean allowed claim set (engineering reconstruction — counsel to verify)

**1.** A system for preserving user's contextual information across different domains, the system comprising:
an anonymous identifier generator configured to generate cryptographically signed, time-limited anonymous user identifiers;
a first-party storage manager configured to securely store the identifiers in browser storage;
a secure handshaking protocol configured to transmit encrypted contextual tokens between different domains;
a domain verification system configured to validate domain relationships and manage access controls;
a context synchronization engine configured to align user context across different domains using behavioral and fuzzy matching algorithms;
a privacy compliance layer configured to manage user consent, displays context continuity indicators and provides user controls for managing the user context;
wherein the system generates a time-limited token with non-identifiable user context, securely transmits the token between domains, validates and synchronizes the context and stores all data in first-party storage, ensuring compliance with privacy regulations and eliminating persistent identifiers.

**2.** The system as claimed in claim 1, wherein the cryptographically signed anonymous user identifiers are generated using domain-specific encryption keys ensuring that contextual information is securely encoded and separated across different domains.

**3.** The system as claimed in claim 1, wherein the time-limited anonymous user identifiers are configured to expire after a predefined period thus, preventing the persistence of user context beyond a specific duration to ensure privacy compliance.

**4.** The system as claimed in claim 1, wherein the first-party storage manager stores the anonymous user identifiers exclusively in browser storage mechanisms such as local Storage, IndexedDB or secure HTTP-only cookies.

**5.** The system as claimed in claim 1, wherein the domain verification system validates relationships between different domains using secure authentication methods to manage access to the encrypted contextual tokens and ensure privacy.

**6.** The system as claimed in claim 1, wherein the context synchronization engine employs behavioral pattern matching and probabilistic identity inference to maintain user context across domains without using persistent identifiers. *(as filed; not shown amended)*

**7.** The system as claimed in claim 1, wherein the context synchronization engine utilizes the fuzzy matching algorithms to infer user context across domains without requiring exact identity matching, thereby maintaining privacy while ensuring continuity.

**8.** The system as claimed in claim 1, wherein the secure handshaking protocol transmits the cryptographically signed anonymous user identifiers between domains using secure transmission methods, such as HTTPS with additional cryptographic protections to prevent token interception.

**9.** The system as claimed in claim 1, wherein the privacy compliance layer provides explicit user consent mechanisms and transparent context preservation notifications, allowing users to manage and control the sharing of their contextual information across domains. *(as filed; not shown amended)*

**10.** The system as claimed in claim 1, wherein the privacy compliance layer includes a user interface that enables users to view, reset or revoke the user context, ensuring user autonomy over their contextual information.

**11.** The system as claimed in claim 1, wherein the first-party storage manager automatically expires the anonymous user identifiers when unused, according to time-limited retention policies, ensuring that stored context is deleted when no longer necessary.

**12.** The system as claimed in claim 1, wherein the different domains include but not limited to a marketing website domain, a product documentation domain, a customer support portal domain. *(as filed; not shown amended)*

**13.** A method for preserving user contextual information across different domains, the method comprising:
receiving a user request initiated from a web browser at a first domain;
generating an anonymous identifier at the first domain;
storing the anonymous identifier in a first-party storage of the web browser;
creating a cryptographically secure time-limited token when a user navigates from the first domain to a second domain;
verifying the second domain using a privacy-preserving handshaking protocol;
encrypting the cryptographically secure time-limited token;
transferring the encrypted token from the first domain to the second domain;
validating the token's authenticity and recency at the second domain;
storing the validated token in the first-party storage of the web browser.

**14.** The method as claimed in claim 13, wherein generating the anonymous identifier at the first domain comprises hashing a random number, timestamp and domain-specific salt using a SHA-256 algorithm. *(as filed; not shown amended)*

**15.** The method as claimed in claim 13, wherein validating the token's authenticity at the second domain comprises verifying cryptographic signature of the token to ensure it is generated by the first domain.

**16.** The method as claimed in claim 13, wherein the encrypted token is transmitted over a secure communication channel using SSL/TLS encryption to protect the token's integrity during transmission. *(as filed; not shown amended)*

**17.** The method as claimed in claim 13, wherein the time-limited token is configured to expire after a predefined period to ensure that user data is not retained longer than necessary. *(as filed; not shown amended)*

---

## 5. Terminology reconciliation (claims ↔ product language)

| Claim term | Product/engineering term | Why they differ |
|---|---|---|
| "anonymous user identifier" | **Pseudonymous** identifier (WaiTag) | Claim language is counsel-facing. Product and privacy documentation must say *pseudonymous*: the identifier contains no direct identifiers, but it persists and singles out a browser, and `identify()` can link it. Using "anonymous" in product claims would be inaccurate under GDPR-style regimes. |
| "cryptographically signed … identifiers" | Digest-derived identifier + HMAC-protected storage + server-signed tokens | The WaiTag string itself carries no detached signature. Signature protections exist at (a) storage integrity (HMAC-SHA256 on every read) and (b) transport (identifier travels only inside an HMAC-signed, AES-256-GCM-encrypted token). **Counsel question Q1.** |
| "encrypted contextual tokens" | WTX-1 token format v2 (sign-then-encrypt) | Implemented literally as of v2: HMAC-SHA256-signed payload sealed in AES-256-GCM. Legacy signed-cleartext tokens are rejected. |
| "domain-specific encryption keys" | HKDF-SHA256 per-tenant, per-destination key derivation | Implemented literally: independent encryption and MAC keys per `(tenantId, destinationDomain)`. |
| "eliminating persistent identifiers" | Time-limited identifiers + no third-party identifiers | Identifiers are first-party-only and now expire automatically (180-day absolute / 30-day unused, configurable). They are *not* indefinite, but they do persist within retention bounds. **Counsel question Q2.** |
| "behavioral and fuzzy matching algorithms" | **Explicit non-embodiment** | Deliberately not implemented (fingerprinting/covert-tracking risk). See §7. **Counsel question Q3.** |
| "storing the validated token" (claim 13, as amended) | SDK stores the validated identity context; the token itself is single-use | After verification the SDK persists the restored identifier/session in first-party storage; the token is consumed server-side and never reusable. **Counsel question Q4.** |

---

## 6. Claim chart — limitation → implementation evidence

Status legend: ✅ implemented & tested · ⚠️ implemented with terminology/construction caveat · ❌ deliberate non-embodiment · ❓ counsel question controls.

### Independent claim 1 (system; §112(f))

| Limitation | Status | Evidence (code / tests / docs) |
|---|---|---|
| Anonymous identifier generator: cryptographically signed, time-limited anonymous user identifiers | ⚠️❓ Q1 | Digest WaiTags: `src/nylo.js` (`Security.generateWaiTag`, SHA-256 over CSPRNG+timestamp+domain salt, fail-closed), `server/utils/secure-id.ts` (`generateWaiTagId`). Time-limited: retention enforcement in `getStoredIdentityData()`. Signature protections: storage HMAC (`validateIntegrity`), signed+encrypted transport (`server/utils/token-core.js`). Tests: `test/sdk-context-controls.test.js` (digest format, no readable timestamp, expiry), `test/token-core.test.js`. |
| First-party storage manager: securely store the identifiers in browser storage | ✅ | `src/nylo.js` storage hierarchy (first-party cookie `nylo_wai`, localStorage, sessionStorage; HMAC integrity on read; reversible encoding documented as obfuscation). Spec §8. Tests: `test/sdk-privacy.test.js`, `test/sdk-context-controls.test.js`. |
| Secure handshaking protocol: transmit **encrypted** contextual tokens between domains | ✅ | WTX-1 token format v2 sign-then-encrypt: `server/utils/token-core.js` (HMAC-SHA256 inner signature; AES-256-GCM; HKDF per tenant+destination; AEAD-bound routing). Hash-fragment transport: `src/nylo.js`, spec §5. Tests: `test/token-core.test.js` (confidentiality, tamper, wrong-key, legacy rejection), `test/demo-token-routes.test.js`. |
| Domain verification system: validate domain relationships, manage access controls | ✅ | DNS TXT verification: `server/utils/dns-verification.ts`, `server/api/dns-verify.ts` (API-key-authenticated management; no caller-supplied tenant IDs). Enforcement on token verification (`isDomainVerified` → 403). Write grants: `server/api/waitag-tracking.ts`, spec §9.11. Tests: `test/server-routes.test.js` (incl. domain-endpoint API-key auth), `test/write-grant.test.js`. |
| Context synchronization engine: align context using **behavioral and fuzzy matching algorithms** | ❌❓ Q3 | **Not practiced.** Synchronization is deterministic and token-based only. Behavioral/fuzzy/probabilistic matching is an explicit non-embodiment (§7). §112(f) construction (spec ¶0038 structures include behavioral pattern matching, probabilistic inference, fuzzy context matching) is for counsel. |
| Privacy compliance layer: consent, context continuity indicators, user controls for the user context | ✅ | Consent gating (fail-closed): `src/nylo.js` `setConsent`; withdrawal purge. Indicators: `nyloContextPreserved` event + demo indicator (`examples/demo.html`). Controls: `getStoredContext()`, `resetContext()`, `revokeContext()`. Tests: `test/consent.test.js`, `test/sdk-context-controls.test.js`. |
| Wherein: time-limited token with non-identifiable user context; secure transmission; validates and synchronizes; all data in first-party storage; eliminating persistent identifiers | ⚠️❓ Q2 | 5-minute single-use tokens (`test/token-core.test.js`); token payload carries pseudonymous fields only (no fingerprint-capable data — server strips defensively). First-party-only storage (no third-party cookies/storage). Identifier persistence bounded by retention policy. "Non-identifiable"/"eliminating persistent identifiers" as construed is for counsel. |

### Dependent system claims 2–12

| # | Limitation (post-amendment) | Status | Evidence |
|---|---|---|---|
| 2 | Identifiers generated using **domain-specific encryption keys**; contextual info securely encoded and separated across domains | ✅ | HKDF-SHA256 derives independent AES-256-GCM + HMAC keys per `(tenant, destinationDomain)`; cross-destination decrypt/verify fails. `server/utils/token-core.js`; `test/token-core.test.js` (destination isolation). Domain salt also diversifies WaiTag derivation. |
| 3 | Time-limited identifiers expire after predefined period | ✅ | 180-day absolute / 30-day unused defaults, configurable, enforced on every read; expired records deleted, fresh identity minted. `src/nylo.js`; `test/sdk-context-controls.test.js`. |
| 4 | Identifiers stored **exclusively** in browser storage mechanisms "such as localStorage, IndexedDB or secure HTTP-only cookies" | ⚠️ | Storage is exclusively first-party browser storage: localStorage (recited), sessionStorage, and a JavaScript-set first-party cookie. IndexedDB and HttpOnly cookies are not used; the claim's list is exemplary ("such as"). HttpOnly rationale documented (spec §9.5). |
| 5 | Domain verification manages access to the **encrypted** contextual tokens via secure authentication | ✅ | Token issuance requires API key + destination binding; verification requires write grant + DNS-verified destination; management endpoints API-key-authenticated. `server/api/*`; `test/server-routes.test.js`. |
| 6 | Behavioral pattern matching + probabilistic identity inference without persistent identifiers | ❌❓ Q3 | **Not practiced** — explicit non-embodiment (§7). |
| 7 | Fuzzy matching algorithms to infer context without exact identity matching | ❌❓ Q3 | **Not practiced** — explicit non-embodiment (§7). |
| 8 | Signed identifiers transmitted via HTTPS with additional cryptographic protections against interception | ✅ | HTTPS required (spec §9.4); identifier travels only inside encrypted+signed token; hash-fragment transport keeps token out of HTTP requests/logs; one-time-use + 5-min expiry. `test/token-core.test.js`, spec §13.1/§13.6. |
| 9 | Explicit consent mechanisms + transparent context preservation notifications | ✅ | `setConsent` (fail-closed, withdrawal purge + grant invalidation); `nyloContextPreserved` transparency event on every restoration. `test/consent.test.js`, `test/sdk-context-controls.test.js`. |
| 10 | UI to view, reset or revoke the user context | ✅ | Public APIs `getStoredContext()` / `resetContext()` / `revokeContext()` + reference UI in `examples/demo.html` (view/reset/revoke buttons, continuity indicator). `test/sdk-context-controls.test.js`. |
| 11 | Automatic expiry of identifiers **when unused** per time-limited retention policies | ✅ | `lastUsedAt` sliding window (30-day default) + absolute cap; passive views don't extend retention; legacy records without timestamps fail closed. `test/sdk-context-controls.test.js`. |
| 12 | Domains include marketing/product-docs/support portal | ✅ | Deployment-scenario limitation; multi-domain deployment documented (README "Cross-Domain Setup", examples). No code constraint on domain roles. |

### Independent claim 13 (method) and dependents 14–17

| # | Step / limitation | Status | Evidence |
|---|---|---|---|
| 13.1 | Receive user request from web browser at first domain | ✅ | SDK bootstrap on page load; write-grant request flow (`POST /api/tracking/grant`). |
| 13.2 | Generate anonymous identifier at the first domain | ⚠️ (terminology) | Pseudonymous WaiTag generated post-consent. `src/nylo.js`. |
| 13.3 | Store identifier in a first-party storage of the browser | ✅ | Three-layer first-party storage with HMAC integrity. |
| 13.4 | Create cryptographically secure time-limited token on navigation | ✅ | Server-side token creation (`signCrossDomainToken`), 5-min TTL, CSPRNG `jti`. |
| 13.5 | Verify second domain via privacy-preserving handshaking protocol | ✅ | DNS-verified destination + write-grant authorization before token processing. |
| 13.6 | **Encrypt** the token | ✅ | AES-256-GCM envelope (v2); cleartext tokens rejected. |
| 13.7 | Transfer encrypted token first→second domain | ✅ | Hash-fragment transport; early-cleanup script. |
| 13.8 | Validate authenticity and recency at second domain | ✅ | AEAD + inner signature + expiry + future-dating + replay (atomic consume) + binding checks; authorization precedes consumption. |
| 13.9 | Store the **validated token** in first-party storage | ❓ Q4 | After successful verification the SDK stores the validated identity context (WaiTag/session, HMAC-protected, encrypted-at-rest encoding) in first-party storage; the raw token is single-use and consumed. Whether storing the validated token's *contents* satisfies "storing the validated token" is a construction question. |
| 14 | Identifier = SHA-256 over random number, timestamp, domain-specific salt | ✅ | Implemented **literally**: `Security.generateWaiTag()` (browser, Web Crypto `crypto.subtle.digest`) and `generateWaiTagId()` (server) hash CSPRNG randomness + timestamp + `"nylo:"+domain` salt; only digest fragments form the identifier. `test/sdk-context-controls.test.js` (format, same-ms uniqueness, no readable timestamp). |
| 15 | Validation comprises verifying cryptographic signature of the token (generated by first domain) | ✅ | Inner HMAC-SHA256 signature verified after decryption; wrong-secret and tampered tokens rejected (`INVALID_SIGNATURE`); envelope-without-tag rejected (`MISSING_SIGNATURE`). |
| 16 | Encrypted token transmitted over SSL/TLS | ✅ | HTTPS mandated (spec §9.4); token additionally encrypted at the application layer (defense in depth beyond the claim). |
| 17 | Token expires after predefined period | ✅ | 300 s default, configurable; `TOKEN_EXPIRED` on expiry; nonce retention ≥ TTL. |

---

## 7. Explicit non-embodiments

The following claimed techniques are **deliberately not implemented**, per product/security policy (no fingerprinting, no covert tracking, consent-first):

1. **Behavioral pattern matching** (claims 1, 6) — inferring identity/context from user behavior.
2. **Probabilistic identity inference** (claim 6) — statistical re-identification without an exact identifier.
3. **Fuzzy matching algorithms** (claims 1, 7) — approximate cross-domain context matching.

Rationale: implementing these as shipped defaults would constitute fingerprinting-adjacent covert tracking, contradicting the product's consent-gated, deterministic-identity security model (see `SECURITY.md`, WTX-1 spec §10, and repository policy docs). Identity synchronization in the reference implementation occurs **only** via explicit, consented, encrypted token exchange with exact identifier matching.

If counsel and product later require these limitations to be practiced, the previously scoped approach is a **consented, ephemeral, data-minimized** design (session-scoped, non-persistent, consent-gated inference that never touches device/browser fingerprint attributes) — to be designed with counsel before any implementation.

---

## 8. Gaps and open counsel questions

- **Q1 — "cryptographically signed … identifiers."** The identifier string itself is not detached-signed; signing exists at storage-integrity and transport layers, and the token carrying the identifier is signed and encrypted. Does this satisfy the limitation under §112(f) construction, or should the server sign WaiTags at issuance (e.g., detached HMAC recorded server-side)? Engineering can add issuance signatures if counsel requires.
- **Q2 — "eliminating persistent identifiers."** WaiTags persist in first-party storage within bounded retention (180-day absolute / 30-day unused, both configurable). The specification frames elimination against third-party persistent identifiers/identity graphs. Confirm the construction and whether current retention defaults are consistent with it.
- **Q3 — behavioral/fuzzy/probabilistic limitations (claims 1, 6, 7).** These are explicit non-embodiments. Because claim 1 recites the synchronization engine "using behavioral and fuzzy matching algorithms," counsel must assess (a) the §112(f) corresponding structure (spec ¶0038) and equivalents, and (b) the implications of not practicing these limitations in the reference implementation. Engineering makes no assertion either way.
- **Q4 — claim 13 "storing the validated token."** The SDK stores the validated token's *decrypted, verified identity context*, not the consumed single-use token string. Storing the raw token would conflict with one-time-use replay protection. Confirm construction or advise if literal token persistence (e.g., storing the envelope alongside a consumed flag) is needed.
- **Q5 — claim 4 storage mechanisms.** Storage uses localStorage (recited), sessionStorage, and a JavaScript-set (non-HttpOnly) first-party cookie; IndexedDB is not used. Confirm the exemplary "such as" list is satisfied; the HttpOnly design rationale is documented in WTX-1 spec §9.5.
- **Q6 — reconstruction verification.** §2/§4 are reconstructed from a scanned amendment. Verify against the official file wrapper (and the issued claims when printed), including the unamended status of claims 6, 9, 12, 14, 16, 17.
- **Q7 — terminology in public materials.** Product/privacy documentation uses *pseudonymous* while claims say *anonymous*. Confirm this divergence is acceptable (engineering strongly recommends keeping "pseudonymous" in all user-facing materials).

---

## 9. Evidence appendix

### A. Test suites (all passing as of 2026-08-26)

| Suite | Coverage relevant to claims |
|---|---|
| `test/token-core.test.js` | v2 encrypt+sign round-trip, confidentiality (no identity fields in cleartext), AEAD tamper (ct/iv/tag/routing), destination key isolation, wrong-secret, legacy v1 rejection, expiry, future-dating, replay (atomic consume) |
| `test/sdk-context-controls.test.js` | Digest WaiTag format + no readable timestamp + same-ms uniqueness, absolute/unused retention, legacy-timestamp fail-closed, configurable expiry attributes, passive `getStoredContext` (no retention extension), `resetContext`, `revokeContext`, `nyloContextPreserved` |
| `test/consent.test.js` | Fail-closed consent gating, withdrawal purge/abort |
| `test/demo-token-routes.test.js` | End-to-end demo server token issuance/verification incl. v2 gates |
| `test/server-routes.test.js` | Write grants on ingestion/registration/verification, tenant resolution, token-burning prevention, DNS gate, domain-verification endpoint API-key auth (no customer-ID fallback) |
| `test/write-grant.test.js` | Grant signing/verification, tamper, expiry, scope/domain binding |
| `test/sdk-privacy.test.js` | Storage hierarchy, fingerprint-free payloads, URL reduction |

Run: `npm test` (Node built-in test runner). TypeScript: `npx tsc --noEmit`.

### B. Reproducing the filed-claims extraction

```bash
unzip -p "attached_assets/Cross_Domain_User_Context_Management_Specification_19:246,046_1787730053606.docx" \
  word/document.xml | sed -e 's/<w:p [^>]*>/\n/g; s/<w:p>/\n/g' -e 's/<[^>]*>//g' | sed -n '/^CLAIMS$/,$p'
```

### C. Key implementation files

`src/nylo.js` (SDK: identity, storage, consent, controls, transport) · `server/utils/token-core.js` (+`.d.ts`) (token format v2) · `server/utils/secure-id.ts` (server ID generation) · `server/api/waitag-tracking.ts` (grants, registration, verification) · `server/api/dns-verify.ts` + `server/utils/dns-verification.ts` (domain verification) · `docs/WTX-1-SPEC.md` (protocol spec v1.4.0-draft) · `SECURITY.md`, `README.md`.

---

*Prepared for patent counsel review. No part of this document is, or should be cited as, a legal conclusion.*
