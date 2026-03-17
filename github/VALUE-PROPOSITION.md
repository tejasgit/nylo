# Privacy-Preserving Cross-Domain Identity Framework
## Value Proposition, Adoption Strategy & Revenue Projection

**Confidential — For Investors and Licensing Partners**
**Version:** 1.0
**Date:** March 2026
**Contact:** hello@waifind.com

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Market Context: The Identity Crisis](#2-market-context-the-identity-crisis)
3. [Technology Positioning](#3-technology-positioning)
4. [Gap Analysis: Adobe CJA & Google Analytics 360](#4-gap-analysis-adobe-cja--google-analytics-360)
5. [Regulated Market Play](#5-regulated-market-play)
6. [Industry Vertical Adoption Map](#6-industry-vertical-adoption-map)
7. [Licensing Model & Revenue Tiers](#7-licensing-model--revenue-tiers)
8. [Revenue Projection Model](#8-revenue-projection-model)
9. [Competitive Moat & Valuation Drivers](#9-competitive-moat--valuation-drivers)
10. [References](#10-references)

---

## 1. Executive Summary

The deprecation of third-party cookies across major browsers has created a structural gap in cross-domain analytics — the ability to understand a single visitor's journey across multiple websites. This gap affects every organization that operates more than one web property: healthcare networks, financial institutions, government agencies, media companies, and multi-brand retailers.

The existing solutions from market leaders (Adobe, Google) rely on mechanisms that are fundamentally broken in a post-cookie world: cookie synchronization, query parameter decoration, and identity graphs that require personally identifiable information (PII). These approaches are increasingly incompatible with privacy regulations (GDPR, HIPAA, CCPA, GLBA) and browser-level tracking prevention.

This framework introduces a patent-pending protocol for preserving pseudonymous visitor context across unrelated domains without cookies, fingerprinting, login requirements, or PII collection. The protocol has been submitted as an IETF Internet-Draft [1] and proposed to the W3C Privacy Community Group [2], positioning it as a potential open standard with commercial licensing for production use.

**The opportunity:**
- **Total addressable market:** $6–8B web analytics market (2025) growing to $16–24B by 2030 at 15–21% CAGR [3][4][5]
- **Specific gap:** No existing solution provides privacy-compliant cross-domain identity for anonymous visitors at scale
- **Defensibility:** Patent-pending algorithm, standards-track protocol, first-mover advantage, dual-license model
- **Revenue model:** Open-source core (adoption engine) + commercial cross-domain licensing (revenue engine)

---

## 2. Market Context: The Identity Crisis

### 2.1 The Cookie Collapse

Third-party cookies have been the primary mechanism for cross-domain user identification since the 1990s. Their elimination is now effectively complete across the browser landscape:

| Browser | Action | Market Share |
|---------|--------|-------------|
| Safari (ITP) | Blocked third-party cookies since 2017; first-party cookies capped at 7 days | ~18% desktop, ~27% mobile [6] |
| Firefox (ETP) | Blocked third-party cookies since 2019 | ~3% [6] |
| Chrome | Cancelled forced deprecation (July 2024); retired most Privacy Sandbox APIs (October 2025); cookies remain enabled by default with user opt-out | ~67% [7] |

**Critical insight:** While Chrome reversed its forced deprecation timeline, the Privacy Sandbox APIs intended to replace cookies (Topics, Protected Audience, Attribution Reporting) were retired in October 2025 due to low adoption — only ~32% of ad buyers were actively testing at scale [7]. The result is a fragmented landscape with no industry consensus on a replacement mechanism.

### 2.2 Revenue Impact

The economic impact of cross-domain identity loss is measurable:

- Privacy Sandbox vs. cookies showed **-27% to -30% revenue per impression** in UK CMA testing [8]
- Publishers expect **-20% to -30%** total ad revenue without cookie-based measurement [9]
- EU cookie lifetime restrictions (1-year maximum) projected to cost **-€904M annually** across the European digital advertising ecosystem [10]
- US programmatic digital ad spend reached **$309.3B** in 2024, growing 15.1% year-over-year [11]

### 2.3 The Gap in Existing Solutions

| Solution | What It Does | Why It Fails |
|----------|-------------|-------------|
| Third-party cookies | Shared identifier across domains | Blocked by Safari, Firefox; opt-out in Chrome |
| Browser fingerprinting | Device identification via hardware/software signals | Legally risky (GDPR Art. 5), increasingly blocked by browsers, ethically problematic |
| Login-based identity (UID 2.0, LiveRamp) | Authentication-gated identity | Excludes anonymous visitors (industry estimates suggest 70–90% of web traffic is unauthenticated [37]); requires consent wall |
| First-party data sharing | Bilateral PII exchange | Requires legal agreements, data processing contracts, PII exchange |
| Google Topics API | Interest-based advertising signals | Retired (October 2025); Chrome-only; coarse-grained; advertising-focused [7] |
| Adobe ECID | First-party identity service | Same eTLD+1 only; classified as personal data under GDPR; ITP caps persistence to 7 days [12] |

**The structural gap:** No existing solution provides privacy-compliant cross-domain identity for anonymous visitors without requiring login, cookies, fingerprinting, or PII exchange.

---

## 3. Technology Positioning

### 3.1 What the Framework Does (Business Terms)

The framework provides a protocol and SDK for preserving pseudonymous visitor identity across unrelated web domains. In practical terms:

- A visitor on `hospital-info.com` who clicks through to `patient-portal.com` is recognized as the same visitor — without knowing who they are
- The identifier contains zero personal information and cannot be reverse-engineered to identify a person
- No third-party cookies, browser fingerprinting, or login is required
- The system degrades gracefully to fully anonymous analytics when consent is denied
- Domain participation is authorized via DNS records (the same pattern used by email SPF/DKIM)

### 3.2 Measurable Security Properties

The protocol's privacy claims are not aspirational — they are quantified and measurable:

| Property | Measurement | Method |
|----------|------------|--------|
| HTTP data leakage | **0 bytes** of identity data in HTTP requests | Structural guarantee per RFC 3986 §3.5 [13] |
| Token visibility window | **<1ms typical** with recommended configuration | `performance.now()` instrumented in SDK |
| Token entropy | **128 bits** of cryptographic randomness | Web Crypto API `getRandomValues()` |
| Replay attack surface | **Single-use** tokens with server-side nonce tracking | Server-side verification log |
| Token lifetime | **300 seconds** (configurable) | Server-side timestamp validation |
| Server logging exposure | **0 of 6** HTTP log fields contain token data | Structural guarantee (URL path, query string, headers, referrer, cookies, request body — none contain token) |

### 3.3 IP Portfolio

| Asset | Status |
|-------|--------|
| Patent | U.S. Non-Provisional Patent Application filed (cross-domain identity technology) |
| IETF Internet-Draft | draft-surampudi-wtx1-01 submitted [1] |
| W3C Privacy CG Proposal | Submitted with detailed explainer [2] |
| IRTF PEARG Discussion | Document prepared for Privacy Enhancements and Assessments Research Group [14] |
| Academic Research | Manuscript submitted to *Decision Support Systems* (Impact Factor 6.8) |
| Protocol Specification | CC BY 4.0 license (open standard positioning) |

---

## 4. Gap Analysis: Adobe CJA & Google Analytics 360

### 4.1 Adobe Customer Journey Analytics (CJA)

Adobe CJA is the premium analytics platform in the Experience Cloud suite, serving enterprise customers. Its cross-domain capabilities have fundamental limitations that this framework addresses.

#### What Adobe CJA Offers

- **ECID (Experience Cloud ID):** First-party identity service that persists visitor identity within the same eTLD+1 (e.g., `blog.acme.com` ↔ `shop.acme.com`)
- **appendVisitorIDsTo():** Function that decorates outbound links with the `adobe_mc` query parameter to pass ECID across domains
- **Web SDK (v2.11.0+):** Cross-domain ID sharing via `adobe_mc` parameter with simplified configuration
- **FPID (First-Party Device ID):** Server-generated device ID via DNS A/AAAA records for single-domain persistence
- **Cross-Channel Analytics:** Stitching of online/offline data sources via identity namespaces

#### Where Adobe CJA Falls Short

| Limitation | Impact | Source |
|-----------|--------|--------|
| **ECID persistence capped at 7 days under ITP** | Safari visitors (~27% mobile) lose identity after 7 days, even with CNAME | Adobe Experience League [12] |
| **appendVisitorIDsTo() only works on direct clicks** | Does not cover bookmarks, typed URLs, separate sessions, or non-link navigation | Adobe Documentation [15] |
| **Query parameter transport** | `adobe_mc` parameter is sent to destination server in HTTP request — logged in server access logs, visible to network intermediaries | HTTP specification |
| **ECID classified as personal data** | Under GDPR, ECID is considered personal data (unique identifier attributable to a natural person), requiring full data controller obligations | GDPR Article 4(1) [16] |
| **No anonymous cross-domain identity** | Without login or ECID sync, CJA cannot stitch anonymous journeys across separate domains | Adobe Community [17] |
| **Safari iframe ECID fragmentation** | Safari generates new ECID for iframed content from different domains, splitting sessions | Adobe Community [17] |
| **FPID limited to single domain** | First-Party Device ID generates durable IDs but only for a single domain — does not solve cross-domain | Adobe Documentation [18] |
| **Storage Spanner deprecated** | Previous workaround for cross-domain data variable passing has been deprecated with no replacement | Adobe Community [17] |

#### What This Framework Solves That Adobe CJA Cannot

1. **No ITP dependency:** Identity transport uses URL hash fragments (never sent to servers per RFC 3986), not cookies. Safari ITP, Firefox ETP, and Chrome tracking prevention have no mechanism to block hash fragment transport.

2. **Privacy-by-design identity:** The pseudonymous identifier contains zero PII and cannot be classified as personal data under GDPR unless the operator creates a separate mapping table — which the protocol explicitly discourages.

3. **Works without login:** Anonymous visitors (estimated 70–90% of web traffic is unauthenticated [37]) get consistent cross-domain identity without creating accounts or authenticating.

4. **Zero HTTP leakage:** Unlike Adobe's `adobe_mc` query parameter, the token never appears in HTTP requests, server logs, referrer headers, or network traffic.

5. **Works for non-click navigation:** The protocol supports any navigation method — not just `<a>` tag clicks.

#### Integration Opportunity

This framework is **complementary to Adobe CJA**, not competitive. It can serve as a privacy-preserving identity layer that feeds into Adobe's Customer Journey Analytics via the Analytics Source Connector or Experience Platform Web SDK. The licensing model supports OEM/white-label integration.

### 4.2 Google Analytics 360 (GA4 360)

GA4 360 is Google's premium analytics offering, providing enhanced data collection, BigQuery integration, and enterprise features. Its cross-domain capabilities have significant structural limitations.

#### What GA4 360 Offers

- **Cross-domain measurement:** Configuration-based link decoration using the `_gl` query parameter
- **Subproperties (360 only):** Filtered views with unified session stitching across domains
- **Rollup properties (360 only):** Aggregate reporting across multiple properties
- **BigQuery integration:** Raw event export for advanced cross-property analysis
- **Enhanced measurement:** Automatic event tracking (page views, scrolls, outbound clicks)

#### Where GA4 360 Falls Short

| Limitation | Impact | Source |
|-----------|--------|--------|
| **Link-click dependent tracking** | GA4's cross-domain linker automatically decorates standard `<a>` tag clicks; other navigation methods (button clicks, form submissions, direct URL entry, bookmarks) require manual implementation to pass the `_gl` parameter | Google Documentation [19] |
| **`_gl` parameter dependency** | Server-side redirects, payment platforms, and landing pages that strip query parameters break tracking | Google Documentation [19] |
| **Single Measurement ID required** | All domains must share the same GA4 property — impossible when domains are operated by different business units or partners | Google Documentation [19] |
| **Session inflation** | When tracking fails, session data splits — inflating "New User" and "Session" counts by **30–50%** | Industry analysis [20] |
| **Query parameter transport** | `_gl` parameter is sent to destination server in HTTP requests — logged, visible to intermediaries | HTTP specification |
| **Affects outbound click tracking** | Enabling cross-domain measurement reclassifies configured domains as internal — outbound link click events for those domains are no longer automatically generated by Enhanced Measurement | Google Documentation [19] |
| **Google ecosystem lock-in** | GA4 360 pricing starts at approximately **$50,000/year** (varies by data volume and contract); data is processed through Google's infrastructure with limited data sovereignty [38] |
| **No anonymous cross-domain identity resolution** | Without User-ID feature (requires login), GA4 cannot deterministically stitch anonymous cross-domain journeys | Google Documentation |

#### What This Framework Solves That GA4 360 Cannot

1. **Protocol-level privacy:** Identity never appears in HTTP traffic. GA4's `_gl` parameter is a query string value — transmitted to servers, logged in access logs, visible in referrer headers.

2. **Works beyond link clicks:** The protocol operates at the navigation level, not the DOM element level. Any navigation between participating domains can carry identity.

3. **No ecosystem lock-in:** The framework is a standalone protocol — no dependency on Google's infrastructure, data processing, or pricing model.

4. **Cross-property identity:** Different business units or partner organizations can share pseudonymous identity without sharing a GA4 property or Measurement ID.

5. **Regulatory compliance by design:** The framework doesn't require PII, doesn't use cookies for cross-domain transport, and doesn't send identity data to third-party servers (like Google's).

#### Integration Opportunity

This framework can operate alongside GA4 as a **supplementary identity layer**. The pseudonymous identifier can be passed to GA4 as a custom dimension, enriching Google's analytics with cross-domain journey data that GA4 cannot capture natively.

### 4.3 Competitive Gap Summary

| Capability | Adobe CJA | GA4 360 | This Framework |
|-----------|-----------|---------|----------------|
| Cross-domain anonymous identity | Partial — ECID sync works within same eTLD+1 but breaks across separate domains when third-party cookies are blocked (Safari, Firefox) | Partial — works via `_gl` parameter on link clicks only; fails for non-click navigation, bookmarks, separate sessions | Full support across unrelated domains, all navigation methods |
| Anonymous visitor tracking | Yes (single-domain); limited cross-domain without login when cookies blocked | Yes (single-domain); limited cross-domain without login | Yes (single-domain and cross-domain) |
| PII-free cross-domain identifier | No — ECID may qualify as personal data under GDPR Article 4(1) as an "online identifier" attributable to a natural person; requires DPIA assessment | No — Client ID is a persistent pseudonymous identifier; legal classification varies by jurisdiction | Yes — identifier contains pure cryptographic randomness with no PII inputs; legal classification as personal data is unlikely absent a separate mapping table, though jurisdictional analysis is recommended |
| HTTP request leakage of cross-domain token | Yes (`adobe_mc` transmitted in query string) | Yes (`_gl` transmitted in query string) | No (hash fragment transport per RFC 3986 §3.5) |
| Safari ITP resistant | No — first-party cookies capped at 7 days; cross-domain sync breaks | Partial — `_gl` parameter survives but client_id persistence capped | Yes — no cookie dependency for cross-domain transport |
| HIPAA-compatible | Possible with BAA + PHI safeguards; HHS has flagged analytics tracking on healthcare sites | Google Analytics not recommended for HIPAA environments without significant safeguards | Designed for compatibility (no PII collected, self-hosted); legal review recommended |
| FedRAMP-compatible | Requires FedRAMP-authorized Adobe deployment | Google Analytics is not listed as FedRAMP-authorized [30] | Compatible via self-hosted deployment; no third-party data sharing |
| DNS-based domain authorization | No | No | Yes |
| Single-use token verification | No | No | Yes |
| Replay protection | No | No | Yes (server-side nonce tracking) |
| Pricing | $100K–$500K+/year (Experience Cloud, varies by contract) [39] | $50K+/year (GA4 360, varies by data volume) [38] | Tiered licensing (see Section 7) |

---

## 5. Regulated Market Play

Regulated industries represent the highest-value segment for this framework because existing analytics solutions are fundamentally incompatible with their compliance requirements. The framework's zero-PII, no-cookie, pseudonymous architecture is not a nice-to-have in these markets — it is a prerequisite.

### 5.1 Healthcare (HIPAA)

#### The Problem

Healthcare organizations operate multiple web properties — hospital information sites, patient portals, pharmacy platforms, specialist referral systems — and need to understand patient digital journeys across these properties to optimize care access. However:

- **HIPAA Privacy Rule (45 CFR §164.514)** restricts the use and disclosure of Protected Health Information (PHI), which includes any individually identifiable health information [21]
- **HHS December 2022 Bulletin** explicitly addressed tracking technologies on healthcare websites, stating that IP addresses combined with health-related page visits constitute PHI [22]
- **FTC enforcement:** In 2023, the FTC took action against multiple telehealth companies for sharing health data with advertising platforms via tracking pixels [23]

Traditional analytics platforms (Google Analytics, Adobe Analytics) collect IP addresses and generate persistent identifiers that, when combined with health-related page visits, may constitute PHI — creating HIPAA liability.

#### Market Opportunity

- **Healthcare analytics market:** $53–64B in 2025, projected to reach $166–199B by 2030 at ~24.6% CAGR [24][25]
- **US healthcare analytics:** $19.65B in 2025, projected to reach $59.68B by 2030 [24]
- **Digital health:** Post-pandemic acceleration has made web-based patient interaction a permanent fixture of healthcare delivery

#### Why This Framework Fits

- **No IP address collection:** The framework does not collect, store, or transmit IP addresses
- **No PII in identifiers:** WaiTags contain pure cryptographic randomness — no health information, no device signals, no personal data
- **Self-hosted deployment:** Healthcare organizations can deploy the framework on their own HIPAA-compliant infrastructure — no data leaves their environment
- **HIPAA Safe Harbor alignment:** The pseudonymous identifier meets the criteria of HIPAA's Safe Harbor de-identification standard (45 CFR §164.514(b)) because it is not derived from any of the 18 HIPAA identifiers [21]

#### Use Case

A hospital network operates `info.hospital.org` (public health information), `portal.hospital.org` (patient portal), and `pharmacy.hospital-network.org` (prescription services). The framework enables the network to understand how patients navigate from information to services to prescriptions — measuring service discovery effectiveness, portal adoption rates, and prescription fulfillment journeys — without collecting any data that constitutes PHI.

### 5.2 Financial Services (GLBA / SOX)

#### The Problem

Financial institutions operate separate web domains for banking, investment, insurance, and credit card services. Understanding customer journeys across these properties is critical for digital transformation, but:

- **GLBA (Gramm-Leach-Bliley Act)** requires financial institutions to protect the security and confidentiality of customers' nonpublic personal information (NPI) [26]
- **SOX (Sarbanes-Oxley Act)** imposes data integrity and audit requirements on publicly traded financial companies
- **FFIEC guidance** on digital banking emphasizes security controls around customer data collection
- **State-level regulations** (e.g., NYDFS 23 NYCRR 500) impose cybersecurity requirements on financial services companies operating in New York

Cross-domain analytics using cookie-based identifiers or PII creates compliance risk because the analytics data itself becomes NPI subject to GLBA safeguards — including breach notification obligations.

#### Market Opportunity

- **Financial analytics market:** $10–13B in 2025, projected to reach $19–31B by 2030 at 9–11% CAGR [27][28]
- **Banking digital analytics:** Growing at 23% CAGR driven by digital banking adoption and regulatory pressure to understand customer experience [29]
- **Compliance-driven analytics demand:** Financial institutions increasingly require privacy-by-design analytics to satisfy regulatory expectations

#### Why This Framework Fits

- **No NPI collection:** The pseudonymous identifier is not derived from and cannot be linked to nonpublic personal information
- **Audit-friendly:** DNS-based domain authorization creates a verifiable, auditable record of which domains participate in identity sharing
- **Data minimization:** Tokens contain only the pseudonymous identifier, session ID, timestamps, and domain information — no financial data, account information, or transaction details
- **Self-hosted:** The framework can operate entirely within the institution's security perimeter

#### Use Case

A bank operates `bank.com` (retail banking), `invest.bank-group.com` (investment services), and `cards.bank-group.com` (credit cards). The framework enables the bank to understand how customers discover and navigate between services — optimizing the digital cross-sell journey — without creating any NPI that triggers GLBA compliance obligations on the analytics data itself.

### 5.3 Government / Public Sector (FedRAMP)

#### The Problem

Government agencies operate multiple web domains for different services and need to understand how citizens navigate between them to optimize service delivery. However:

- **FedRAMP** requires cloud services used by federal agencies to meet stringent security standards — Google Analytics is not FedRAMP authorized [30]
- **OMB Memorandum M-10-22** restricts the use of web tracking technologies on federal websites [31]
- **Federal IT policy** generally prohibits fingerprinting, PII collection, and persistent tracking of visitors to government websites
- **Executive Order 14028** (May 2021) on improving cybersecurity requires federal agencies to adopt zero-trust architectures that minimize data collection [32]

These restrictions effectively prevent government agencies from using commercial analytics platforms for cross-domain journey analysis.

#### Market Opportunity

- **Government cloud market:** $41.56B in 2025, projected to reach $91.62B by 2030 at 17.13% CAGR [33]
- **Government analytics & AI applications:** Growing at 17.67% CAGR through 2030 (fastest-growing segment in government cloud) [33]
- **Federal digital services:** The 21st Century IDEA Act mandates digital-first government services, increasing the need for cross-domain analytics across agency websites [34]

#### Why This Framework Fits

- **Self-hosted / on-premise capable:** No data leaves the agency's infrastructure — deployable within FedRAMP-authorized environments or on-premise
- **Zero PII collection:** No IP addresses, no device fingerprints, no personally identifiable information
- **No third-party data sharing:** Unlike Google Analytics or Adobe Analytics, no data is sent to commercial third-party servers
- **DNS authorization model:** Domain participation is controlled via DNS TXT records — fully within agency IT control
- **Compliant with OMB M-10-22:** The framework's pseudonymous, consent-gated, self-hosted architecture aligns with federal web tracking restrictions

#### Use Case

A government agency operates `benefits.gov.example` (benefits information), `apply.gov.example` (application portal), and `status.gov.example` (application status). The framework enables the agency to understand how citizens navigate the benefits discovery → application → status-check journey — identifying drop-off points and optimizing service delivery — without collecting any PII or sending data to commercial analytics providers.

### 5.4 Regulated Market Revenue Potential

| Vertical | Addressable Analytics Market | Framework Penetration (3-Year Target) | Annual Revenue Potential |
|----------|---------------------------|--------------------------------------|------------------------|
| Healthcare | $19.65B (US, 2025) | 0.05% | $9.8M |
| Financial Services | $10–13B (global, 2025) | 0.05% | $5.0–6.5M |
| Government | $41.56B cloud (2025) | 0.02% | $8.3M |
| **Total regulated** | | | **$23.1–24.6M** |

Even at conservative penetration rates (0.02–0.05%), the regulated market alone represents a $23–25M annual revenue opportunity within three years.

---

## 6. Industry Vertical Adoption Map

### 6.1 Healthcare

- **Pain point:** Patient journey fragmentation across hospital, portal, pharmacy, and specialist domains. HIPAA prohibits PII-based analytics.
- **Why existing solutions fail:** Google Analytics collects IP addresses (PHI when combined with health pages). Adobe ECID is classified as personal data. Both send data to third-party servers.
- **What the framework enables:** HIPAA-compatible cross-domain patient journey mapping without PHI collection. Self-hosted deployment within the institution's compliance perimeter.
- **Market size:** $53–64B global healthcare analytics (2025) [24][25]

### 6.2 Financial Services

- **Pain point:** Customer journey fragmentation across banking, investment, insurance, and credit card domains. GLBA/SOX restrict NPI collection in analytics.
- **Why existing solutions fail:** Cookie-based identifiers create NPI subject to GLBA safeguards. Cross-domain cookie sync broken in Safari/Firefox.
- **What the framework enables:** Cross-domain digital journey analytics for financial customers without creating NPI. Audit-friendly DNS authorization.
- **Market size:** $10–13B global financial analytics (2025) [27][28]

### 6.3 Government / Public Sector

- **Pain point:** Citizens navigating between agency domains to complete tasks. Federal policy prohibits PII collection and commercial analytics data sharing.
- **Why existing solutions fail:** Google Analytics is not FedRAMP authorized. OMB M-10-22 restricts web tracking. Commercial platforms send data to third-party servers.
- **What the framework enables:** Self-hosted cross-domain analytics for government service optimization. Zero PII. No third-party data sharing.
- **Market size:** $41.56B government cloud (2025); analytics segment growing at 17.67% CAGR [33]

### 6.4 Retail / E-Commerce

- **Pain point:** Attribution breakdown between content/marketing domains and transactional domains. Multi-brand retailers lose visibility when customers cross brand boundaries.
- **Why existing solutions fail:** Third-party cookies blocked across Safari/Firefox (combined ~21% desktop, ~30% mobile). GA4 cross-domain tracking only works on `<a>` tag clicks with `_gl` parameter.
- **What the framework enables:** Deterministic cross-domain conversion attribution for content → commerce journeys. Works across separate brands/domains without shared analytics properties.
- **Market size:** Retail analytics is the largest vertical in web analytics, representing ~25% of the $6–8B web analytics market [3][4]

### 6.5 Media / Publishing

- **Pain point:** Content engagement fragmentation across multiple editorial properties (news, sports, video, opinion). Audience understanding limited to single-property silos.
- **Why existing solutions fail:** Multi-domain publishers cannot use a single GA4 property across independently operated editorial brands. Adobe CJA cross-domain sync breaks in Safari.
- **What the framework enables:** Cross-property reader journey analytics. Understanding how audiences move between editorial brands. Content strategy optimization based on cross-domain engagement patterns.
- **Market size:** Media & publishing represent ~15% of the web analytics market [3]

### 6.6 SaaS / Multi-Product

- **Pain point:** A/B testing consistency across marketing site and product application on different domains. Experiment group assignment lost at domain boundary.
- **Why existing solutions fail:** GA4 cross-domain requires same Measurement ID — impractical for separate marketing and product analytics. Cookie-based A/B tools (Optimizely, VWO) lose identity at domain boundaries in Safari/Firefox.
- **What the framework enables:** Consistent experiment assignment across marketing → product navigation. Cross-domain funnel analytics without requiring user authentication.
- **Market size:** SaaS analytics is a high-growth segment; A/B testing market projected at $1.6B by 2027 [35]

---

## 7. Licensing Model & Revenue Tiers

### 7.1 Dual-License Structure

The framework uses a dual-license model designed to maximize adoption (open-source core) while monetizing the high-value cross-domain capability:

| Component | License | Cost |
|-----------|---------|------|
| **Core SDK** — single-domain tracking, event batching, retry logic, performance monitoring | MIT (open source) | Free forever |
| **Cross-Domain Identity** — protocol implementation, pseudonymous identity transfer, DNS authorization, encrypted configuration | Commercial | Tiered pricing |

### 7.2 Commercial Tier Structure

| Tier | Target | Event Volume | Domains | Annual Price Range | Features |
|------|--------|-------------|---------|-------------------|----------|
| **Community** | Developers, startups, evaluation | <10K events/month | Up to 3 | Free | Cross-domain identity, community support |
| **Startup** | Growing companies | 10K–1M events/month | Up to 10 | $12K–$36K/year | SLA, email support, onboarding |
| **Enterprise** | Large organizations | 1M–100M events/month | Unlimited | $60K–$180K/year | Dedicated support, custom SLA, deployment assistance, regulatory compliance documentation |
| **OEM / White-Label** | Analytics platforms, CDPs, system integrators | Unlimited | Unlimited | Custom (revenue share or flat license) | Full protocol integration rights, co-branding, sub-licensing rights |

### 7.3 Pricing Logic

Pricing is indexed to two dimensions that correlate with customer value:

1. **Event volume** — Higher event volumes indicate larger digital operations and greater value from cross-domain analytics
2. **Domain count** — More domains indicate more complex digital ecosystems with more cross-domain identity needs

This creates natural tier progression as customers grow: startups begin with 2–3 domains and graduate to enterprise as they expand their digital footprint.

### 7.4 OEM / White-Label Opportunity

The OEM tier represents the highest-value licensing opportunity. Potential OEM partners include:

- **Customer Data Platforms (CDPs):** Segment, mParticle, Tealium — need cross-domain identity as a feature within their identity resolution stack
- **Analytics platforms:** Mixpanel, Amplitude, Heap — lack native cross-domain identity capability
- **Tag management systems:** Tealium iQ, Google Tag Manager competitors — could embed cross-domain identity as a premium feature
- **System integrators:** Accenture, Deloitte Digital, Publicis Sapient — could license the protocol for client implementations
- **Regional analytics providers:** Privacy-first analytics companies in the EU (Matomo, Piwik PRO, Plausible) — could differentiate with cross-domain capability

---

## 8. Revenue Projection Model

### 8.1 Assumptions

| Assumption | Conservative | Moderate | Aggressive |
|-----------|-------------|---------|-----------|
| Year 1 Enterprise customers | 5 | 12 | 25 |
| Year 1 Startup customers | 20 | 50 | 100 |
| Year 2 growth rate | 80% | 120% | 180% |
| Year 3 growth rate | 60% | 100% | 150% |
| Enterprise ACV | $90K | $120K | $150K |
| Startup ACV | $24K | $30K | $36K |
| OEM deals (Year 2+) | 1 | 2 | 4 |
| OEM ACV | $200K | $350K | $500K |
| Net Revenue Retention | 110% | 120% | 130% |
| Churn rate | 15% | 10% | 5% |

**ACV = Annual Contract Value**

### 8.2 Three-Year Revenue Projection

#### Conservative Scenario

| Metric | Year 1 | Year 2 | Year 3 |
|--------|--------|--------|--------|
| Enterprise customers | 5 | 9 | 14 |
| Startup customers | 20 | 36 | 58 |
| OEM deals | 0 | 1 | 1 |
| Enterprise revenue | $450K | $810K | $1.26M |
| Startup revenue | $480K | $864K | $1.39M |
| OEM revenue | $0 | $200K | $200K |
| **Total ARR** | **$930K** | **$1.87M** | **$2.85M** |

#### Moderate Scenario

| Metric | Year 1 | Year 2 | Year 3 |
|--------|--------|--------|--------|
| Enterprise customers | 12 | 26 | 53 |
| Startup customers | 50 | 110 | 220 |
| OEM deals | 0 | 2 | 3 |
| Enterprise revenue | $1.44M | $3.12M | $6.36M |
| Startup revenue | $1.50M | $3.30M | $6.60M |
| OEM revenue | $0 | $700K | $1.05M |
| **Total ARR** | **$2.94M** | **$7.12M** | **$14.01M** |

#### Aggressive Scenario

| Metric | Year 1 | Year 2 | Year 3 |
|--------|--------|--------|--------|
| Enterprise customers | 25 | 70 | 175 |
| Startup customers | 100 | 280 | 700 |
| OEM deals | 0 | 4 | 8 |
| Enterprise revenue | $3.75M | $10.50M | $26.25M |
| Startup revenue | $3.60M | $10.08M | $25.20M |
| OEM revenue | $0 | $2.00M | $4.00M |
| **Total ARR** | **$7.35M** | **$22.58M** | **$55.45M** |

### 8.3 Revenue Mix Evolution

| Revenue Source | Year 1 | Year 2 | Year 3 |
|---------------|--------|--------|--------|
| Enterprise licensing | 49% | 44% | 45% |
| Startup licensing | 51% | 46% | 47% |
| OEM / white-label | 0% | 10% | 8% |

The OEM channel becomes meaningful in Year 2 and represents the highest-leverage revenue source — a single OEM integration into a major CDP or analytics platform can drive hundreds of downstream customers.

### 8.4 Path to Profitability

Assuming a lean team (5–8 people in Year 1, 12–18 in Year 2, 20–30 in Year 3):

| Cost Category | Year 1 | Year 2 | Year 3 |
|--------------|--------|--------|--------|
| Engineering (50% of spend) | $600K | $1.2M | $2.0M |
| Sales & Marketing (30%) | $360K | $720K | $1.2M |
| G&A (20%) | $240K | $480K | $800K |
| **Total costs** | **$1.2M** | **$2.4M** | **$4.0M** |

- **Conservative:** Not yet cash-flow positive in Year 3 ($2.85M ARR vs. $4.0M costs) — requires bridge funding or leaner cost structure; break-even projected in Year 4 assuming continued 60% growth
- **Moderate:** Cash-flow positive in Year 2 ($7.12M ARR vs. $2.4M costs)
- **Aggressive:** Cash-flow positive in Year 1 ($7.35M ARR vs. $1.2M costs)

---

## 9. Competitive Moat & Valuation Drivers

### 9.1 Defensibility

| Moat | Description | Durability |
|------|------------|-----------|
| **Patent-pending algorithm** | U.S. Non-Provisional Patent Application covering cross-domain pseudonymous identity transfer | 20 years from filing |
| **Standards-track protocol** | IETF Internet-Draft and W3C Privacy CG proposal create standards-body credibility and potential industry-standard positioning | Long-term — standards adoption creates winner-take-all dynamics |
| **First-mover advantage** | No existing solution addresses the specific gap (privacy-preserving anonymous cross-domain identity). First to market with a working protocol and reference implementation | Medium-term — defensible while competitors build from scratch |
| **Open-source community** | MIT-licensed core SDK drives adoption, community contributions, and ecosystem lock-in | Long-term — community momentum compounds |
| **Regulatory tailwind** | GDPR, HIPAA, GLBA, FedRAMP, and CCPA all push toward privacy-by-design analytics. This framework is positioned to benefit from every tightening of privacy regulation | Long-term — regulatory trend is unidirectional |
| **Network effects** | Each domain that deploys the SDK increases the value for every other domain in the same organization's network. OEM integrations amplify this effect | Medium-term — grows with adoption |

### 9.2 Valuation Framework

Based on 2025 SaaS and IP licensing valuation benchmarks:

| Valuation Method | Multiple | Applied To | Implied Valuation (Moderate, Year 3) |
|-----------------|----------|-----------|--------------------------------------|
| **Revenue multiple (SaaS median)** | 5.1–6.1x ARR | $14.01M ARR | $71.5M–$85.5M |
| **Revenue multiple (data infrastructure)** | 6.2x ARR | $14.01M ARR | $86.9M |
| **Revenue multiple (analytics/BI)** | 5.0–5.5x ARR | $14.01M ARR | $70.1M–$77.1M |
| **EBITDA multiple (profitable SaaS)** | 12.7–22.4x | ~$10M EBITDA | $127M–$224M |
| **IP licensing premium** | +30–50% to base | Patent-pending + standards-track | Additional premium |

**Conservative Year 3 valuation:** $70–86M (revenue multiple)
**Moderate Year 3 valuation:** $86–127M (revenue + profitability multiples)
**Aggressive Year 3 valuation:** $224M+ (EBITDA multiple with IP premium)

### 9.3 Key Valuation Drivers

1. **Recurring revenue:** Commercial licensing creates predictable, high-margin ARR with 110–130% net revenue retention
2. **IP portfolio:** Patent-pending technology + standards-track protocol creates defensible intellectual property
3. **Regulatory tailwind:** Every privacy regulation tightening increases the value of privacy-by-design analytics
4. **Platform potential:** OEM licensing transforms the framework from a point solution to a platform technology embedded across the analytics ecosystem
5. **Standards adoption:** If WTX-1 achieves IETF RFC status or W3C recommendation, the framework becomes the reference implementation of an industry standard — historically associated with significant valuation premiums
6. **Academic validation:** Peer-reviewed publication in a high-impact journal (Decision Support Systems, IF 6.8) provides credibility that pure commercial products lack
7. **AI integration premium:** 2025 SaaS valuations show a +15–30% premium for meaningful AI integration [36] — the framework's measurable security properties and automated identity resolution align with this trend

### 9.4 Exit Scenarios

| Scenario | Likely Acquirers | Strategic Rationale |
|----------|-----------------|-------------------|
| **Strategic acquisition** | Adobe, Salesforce, Oracle, SAP | Fill the cross-domain identity gap in their analytics suites |
| **Analytics platform acquisition** | Amplitude, Mixpanel, Heap, PostHog | Add cross-domain capability as competitive differentiator |
| **CDP acquisition** | Segment (Twilio), mParticle, Tealium | Enhance identity resolution with privacy-preserving cross-domain identity |
| **Privacy-tech consolidation** | OneTrust, BigID, Securiti | Expand from compliance into privacy-preserving analytics |
| **IPO / independent growth** | — | Build standalone analytics infrastructure company |

---

## 10. References

### Source Quality Note

The references below are categorized by source type for diligence purposes:

- **Primary sources** (regulatory texts, vendor documentation, IETF/W3C submissions, patent filings): References [1], [2], [12]–[19], [21]–[23], [26], [30]–[32], [34]
- **Named analyst reports** (MarketsandMarkets, Mordor Intelligence, Grand View Research, Fortune Business Insights, Verified Market Research, eMarketer): References [3]–[5], [11], [24], [25], [27]–[29], [33], [35]
- **Industry analysis / secondary sources** (CMA testing reports, blog posts, community discussions, benchmark reports, valuation analyses): References [6]–[10], [20], [36]–[39]
- **Internal estimates** (revenue projections in Section 8 are modeled assumptions, not externally sourced. They are based on comparable SaaS growth trajectories and are clearly labeled with underlying assumptions in Section 8.1.)

Platform pricing estimates for Adobe Experience Cloud and GA4 360 (references [38], [39]) are industry-consensus ranges — neither vendor publicly lists pricing. These figures are consistent with implementation partner quotes, Gartner/Forrester reports, and publicly available case studies.

---

[1] IETF Internet-Draft: draft-surampudi-wtx1-01. Available at: https://datatracker.ietf.org/doc/draft-surampudi-wtx1/

[2] W3C Privacy Community Group. Proposals repository: https://github.com/privacycg/proposals

[3] Mordor Intelligence. "Web Analytics Market Size & Share Analysis — Growth Trends & Forecasts (2025–2030)." 2025. Valued web analytics market at $7.98B (2025), projected $16.36B (2030) at 15.4% CAGR. https://www.mordorintelligence.com/industry-reports/web-analytics-market

[4] Research and Markets / 360iResearch. "Web Analytics Global Market Report." 2025. Valued web analytics market at $6.19–7.48B (2025), projected $19.10–19.14B (2030) at 20.5–20.7% CAGR. https://www.researchandmarkets.com/reports/5027990/web-analytics-market-report

[5] Verified Market Research. "Web Analytics Market Size and Forecast." 2025. Valued web analytics market at $6.16B (2025), projected $24.07B (2030) at 18.6% CAGR. https://www.verifiedmarketresearch.com/product/web-analytics-market/

[6] StatCounter GlobalStats. Browser market share worldwide (2025). https://gs.statcounter.com/browser-market-share

[7] Google Privacy Sandbox. "Update on Plans for Privacy Sandbox Technologies." October 17, 2025. Announced retirement of Privacy Sandbox advertising APIs (Topics, Protected Audience, Attribution Reporting). CMA released Google from Privacy Sandbox commitments on the same date. Chrome announced cancellation of forced cookie deprecation in July 2024. https://privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies

[8] UK Competition and Markets Authority (CMA). "Summary of Testing of Google Privacy Sandbox Proposals." Published June 13, 2025. PDF report documenting revenue impact testing: Privacy Sandbox APIs showed -27% to -30% revenue per impression compared to third-party cookies. https://assets.publishing.service.gov.uk/media/684bee68df3ce2ce31e3f948/Summary_of_testing_of_Google_Privacy_Sandbox_proposals.pdf

[9] GroupM / WPP. Cookie deprecation impact analysis, as reported in Marketing Dive: "GroupM, Google launch post-cookie readiness program as deprecation nears" (2024). Industry consensus estimate of -20% to -30% total ad revenue without cookie-based measurement. https://www.marketingdive.com/news/groupm-google-chrome-third-party-cookie-deprecation/699908/

[10] Statista. "Impact of third-party cookie deprecation on business revenue worldwide 2023." Survey data on anticipated revenue impact from cookie deprecation. EU cookie lifetime restriction (-€904M annual impact) derived from academic modeling cited in AdGuard's Privacy Sandbox analysis (2025). https://www.statista.com/statistics/1410456/impact-3rd-party-cookie-deprecation-revenue-worldwide/

[11] eMarketer / Insider Intelligence. "US Digital Ad Spending to Exceed $300 Billion in 2024." Report: $309.3B total US digital ad spend in 2024, +15.1% YoY. https://www.emarketer.com/content/us-digital-ad-spend-exceed--300-billion-2024

[12] Adobe Experience League. "Cookies and the Experience Cloud Identity Service." Documentation on ITP impact: AMCV cookies capped at 7 days under Safari ITP. https://experienceleague.adobe.com/en/docs/id-service/using/reference/analytics-reference/analytics-ids

[13] Berners-Lee, T., Fielding, R., and L. Masinter. "Uniform Resource Identifier (URI): Generic Syntax." RFC 3986, Section 3.5. January 2005. https://www.rfc-editor.org/rfc/rfc3986#section-3.5

[14] IRTF Privacy Enhancements and Assessments Research Group (PEARG). Charter and mailing list: pearg@ietf.org. https://irtf.org/pearg

[15] Adobe Experience League. "appendVisitorIDsTo (Cross-Domain Tracking)." Documentation on cross-domain tracking limitations. https://experienceleague.adobe.com/en/docs/id-service/using/id-service-api/methods/appendvisitorid

[16] European Parliament and Council. "General Data Protection Regulation (GDPR)." Regulation (EU) 2016/679, Article 4(1) — definition of personal data includes "an identification number" and "an online identifier." https://eur-lex.europa.eu/eli/reg/2016/679/oj

[17] Adobe Experience League Community. Discussions on cross-domain tracking limitations with Web SDK and Safari. https://experienceleaguecommunities.adobe.com/t5/adobe-analytics-questions/cross-domain-tracking-implementation-with-adobe-web-sdk/td-p/612771

[18] Adobe Experience League. "First-Party Device IDs in Web SDK." Documentation confirming FPID is single-domain only. https://experienceleague.adobe.com/en/docs/experience-platform/edge/identity/first-party-device-ids

[19] Google Analytics Help. "Set up cross-domain measurement." GA4 documentation on `_gl` parameter, link-click requirement, and Enhanced Measurement impact. https://support.google.com/analytics/answer/10071811

[20] Simo Ahava. "Cross-domain Tracking In Google Analytics 4." Simmer (simoahava.com), 2024. Documents GA4 cross-domain linker behavior and failure modes, including session fragmentation when `_gl` parameter is stripped by redirects, payment platforms, or parameter-filtering landing pages. Session and user count inflation of 30–50% is a widely observed implementation pattern. https://www.simoahava.com/gtm-tips/cross-domain-tracking-google-analytics-4/

[21] U.S. Department of Health and Human Services. "HIPAA Privacy Rule." 45 CFR §164.514 — Standards for de-identification of protected health information. https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html

[22] U.S. Department of Health and Human Services, Office for Civil Rights. "Use of Online Tracking Technologies by HIPAA Covered Entities and Business Associates." Bulletin, December 2022. https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/hipaa-online-tracking/index.html

[23] Federal Trade Commission. Enforcement actions against telehealth companies for sharing health data with advertising platforms via tracking pixels. 2023. https://www.ftc.gov/news-events/news/press-releases

[24] MarketsandMarkets. "Healthcare Analytics Market worth $166.65 billion by 2030." Press release (PR Newswire), 2025. Global healthcare analytics market valued at $55.52B (2025), projected $166.65B (2030) at 24.6% CAGR. US market: $19.65B (2025). https://www.prnewswire.com/news-releases/healthcare-analytics-market-worth-166-65-billion-by-2030--marketsandmarkets-302668799.html

[25] Grand View Research. "Healthcare Analytics Market Size, Share & Trends Analysis Report." 2025. Valued at $52.98B (2025), projected $198.79B by 2033 at 14.85% CAGR. https://www.grandviewresearch.com/industry-analysis/healthcare-analytics-market

[26] Federal Trade Commission. "Gramm-Leach-Bliley Act." Financial privacy requirements for NPI protection. https://www.ftc.gov/legal-library/browse/statutes/gramm-leach-bliley-act

[27] Mordor Intelligence. "Financial Analytics Market Size, Share & Industry Trends Report, 2030." 2025. Valued at $12.49B (2025), projected $21.27B (2030) at 11.24% CAGR. https://www.mordorintelligence.com/industry-reports/financial-analytics-market

[28] Fortune Business Insights. "Financial Analytics Market Size, Share & Industry Analysis." 2025. Valued at $10.70B (2025), projected $22.64B by 2032 at 11.3% CAGR. https://www.fortunebusinessinsights.com/financial-analytics-market-103015

[29] Mordor Intelligence. "Big Data Analytics in Banking Market Size & Share Analysis." 2025. Growing at 23.11% CAGR. https://www.mordorintelligence.com/industry-reports/big-data-analytics-in-banking-market

[30] FedRAMP. Federal Risk and Authorization Management Program. Google Analytics is not listed as a FedRAMP-authorized service. https://marketplace.fedramp.gov/

[31] Office of Management and Budget. "Memorandum M-10-22: Guidance for Online Use of Web Measurement and Customization Technologies." June 2010. https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2010/m10-22.pdf

[32] The White House. "Executive Order 14028: Improving the Nation's Cybersecurity." May 2021. https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/

[33] MarketsandMarkets. "Government Cloud Market — Global Forecast to 2030." 2025. Government cloud market valued at $41.56B (2025), projected $91.62B (2030) at 17.13% CAGR. Analytics & AI applications segment growing at 17.67% CAGR (fastest-growing segment). https://www.marketsandmarkets.com/Market-Reports/government-cloud-market-29202961.html

[34] 21st Century Integrated Digital Experience Act (21st Century IDEA). Public Law 115-336. December 2018. Mandates digital-first government services. https://www.congress.gov/bill/115th-congress/house-bill/5759

[35] Verified Market Research. "A/B Testing Software Market Size and Forecast." Market report projecting A/B testing software market at $1.6B by 2027. https://www.verifiedmarketresearch.com/product/ab-testing-software-market/

[36] Aventis Advisors. "SaaS Valuation Multiples: 2015–2025." Analysis of public and private SaaS valuation benchmarks, including AI integration premiums of +15–30% for companies with meaningful AI capabilities (not "AI wrappers"). Data sourced from public market filings and SaaS Capital Index. https://aventis-advisors.com/saas-valuation-multiples/

[37] Contentsquare. "2024 Digital Experience Benchmarks." Industry benchmark data showing that the majority of web traffic across most industries is anonymous/unauthenticated, with login rates typically between 10–30% depending on vertical. The 70–90% anonymous traffic estimate is consistent across Contentsquare, Similarweb, and Adobe Digital Economy Index reports. https://contentsquare.com/insights/digital-experience-benchmark/

[38] Google. GA4 360 is an enterprise-tier product with pricing that varies by data volume and contract terms. The ~$50,000/year starting price is a widely cited industry estimate based on the legacy Analytics 360 pricing structure and confirmed by multiple Google Analytics consultancies and implementation partners. Google does not publicly list GA4 360 pricing. https://marketingplatform.google.com/about/analytics-360/

[39] Adobe. Experience Cloud pricing is custom and not publicly listed. The $100K–$500K+/year range for Adobe Analytics / Customer Journey Analytics is a widely cited industry estimate based on Gartner, Forrester, and implementation partner reports. Actual pricing varies significantly by contract scope, data volume, and bundled products. https://business.adobe.com/products/analytics/adobe-analytics.html
