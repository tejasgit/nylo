---
name: Nylo claims & licensing alignment
description: Rules for keeping privacy/licensing claims truthful across README, protocol docs, and package metadata.
---

# Claims & licensing alignment

- **Identity layer is not feature-gated.** After consent, the SDK always persists a WaiTag, registers it server-side, and processes cross-domain tokens — independent of the 23 event feature toggles (which do all default off). Docs must never claim cross-domain identity is "off by default"; only event reporting is toggled.
  **Why:** Completion review rejected docs that implied feature toggles gated identity/sync.
- **Wording standard:** "no third-party cookies", "no direct identifiers collected by default", "pseudonymous, not anonymous" (personal data under GDPR-style regimes), `identify()` linkage disclosed wherever WaiTag anonymity is discussed — including generated IETF draft artifacts (`docs/ietf/*.txt/.xml/.html`), which must be edited/regenerated in lockstep with the markdown spec.
- **Licensing:** package is dual-licensed (`"license": "SEE LICENSE IN LICENSING.md"`). Mixed-license SDK file uses `LicenseRef-Nylo-Dual` (defined in LICENSING.md) — do NOT use `MIT AND LicenseRef-Nylo-Commercial` (SPDX AND applies both licenses to the whole file). Every source file needs an SPDX header; LICENSING.md's file table must match actual headers exactly. Attorney review still pending — keep the "provisional" caveat.
- **Still stale:** marketing drafts in `github/` (DEVTO, MEDIUM, DAILYDEV, VALUE-PROPOSITION, STARTER-ISSUES) retain old "No PII / No cookies / MIT" claims; fix before publishing. (Follow-up task could not be recorded due to a platform task-ref bug.)
