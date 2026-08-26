#!/usr/bin/env node
/**
 * check-draft-consistency.js
 *
 * Cross-checks the IETF draft's generated text against the reference
 * implementation's actual endpoint contract, so the document cannot drift
 * from the code without this check failing. Guards against exactly the
 * class of bug where the spec names one grant scope, error code, or
 * response shape and the server enforces another.
 *
 * Checks:
 *   1. Per-endpoint write-grant scopes in server/api/waitag-tracking.ts
 *      match what the draft states (e.g. verification under `ingest`).
 *   2. Every externally surfaced error code emitted by the token and grant
 *      endpoints appears in the draft text.
 *   3. Response-branch inspection: every res.status(...).json(...) branch
 *      of the verification handler fits the contract documented in draft
 *      Section 6.4 -- coded 403s, the MALFORMED_TOKEN 400/403 split, the
 *      grant-enforcement statuses from grant.ts, and exactly the documented
 *      message-only HTTP 400/500 responses (no undocumented no-code
 *      branches). test/verify-error-contract.test.js pins the same
 *      contract behaviorally.
 *   4. Known-stale vocabulary (DOMAIN_NOT_AUTHORIZED, a request-body
 *      "referrer" member) does not reappear in the draft or prose spec.
 *
 * Usage: node scripts/check-draft-consistency.js
 * Exit 0 = consistent; exit 1 = drift found (each problem listed).
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DRAFT_TXT = path.join(ROOT, 'docs/ietf/draft-surampudi-wtx1-02.txt');

const read = (p) => fs.readFileSync(p, 'utf8');

const draftRaw = read(DRAFT_TXT);
// Collapse whitespace so phrases survive the 72-column line wrapping.
const draft = draftRaw.replace(/\s+/g, ' ');

// Multi-word phrase matching must tolerate line wraps, including xml2rfc's
// breaks after hyphens ("human-\n readable" -> "human- readable").
const hasPhrase = (p) => new RegExp(
  p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/-/g, '-\\s*').replace(/ /g, '\\s+')
).test(draft);

const problems = [];

const tracking = read(path.join(ROOT, 'server/api/waitag-tracking.ts'));
const grantSrc = read(path.join(ROOT, 'server/api/grant.ts'));

function handlerSlice(src, route) {
  const start = src.indexOf(`app.post("${route}"`);
  if (start === -1) return null;
  const next = src.indexOf('app.post(', start + 10);
  return src.slice(start, next === -1 ? src.length : next);
}

// ------------------------------------------------------------- scopes
function scopeOf(route) {
  const slice = handlerSlice(tracking, route);
  if (!slice) return null;
  const m = slice.match(/requireWriteGrant\(req,\s*'(\w+)'\)/);
  return m ? m[1] : null;
}

const scopes = {
  verify: scopeOf('/api/tracking/verify-cross-domain-token'),
  register: scopeOf('/api/tracking/register-waitag'),
  event: scopeOf('/api/tracking/event'),
};

for (const [k, v] of Object.entries(scopes)) {
  if (!v) problems.push(`could not extract the grant scope of the ${k} endpoint from waitag-tracking.ts`);
}

if (scopes.verify && !hasPhrase(`bearing the ${scopes.verify} scope`)) {
  problems.push(`draft must state that verification requires a grant bearing the "${scopes.verify}" scope (code: requireWriteGrant(req, '${scopes.verify}'))`);
}
if (scopes.verify && scopes.event && scopes.verify === scopes.event) {
  if (!hasPhrase(`${scopes.verify} authorizes event ingestion and token verification`)) {
    problems.push(`draft's scope definition must say "${scopes.verify} authorizes event ingestion and token verification"`);
  }
} else if (scopes.verify !== scopes.event) {
  problems.push('verify and event endpoints use different scopes; the draft scope definitions need rewriting');
}
if (scopes.register && !hasPhrase(`${scopes.register} authorizes identifier registration`)) {
  problems.push(`draft's scope definition must say "${scopes.register} authorizes identifier registration"`);
}

// -------------------------------------------------------- error codes
// Externally surfaced codes from the token exchange + grant subsystem.
const required = new Set();
const collect = (src, skip = new Set()) => {
  for (const m of src.matchAll(/error:\s*'([A-Z][A-Z_]+)'/g)) {
    if (!skip.has(m[1])) required.add(m[1]);
  }
};

// token-core: all verification codes. NO_SECRET is internal-only — the
// routes fail closed before verify can run without a secret.
collect(read(path.join(ROOT, 'server/utils/token-core.js')), new Set(['NO_SECRET']));

// waitag-tracking: only the two cross-domain token handlers (registration
// and event ingestion have their own input-validation codes outside the
// draft's normative token exchange).
for (const route of ['/api/tracking/verify-cross-domain-token', '/api/tracking/generate-cross-domain-token']) {
  collect(handlerSlice(tracking, route) || '');
}

// grant.ts: issuance + enforcement codes.
collect(grantSrc);

// write-grant.js verify() failures surface as GRANT_<suffix> via grant.ts.
for (const m of read(path.join(ROOT, 'server/utils/write-grant.js')).matchAll(/error:\s*'([A-Z][A-Z_]+)'/g)) {
  if (m[1] !== 'NO_SECRET') required.add('GRANT_' + m[1]);
}

for (const code of [...required].sort()) {
  if (!draft.includes(code)) {
    problems.push(`error code ${code} is emitted by the implementation but missing from the draft text`);
  }
}

// ------------------------------------- response-branch inspection (§6.4)
const verifySlice = handlerSlice(tracking, '/api/tracking/verify-cross-domain-token') || '';
if (!verifySlice) problems.push('could not locate the verification handler in waitag-tracking.ts');

const branches = [];
for (const m of verifySlice.matchAll(/res\.status\(([^)]+)\)\.json\(\{([\s\S]*?)\}\)/g)) {
  const body = m[2];
  const lit = body.match(/error:\s*'([A-Z_]+)'/);
  branches.push({ status: m[1].trim(), code: lit ? lit[1] : null, hasError: /error\s*:/.test(body) });
}

const fits = (b) =>
  (b.status === '400' && !b.hasError) ||            // structural, message-only
  (b.status === '500' && !b.hasError) ||            // internal, message-only
  (b.status === '403' && b.hasError) ||             // coded authorization/binding
  (b.status === 'failure.status' && b.hasError) ||  // grant enforcement (grant.ts)
  (b.status === 'status' && b.hasError);            // MALFORMED_TOKEN 400/403 split

for (const b of branches.filter((b) => !fits(b))) {
  problems.push(`verify-handler branch res.status(${b.status}) ${b.hasError ? `with code ${b.code || '<dynamic>'}` : 'without an error member'} does not fit the response contract of draft Section 6.4 -- update the draft`);
}

const messageOnly400 = branches.filter((b) => b.status === '400' && !b.hasError).length;
if (messageOnly400 !== 3) {
  problems.push(`expected exactly 3 message-only HTTP 400 branches (missing token, missing domain, invalid domain) in the verify handler; found ${messageOnly400} -- update draft Sections 6.1/6.4`);
}
const messageOnly500 = branches.filter((b) => b.status === '500' && !b.hasError).length;
if (messageOnly500 !== 1) {
  problems.push(`expected exactly 1 message-only HTTP 500 branch in the verify handler; found ${messageOnly500} -- update draft Section 6.4`);
}
if (!/result\.error\s*===\s*'MALFORMED_TOKEN'\s*\?\s*400\s*:\s*403/.test(verifySlice)) {
  problems.push('verify handler no longer maps MALFORMED_TOKEN to 400 and all other token failures to 403 -- update draft Section 6.4');
}
for (const b of branches) {
  if (b.code && !draft.includes(b.code)) {
    problems.push(`verify-handler literal error code ${b.code} missing from the draft text`);
  }
}

// Grant-enforcement statuses documented in Sections 6.4/8.3 come from grant.ts.
if (!/status:\s*401,\s*error:\s*'GRANT_REQUIRED'/.test(grantSrc)) {
  problems.push('grant.ts no longer maps GRANT_REQUIRED to HTTP 401 -- update draft Sections 6.4/8.3');
}
if (!/status:\s*503,\s*error:\s*'GRANTS_UNAVAILABLE'/.test(grantSrc)) {
  problems.push('grant.ts no longer maps GRANTS_UNAVAILABLE to HTTP 503 -- update draft Sections 6.4/8.3');
}
if (!/status:\s*403,\s*error:\s*'GRANT_'\s*\+/.test(grantSrc)) {
  problems.push('grant.ts no longer maps grant-validation failures to HTTP 403 GRANT_* -- update draft Sections 6.4/8.3');
}

// The draft must document the two message-only response classes.
if (!hasPhrase('carry only a human-readable message')) {
  problems.push('draft Section 6.4 must document the message-only HTTP 400/500 responses (expected phrase "carry only a human-readable message")');
}

// --------------------------------------------------- stale vocabulary
if (draft.includes('DOMAIN_NOT_AUTHORIZED')) {
  problems.push('draft still contains DOMAIN_NOT_AUTHORIZED (implementation emits DOMAIN_NOT_VERIFIED)');
}
if (draftRaw.includes('"referrer"')) {
  problems.push('draft shows a "referrer" member in a request body; the verification endpoint does not consume one');
}
if (read(path.join(ROOT, 'docs/WTX-1-SPEC.md')).includes('DOMAIN_NOT_AUTHORIZED')) {
  problems.push('docs/WTX-1-SPEC.md still contains DOMAIN_NOT_AUTHORIZED');
}

// ------------------------------------------------------------- report
if (problems.length) {
  console.error(`DRAFT CONSISTENCY: ${problems.length} problem(s):\n`);
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}
console.log(
  `Draft consistency OK: scopes { verify: ${scopes.verify}, register: ${scopes.register}, event: ${scopes.event} }; ` +
  `${required.size} implementation error codes all present; ` +
  `${branches.length} verify-handler response branches all fit the documented contract; no stale vocabulary.`
);
