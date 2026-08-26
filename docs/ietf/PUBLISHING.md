# Publishing draft-surampudi-wtx1-02

The draft is ready for submission. Submission to the IETF Datatracker is a
manual, author-run step — it requires the author's Datatracker account and
email confirmation, so no tool here performs it.

## Files

| File | Role |
|---|---|
| `draft-surampudi-wtx1-02.xml` | Canonical source (RFCXML v3). Edit this one. |
| `draft-surampudi-wtx1-02.txt` | Generated. Submission format. |
| `draft-surampudi-wtx1-02.html` | Generated. For convenience/review. |

## Regenerating outputs after any XML edit

```sh
export PATH="/home/runner/workspace/.local/bin:$PATH"   # xml2rfc lives here
xml2rfc --text docs/ietf/draft-surampudi-wtx1-02.xml -o docs/ietf/draft-surampudi-wtx1-02.txt
xml2rfc --html docs/ietf/draft-surampudi-wtx1-02.xml -o docs/ietf/draft-surampudi-wtx1-02.html
```

Both must be regenerated together so the three artifacts stay synchronized.
The current XML compiles with zero errors and zero warnings; keep it that way.

## Pre-submission checklist

0. **Spec-vs-implementation consistency**: run
   `node scripts/check-draft-consistency.js`. It cross-checks the draft text
   against the implementation's endpoint contract (write-grant scopes per
   endpoint, every surfaced error code, stale vocabulary) and fails on drift.
   Run it after any edit to the draft XML **or** to the server's token/grant
   code, and always regenerate the `.txt` first — the script reads the
   generated text.
1. **Date**: `<date year="2026" month="August" day="26"/>` in the XML should be
   the actual submission date. Update and regenerate if submitting later.
2. **Author details**: verify name, organization, and email in `<author>` are
   the ones to publish (they appear verbatim in the public document).
3. **Repository URL**: Section 17 (Implementation Status) links the GitHub
   repository. Confirm it is the URL you want public, and that the repo's
   license text matches the "dual license" description.
4. **Nits**: run the official checker on the generated text —
   <https://author-tools.ietf.org/idnits> (upload the `.txt`). The local
   toolchain does not include idnits; this is a browser step.
5. **Diff against draft-01**: sanity-check with
   <https://author-tools.ietf.org/iddiff> (upload `-01.txt` and `-02.txt`)
   and confirm the change log (Appendix A) matches what the diff shows.

## Submitting

1. Go to <https://datatracker.ietf.org/submit/>.
2. Upload `draft-surampudi-wtx1-02.xml` (XML is the preferred submission
   format; the Datatracker regenerates text/HTML itself).
3. The Datatracker checks that the name (`draft-surampudi-wtx1-02`) is the
   next revision of the existing series and emails a confirmation link to the
   author address — click it to complete posting.
4. After posting, the draft appears at
   <https://datatracker.ietf.org/doc/draft-surampudi-wtx1/>.

## After posting (optional, author's call)

- Announce the revision on the PEARG list (`pearg@irtf.org`) referencing the
  earlier discussion thread; the draft's anti-tracking interaction section
  (14.6) explicitly invites that review.
- Drafts expire 185 days after posting. Set a reminder to either revise or
  re-post before expiry (the expiry date is printed on page 1).
