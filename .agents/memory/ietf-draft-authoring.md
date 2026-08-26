---
name: IETF draft authoring
description: Durable lessons for writing or revising the WTX-1 Internet-Drafts
---

# Toolchain
- xml2rfc lives in the workspace-local tool bin, which is not on the default
  shell PATH — export it before compiling. Always regenerate text and HTML
  together so published artifacts never drift from the XML.
- RFCXML v3: anchors must not start with `table-`, `figure-`, `section-`,
  `iref-`, or `u-`; every `<reference>` needs a citing `<xref>`; keep
  artwork/sourcecode within 72 columns. idnits is a browser step
  (author-tools.ietf.org), not a local install.
- Reference-URL checking: some sites 404 on HEAD but 200 on a browser-UA
  GET — confirm with GET before "fixing" a citation.

# Wire-truth rule for protocol claims
Endpoint handlers are the only source of truth for wire behavior; prose
docs and older drafts drift (stale error names, wrong scope-to-endpoint
mappings, undocumented message-only responses).

**Why:** normative text copied from prose has contradicted what the server
actually returns.

**How to apply:** before writing a normative claim, read the handler and
capture the full response contract per branch — HTTP status, body members,
and error code or its documented absence — and keep the repo's automated
draft-vs-implementation consistency check and the behavioral contract
tests in lockstep with every new claim.
