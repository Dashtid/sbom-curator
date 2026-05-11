# Architecture

## Problem

A hand-curated SBOM (SPDX 2.3) is the authoritative artifact for regulatory
submission — the FDA, in the medical-device case, expects one SBOM that meets
the NTIA minimum baseline on its own. Scanners (Syft) can't author that
artifact: they miss vendored binaries and statically-linked libraries, and
they can't enrich entries with the supplier/license/relationship metadata a
regulator expects.

But a hand-rolled SBOM written from scratch every release is brittle. The
practical loop is: keep the manual SBOM authoritative, scan with Syft each
release, surface deltas the curator merges by hand. sbom-curator produces
that delta surface.

## Design

```
   manual.spdx (authoritative, the deliverable)
            \
             >--  parse  --  normalize  --\                /--  reconcile  --  <name>-reconcile.md
            /                               >--  match  --<
   syft.spdx.json (periodic input)         /                \--  plan (ingest)  --  <name>-ingest.md
            \                             /
             >--  parse  --  normalize  -/
```

### Stages

1. **Parse**. Read both SPDX 2.3 inputs into a common in-memory shape:
   `{name, version, purl?, license?, source: "manual" | "syft"}`.

2. **Normalize**. Lowercase names, strip vendor prefixes where unambiguous,
   coalesce versions ("1.0" vs "1.0.0"). Document each rule; precision matters
   more than recall.

3. **Match** (`reconcile`). Lowercase-name match into three buckets:
   - **Only in manual** — usually vendored or hand-rolled entries Syft can't
     see; check for stale entries the curator forgot to remove.
   - **Only in Syft** — candidate additions to the manual SBOM. Some are
     build-tooling that doesn't ship and can be ignored; the rest belong in
     the deliverable.
   - **In both** — cross-check version and license; flag mismatches.

4. **Plan** (`ingest`). Relabel the buckets as curator actions, splitting
   `in both` on PEP 440 version equivalence: **bump** (older version on the
   manual side), **add** (only-in-Syft), **keep** (versions agree; license
   drift carried as an annotation), **preserve** (only-in-manual). One
   matcher, two views — `ingest` is built on `reconcile`'s output so they
   never disagree about the facts.

5. **Report**. Markdown, suitable for a PR comment or audit attachment.
   `reconcile` writes the four-bucket diff; `ingest` writes the action plan
   (quiet keeps counted, not enumerated).

## Out of scope (for v1)

- Auto-rewriting the manual SBOM. `ingest` produces an edit plan; the curator
  applies it by hand. An `ingest --apply` mode, if it ever lands, stays
  opt-in — auto-rewrite must not clobber the curator's formatting, comments,
  or curated relationships. See [`BACKLOG.md`](../BACKLOG.md).
- Vulnerability scanning. That is `sbom-sentinel`'s job.
- CycloneDX support. v1 is SPDX-on-SPDX. Have Syft emit SPDX (`syft scan ...
  -o spdx-json=...`); a CycloneDX parser is an additive follow-up if a real
  use case arrives.

## Open questions

- Component identity. PURL when available, else `(name, version)` pair.
  How aggressive is normalization allowed to get before false-positive matches
  hide real divergence?
- License comparison. SPDX expression equivalence is not string equality.
  v1 may flag any non-identical license string and let the reviewer judge.
- Output stability. The triage report is read by humans; ordering and section
  layout should not change run-to-run unless the inputs changed.
