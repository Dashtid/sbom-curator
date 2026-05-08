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
             >---  parse  ---  normalize  ---\
            /                                  >---  reconcile  ---  report.md
   syft.spdx.json (periodic input)           /
            \                               /
             >---  parse  ---  normalize  -/
```

### Stages

1. **Parse**. Read both SPDX 2.3 inputs into a common in-memory shape:
   `{name, version, purl?, license?, source: "manual" | "syft"}`.

2. **Normalize**. Lowercase names, strip vendor prefixes where unambiguous,
   coalesce versions ("1.0" vs "1.0.0"). Document each rule; precision matters
   more than recall.

3. **Reconcile**. Three buckets:
   - **Only in manual** — usually vendored or hand-rolled entries Syft can't
     see; check for stale entries the curator forgot to remove.
   - **Only in Syft** — candidate additions to the manual SBOM. Some are
     build-tooling that doesn't ship and can be ignored; the rest belong in
     the deliverable.
   - **In both** — cross-check version and license; flag mismatches.

4. **Report**. Markdown, suitable for a PR comment or audit attachment.

## Out of scope (for v1)

- Auto-rewriting the manual SBOM. The curator merges deltas by hand. An
  `ingest` command with an explicit edit plan (BUMP / ADD / KEEP / PRESERVE)
  is the planned headline; an `--apply` flag, if it ever lands, stays
  opt-in. See [`BACKLOG.md`](../BACKLOG.md).
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
