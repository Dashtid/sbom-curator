# Architecture

## Problem

A hand-maintained SBOM (SPDX 2.3) is the authoritative artifact for regulatory
submission — the FDA, in the medical-device case, expects one SBOM. Its scope
is the curator's call (a focused list of significant components, or the full
deployed closure, or in between); the tool doesn't enforce one. Scanners can't
author that artifact: they miss vendored binaries and statically-linked libs,
and they can't add the supplier/license/relationship metadata a regulator
expects.

But hand-rewriting the SBOM every release is brittle. The practical loop is:
keep the SBOM authoritative, scan each release, surface the delta the curator
merges by hand. sbom-curator produces that delta — a *change report*.

## Design

```
   manual.spdx (the deliverable, never modified)
            \
             >--  parse  ----------------------  normalize  --\                /--  reconcile  --  <name>-reconcile.md
            /                                                   >--  match  --<
   syft.spdx.json (a scan, SPDX JSON)                          /                \--  plan (ingest)  --  <name>-ingest.md
            \                                                /
             >--  parse  --  filter / dedupe  --  normalize  -/
```

### Stages

1. **Parse**. Read both SPDX 2.3 inputs into a common in-memory shape:
   `{name, version, purl?, license?, source: "manual" | "syft"}`. Packages the
   document `DESCRIBES`, and packages sharing a name with one, are dropped —
   that's the product itself, not a dependency. Also dropped: packages with no
   usable version (missing, or the literal `UNKNOWN` / a `NOASSERTION`
   sentinel) and packages whose name is a filesystem path — loose binaries a
   directory scan emits from inside vendored source trees, not dependencies.

2. **Filter & dedupe the scan** (`curate/scope.py`, after parse, before
   match). For directory scans, where the `DESCRIBES` target is a synthetic
   directory node that shares no name with the product's assemblies,
   `--product-prefix` drops scan packages by name prefix (`Hermes.` → the
   ~470 `Hermes.*` DLLs of a .NET app) — a curator hint. Then `dedupe_scan`
   collapses a package the scan lists more than once: exact duplicates, and
   "same package at different precision" pairs (a NuGet semver alongside its
   .NET assembly version; a `+build`-local-segment version alongside the
   same version without). A genuine multi-version install is kept.

3. **Normalize**. Lowercase names, coalesce versions ("1.0" vs "1.0.0" via PEP
   440), compare licenses as SPDX expressions. (Vendor-prefix / coarse-vs-fine
   name normalization is not yet implemented — see BACKLOG.)

4. **Match** (`reconcile`). Two passes: first by **PURL identity** (same
   package URL after lowercasing, URL-decoding, and dropping the
   `@version` / `?qualifiers` / `#subpath` — so a curator entry named
   `CommunityToolkit` with PURL `pkg:nuget/CommunityToolkit.Mvvm@8.2.2`
   matches a scan entry `CommunityToolkit.Mvvm`), then whatever is still
   unmatched by **lowercased name**. PURL match wins; a component is
   consumed by at most one match. Result is three buckets:
   - **Only in manual** — vendored/static entries the scanner can't see, or
     entries the scan lists under a different name *with no PURL to bridge
     it*, or stale entries.
   - **Only in Syft** — candidates to add. Some don't ship (build tooling).
   - **In both** — cross-check version and license; flag mismatches. (A
     PURL match with differing versions lands here, so it surfaces as a
     bump — that's intentional.)

5. **Plan** (`ingest`). Relabel the buckets as a change report, splitting
   `in both` on PEP 440 version equivalence: **added** (only-in-Syft),
   **bumped** (older version on the manual side), **review** (only-in-manual —
   "only in your SBOM"), **keep** (versions agree). A *license change* is
   carried as an annotation on `keep`/`bump`, and counts only when both sides
   have a license and they differ. One matcher, two views — `ingest` is built
   on `reconcile`'s output, so they never disagree about the facts.

6. **Report**. Markdown, suitable for a PR comment or audit attachment.
   `reconcile` writes the four-bucket diff; `ingest` writes the change report
   (unchanged-and-unchanged entries counted, not enumerated).

## Out of scope (for v1)

- Auto-rewriting the manual SBOM. `ingest` produces a report; the curator
  applies it by hand. An `ingest --apply` mode, if it ever lands, stays
  opt-in — auto-rewrite must not clobber the curator's formatting, comments,
  or curated relationships. See [`BACKLOG.md`](../BACKLOG.md).
- Vulnerability scanning. That is `sbom-sentinel`'s job.
- CycloneDX (or any non-SPDX) input. Convert to SPDX JSON first (`syft
  convert ...`); see BACKLOG for the standing decision.

## Open questions

- Name normalization. `Reactive` ↔ `System.Reactive`, `Infragistics Ultimate`
  ↔ `Infragistics.WPF.*`, coarse component ↔ fine binaries. How aggressive can
  matching get before false-positive matches hide real divergence? (BACKLOG.)
- Output stability. Reports are read by humans; ordering and section layout
  should not change run-to-run unless the inputs changed.
