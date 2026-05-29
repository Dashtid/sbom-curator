# Architecture

## Problem

A hand-maintained SPDX 2.3 SBOM is the authoritative artifact for regulatory
submission. Scope is the curator's call; the tool doesn't enforce one.
Scanners can't author that artifact — they miss vendored binaries and
statically linked libs, and they can't supply the supplier / license /
relationship metadata a regulator expects.

Hand-rewriting every release is brittle. The practical loop: keep the SBOM
authoritative, scan each release, surface the delta the curator merges by
hand. sbom-curator produces that delta — a change report.

## Design

```
manual.spdx ─┐
             ├─ parse ─ normalize ─┐
syft.json  ──┤                     ├─ match ─┬─ reconcile ─ <name>-reconcile.md
             └─ parse ─ filter ────┘         └─ plan ────── <name>-ingest.md
                       dedupe
                       normalize
```

### Stages

1. **Parse.** Both SPDX 2.3 inputs into `{name, version, purl?, license?,
   source}`. Drops the product itself (packages the document `DESCRIBES` and
   packages sharing a name with one), packages with no usable version
   (`UNKNOWN`, `NOASSERTION`, missing), and packages whose name is a
   filesystem path (loose binaries inside vendored source trees).

2. **Filter & dedupe the scan** (`curate/scope.py`). For directory scans
   where the `DESCRIBES` target is a synthetic node, `--product-prefix`
   drops scan packages by name prefix (e.g. `Hermes.` removes ~470 `Hermes.*`
   .NET assemblies). Then `dedupe_scan` collapses exact duplicates and
   precision-variant pairs (NuGet semver ↔ .NET assembly version;
   `+build`-local-segment vs not). Genuine multi-version installs are kept.

3. **Normalize.** Lowercase names; PEP 440 version equivalence (`1.0` vs
   `1.0.0`); SPDX expression license equivalence.

4. **Match** (`reconcile`). Three passes:

   1. **PURL identity** — same package URL after lowercasing, URL-decoding,
      and stripping `@version` / `?qualifiers` / `#subpath`. A curator
      entry named `CommunityToolkit` with PURL
      `pkg:nuget/CommunityToolkit.Mvvm@8.2.2` matches the scan's
      `CommunityToolkit.Mvvm`.
   2. **Lowercased name** — whatever is still unmatched.
   3. **Family coverage** — a manual entry declaring
      `PackageComment: <text>sbom-curator covers-prefix: Vortice.</text>`
      absorbs every still-unmatched scan package whose name starts with that
      prefix. One umbrella can cover many sub-packages; longest matching
      prefix wins.

   Four output buckets: **only in manual** (vendored / unbridged / stale),
   **only in Syft** (candidates to add), **in both** (cross-check version
   and license), **covered** (absorbed by a family entry; not
   version-checked).

5. **Plan** (`ingest`). Relabels reconcile's buckets as a change report:
   **added** (only-in-Syft), **bumped** (older version in manual), **review**
   (only-in-manual), **keep** (agreed). License changes are flagged on
   `keep` / `bump` only when both sides carry a license and they differ.

6. **Report.** Markdown. `reconcile` emits the four-bucket diff; `ingest`
   emits the change report (unchanged entries counted, not enumerated).

7. **Finalize.** `sbom-curator finalize` strips `sbom-curator <key>:`
   annotations from `PackageComment` blocks via a text-level edit
   (`curate/finalize.py`). Source is never modified; finalized output ships
   to the regulator.

## Out of scope (v1)

- **Auto-rewriting the manual SBOM.** `ingest` produces a report; the
  curator applies it by hand. An `ingest --apply` would clobber formatting,
  comments, and curated relationships. See [`BACKLOG.md`](../BACKLOG.md).
- **Vulnerability scanning.** That is `sbom-sentinel`'s job.
- **Non-SPDX input.** Convert to SPDX JSON first (`syft convert ...`).

## Open questions

- **Name normalization.** `Reactive` ↔ `System.Reactive`, coarse component
  ↔ fine binaries. How aggressive can matching get before false positives
  hide real divergence?
- **Output stability.** Reports are read by humans; ordering and layout
  should not change run-to-run unless inputs changed.
