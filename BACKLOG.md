# Backlog

Open work for sbom-curator. Each item names a **trigger** — the real-world
signal that justifies starting it. Nothing here is urgent; items wait for
their trigger so the codebase stays free of speculative complexity.

## Open

### `ingest --apply` — write the edit plan back to the manual SBOM

**Trigger:** the curator has run `ingest` against a few real customer
SBOMs by hand and the same mechanical edits (version bumps, appending
new package blocks) are clearly worth automating.

`ingest` produces a plan; today the curator applies it by hand. An
`--apply` flag would let the tool perform the safe subset of edits:
appending `AddAction` package blocks, updating `PackageVersion` lines
for `BumpAction`s. It must preserve the file's existing formatting,
comments, package groupings, and curated relationships — which rules
out "parse with spdx-tools, re-serialize" (that loses all of it).
Likely a surgical text-edit pass, or it stays manual. Kept opt-in
regardless; the default is to leave the curator's file untouched.

### .NET name-style normalization (top priority — trigger met)

**Trigger:** met. A real Affinity 5.0.0 manual SBOM run against the
matching Syft scan (2026-05-12) showed the name-mismatch problem is
pervasive in .NET and dominates the report. Examples from that run:

| Manual lists | Scan sees | Mismatch type |
| --- | --- | --- |
| `Reactive` 4.4.1 | `System.Reactive` 4.4.1 (+ `.Core`, `.Interfaces`, `.Linq`) | Vendor-prefix dropped in the manual; *version actually matches* |
| `Vortice` 3.2.0 | `Vortice.Direct3D11`, `.DXGI`, `.DirectX`, `.Direct3D9` 3.2.0 | Manual lists the family; scan lists the individual NuGet packages |
| `CommunityToolkit` 8.2.2 | `CommunityToolkit.Mvvm` 8.2.2 | Same family-vs-package pattern; version matches |
| `Infragistics Ultimate` 2022.2 | `Infragistics.WPF.*` 22.2.19 (×12) | Family-vs-package *and* marketing-version vs NuGet-version (`2022.2` ≈ `22.2.x`) |
| `DCMTK` 3.6.7 | `dcm2json`, `dcmconv`, `dcmcjpeg`, … (~40 tool binaries) | Coarse component vs the individual executables a directory scan finds |
| `CUDA Runtime Library` 11.0.194 | `NVIDIA CUDA 11.0.194 Runtime` | Different name string entirely; the version is embedded in the name |

Without normalization, every one of these lands in *added* (the scan's
fine-grained names) and *only in your SBOM* (the curator's coarse name)
— two large noisy buckets that bury the handful of genuinely-missing
packages. Distinct sub-problems:

1. **Family ↔ package** — does manual `CommunityToolkit` mean the whole
   family or specifically `CommunityToolkit.Mvvm`? The tool can't infer
   curator intent; likely needs a curator-side hint (a glob in the
   manual entry's name, or an SPDX annotation) or a "this manual entry
   covers all `X.*`" convention.
2. **Vendor-prefix** — `Reactive` ↔ `System.Reactive` is a clean prefix
   strip. `CommunityToolkit` ↔ `CommunityToolkit.Mvvm` is a sibling
   suffix add. Different rules.
3. **Coarse ↔ binaries** — `DCMTK` ↔ 40 `dcm*` executables. Tied to the
   "scan the install, not the build tree" guidance — a clean scan
   reduces but doesn't eliminate this for native libs.

The Affinity 5.0.0 pair is the design input; it isn't committable as a
fixture (customer-confidential), so the work needs an anonymized or
synthetic .NET pair to test against, or it's designed against the live
Affinity files and tested with a small synthetic .NET fixture.

### `lint` subcommand — preflight the manual SBOM (trigger met)

**Trigger:** met. The real Affinity 5.0.0 manual SBOM (2026-05-12)
would not parse — line 196 (`PackageVersion: NOASSERTION` on the
`haeslib` package) is spec-forbidden by SPDX 2.3 §7.3 (the field is
optional; absence means "unknown"). spdx-tools rejects it correctly
but the error message — `Token did not match specified grammar rule.
Line: 196` — is opaque, and the curator had to hand-edit the file
before the tool would run.

A small `sbom-curator lint manual.spdx` subcommand would catch known
spec violations before `ingest`/`reconcile`, with actionable messages
("line 196: delete `PackageVersion: NOASSERTION` — that value isn't
permitted by SPDX 2.3 §7.3; omit the field when the version is
unknown"). Keeps the linting story in its own command rather than
making the parser permissive. Worth doing soon — it's the first thing
that bit a real run.

### Folder-scan mode

**Trigger:** running `ingest --manual … --syft … --name …` pairwise
across several products gets tedious.

`sbom-curator ingest artifacts/` (or a dedicated verb) would discover
matching `manual/<name>.spdx` + `syft/<name>.syft.spdx.json` pairs in
the conventional layout and write `reports/<name>-ingest.md` for each.
Pure convenience over the explicit-flags form; needs the multi-product
workflow to actually exist first.

### Auto-detect the product's own assemblies on the scan side

**Partly shipped (PR #20): `--product-prefix`.** The Affinity 5.0.0
directory scan listed ~472 `Hermes.*` .NET assemblies — the product
itself, decomposed into its DLLs — every one an *added* entry. PR #16
filters packages that share a name with a `DESCRIBES` target, but a
*directory* scan's `DESCRIBES` target is a synthetic component named
after the directory, not "Hermes", so the assemblies slip through.
`ingest --product-prefix Hermes.` now drops them by name prefix (a
curator hint). **Still open:** infer the prefix automatically — e.g.
from the product name the *manual* SBOM `DESCRIBES`, or from the
dominant assembly-name cluster in the scan — so the curator doesn't
have to supply it. Must not over-filter a real dependency that
legitimately shares a prefix with the product.

### Per-file / per-assembly deduplication

**Trigger:** met (mildly). The Affinity scan listed
`CommunityToolkit.Mvvm 8.2.2` *and* `CommunityToolkit.Mvvm
8.2.2.1+4c21e0294b` as separate rows (PEP 440 treats the local segment
as distinguishing — correct per spec, but they're the same package),
and several `Hermes.*` assemblies twice at the same version (the same
DLL found at two paths). Possible approach: collapse entries sharing a
PURL (or name) up to the local/build segment before the buckets are
finalized. Needs care not to hide genuine multi-version installs.

### Snapshot tests for the Markdown report

**Trigger:** a layout change accidentally breaks the "stable diff
run-to-run" promise — or earlier, if pinning shape becomes desirable.

`tests/test_report.py` exercises individual rendering primitives. Add a
snapshot test that pins the full rendered report against the dogfood
fixture, so layout regressions (column reordering, section omission,
heading rename) fail CI rather than slipping through.

### Configurable exit-code thresholds

**Trigger:** someone wants to gate CI on reconciliation findings.

Add a `--fail-on=version,license,only-in-syft` flag that maps to a
non-zero exit when any selected bucket is non-empty. The
`Reconciliation` dataclass already exposes the inputs (`version_mismatches`,
`license_mismatches`, etc.). Default stays exit-0 — the artifact is the
report; gating is opt-in.

### CHANGELOG and 0.1.0 tag

**Trigger:** ready to cut a public release.

Add `CHANGELOG.md` (Keep-a-Changelog format), bump `pyproject.toml` to
`0.1.0`, tag the release commit, push the tag. Optionally publish to
PyPI when the tool's audience extends past the local toolchain.

## Decided against

- **CycloneDX (or other non-SPDX) input parser.** The workflow produces
  SPDX JSON (`syft scan ... -o spdx-json=...`); a CycloneDX file is
  converted externally first (`syft convert in.json -o spdx-json=out.spdx.json`).
  Keeping the parser layer SPDX-only avoids carrying a translation layer
  whose only job is to undo a flag the user controls. Revisit only if a
  workflow genuinely *cannot* produce or convert to SPDX.

## Done

Recorded for context; remove entries once the project context fully
covers them.

| Shipped in | What |
| --- | --- |
| PR #1 | SPDX 2.3 JSON parser (hand-rolled) |
| PR #2 | Switch parser to spdx-tools (gains tag-value, YAML, RDF) |
| PR #3 | Drop CycloneDX from v1 scope |
| PR #4 | dicom-fuzzer 1.11.0 dogfood fixture pair |
| PR #5 | Reconciler + Markdown report + CLI wiring |
| PR #6 | README running example + `[i]` marker escape fix |
| PR #7 | Loose version (PEP 440) + license (SPDX expression) equivalence |
| PR #9 | Content-sniff SPDX tag-value under `.txt` extension (real customer SBOMs commonly land as `.txt`) |
| PR #12 | Rename project sbom-overlay → sbom-curator |
| PR #13 | Reframe docs around the FDA-curator workflow; report file → `-reconcile.md` |
| PR #14 | Re-fatten the dogfood manual SBOM to the comprehensive FDA shape |
| PR #15 | `ingest` command (added / bumped / review / keep change report) |
| PR #16 | Filter the product out of the Syft side (skip packages sharing a name with a DESCRIBES target) |
| PR #17 | Pin GitHub Actions to commit SHAs + add Dependabot |
| PR #19 | Reframe `ingest` as a per-scan change report; soften the "comprehensive manual" framing |
| PR #20 | `--product-prefix` — drop the product's own assemblies (e.g. `Hermes.*`) from the scan side |
