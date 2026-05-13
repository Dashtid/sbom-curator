# Backlog

Open work for sbom-curator. Each item names a **trigger** — the real-world
signal that justifies starting it. Nothing here is urgent; items wait for
their trigger so the codebase stays free of speculative complexity.

## Open

### Auto-suggest scope hints in the report

**Trigger:** met. The `--product-prefix` flag (PR #20) and `covers-prefix`
annotations (PR #23) are powerful but the curator has to *discover* them
by reading a noisy first-run report and figuring out the right strings.
The matcher already has the data to propose both: a tight cluster of
*added* packages sharing a prefix that matches nothing on the manual
side is exactly the signal.

Add a "Suggested annotations" appendix to the report when such a cluster
exists, e.g. "5 scan packages share the prefix `Vortice.` but no manual
entry covers it — add `PackageComment: <text>sbom-curator covers-prefix:
Vortice.</text>` to the entry that owns them." The largest cluster whose
prefix overlaps the manual's `DESCRIBES` target name doubles as a
`--product-prefix` suggestion. Pure additive; no auto-apply (a wrong
auto-applied prefix is nuclear).

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
curator hint; repeatable, so it doubles as the knob for framework noise
the curator deliberately doesn't enumerate — `--product-prefix System.
--product-prefix Microsoft.Extensions.`). **Still open:** infer the
product prefix automatically — e.g. from the product name the *manual*
SBOM `DESCRIBES`, or from the dominant assembly-name cluster in the scan
— so the curator doesn't have to supply it. Must not over-filter a real
dependency that legitimately shares a prefix with the product.

**Deferred — config file.** If a curator finds themselves passing the
same handful of `--product-prefix` (and, later, `--fail-on`,
coverage-hint, etc.) flags on every run, that's the trigger to add a
project config file (`sbom-curator.toml` or `--config path`). Not before
— a flag or two on the command line is fine; a config layer with no
settled set of settings to hold is speculative.

### Teach `versions_equal` the NuGet semver ↔ .NET assembly-version pattern

**Trigger:** met. After PR #22's PURL match, the Affinity manual's
`Reactive 4.4.1` pairs with the scan's `System.Reactive 4.4.1.57983` —
same NuGet release, different version-string conventions. The matcher
reads it as a bump. `dedupe_scan`'s `_canonical_variant` (PR #21) already
recognises the pattern (3-component release vs 4-component sharing
`major.minor`). Lift that into `versions_equal` (or a sibling) so a PURL
match across that pair reads as agreement. Small, isolated.

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

- **`ingest --apply`** (write the edit plan back to the manual SBOM).
  The cost is high — must preserve the curator's formatting, comments,
  package groupings, and curated relationships, which rules out
  parse-and-re-serialise — and the value is low: reading the report and
  applying changes by hand is the part the curator wants control over.

- **Coverage glob support beyond literal prefix.** A glob like
  `Vortice.*WPF.*` would be an obvious extension to `covers-prefix:` but
  no real case has shown up. Revisit if a curator entry's intended
  coverage genuinely can't be expressed as a single name prefix.

- **Coverage version-spread sanity check.** A warning when an umbrella's
  covered sub-packages span an unusually wide version range could flag
  side-by-side installs of two family versions. Schemes diverge between
  umbrellas (e.g. marketing `2022.2`) and sub-packages (`22.2.19`), so a
  naive check is noisy. Revisit when a real run misses something the
  curator wishes had been flagged.

- **Dedup residuals from PR #21:** (a) collapse name-groups with three
  or more distinct versions where only some are precision-variants —
  currently kept whole; (b) key dedup on PURL as well as name; (c) a
  `## Collapsed scan duplicates` audit appendix in the report. Each is
  marginal noise reduction at this point; revisit if a real run shows
  the noise.

- **Snapshot tests for the Markdown report.** `tests/test_report.py`
  pins each rendering primitive; a full-report snapshot would catch
  cross-section layout regressions but at the cost of pinning every
  small rendering tweak. Add only if a layout regression actually slips
  through CI.

- **Project config file (`sbom-curator.toml`).** The trigger ("curator
  passes the same handful of `--product-prefix`/`--fail-on`/etc. flags
  on every run") isn't met — Affinity needs one prefix flag. Revisit
  when a second product onboards and the flag-set stabilises.

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
| PR #21 | Scan-side hygiene — drop `UNKNOWN`-version / path-named entries (parser); `dedupe_scan` collapses exact dups + precision-variant pairs |
| PR #22 | PURL-aware matching — match manual↔scan on equal version-free PURLs before falling back to lowercased name |
| PR #23 | Family-prefix coverage — `PackageComment: sbom-curator covers-prefix: <X>` on a manual entry absorbs unmatched scan packages whose name starts with `<X>` into a dedicated `covered` bucket |
| PR #24 | `lint` subcommand — translate spdx-tools' opaque grammar errors into line-numbered actionable messages (`PackageVersion: NOASSERTION`, SPDX 2.3 §7.3); warn on packages `ingest`/`reconcile` would silently skip |
