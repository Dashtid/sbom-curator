# Backlog

Open work for sbom-curator. Each item names a **trigger** — the real-world
signal that justifies starting it. Nothing here is urgent; items wait for
their trigger so the codebase stays free of speculative complexity.

## Open

### Auto-suggest `--product-prefix`

**Partly shipped (PR #25): `covers-prefix` suggestions.** Tight name
clusters in *added* that no manual entry covers now surface as
`Suggested annotations` in the report and a console line. **Still open:**
the same machinery could spot a candidate `--product-prefix` — likely
the largest *added* cluster on a first run (no Hermes-filter applied),
or the cluster whose prefix overlaps the manual's `DESCRIBES` target.
Punted from PR #25 because every heuristic is liable to false positives
on a wrong auto-apply; "suggest in the report, never auto-apply" is the
right shape, and product-prefix suggestion has more risk of misleading a
curator into typing the wrong thing than covers-prefix does. Revisit
when a new product onboards and the discovery friction shows up.

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
| PR #25 | Auto-suggest `covers-prefix` — tight name clusters in *added* that no manual entry covers surface in a `## Suggested annotations` section with the exact annotation text |
| PR #26 | `versions_equal` accepts the NuGet semver ↔ .NET assembly-version pattern (`4.4.1` ↔ `4.4.1.57983`, length pair (3, 4), first three components equal) — kills the spurious `Reactive` bump |
| PR #27 | `--fail-on` on `ingest` (`added`, `bumped`, `review`, `license`) and `reconcile` (`only-in-syft`, `only-in-manual`, `version`, `license`) — exit 1 when any listed bucket is non-empty, so CI can gate on reconciliation findings |
| PR #28 | `CHANGELOG.md` + bump to v0.1.0 — first tagged release |
| PR #30 | Folder-scan mode — `sbom-curator ingest <PATH>` discovers conventional `manual/`/`syft/` pairs and ingests each; `--strict-naming` opt-in for CI; aggregate exit code; per-pair parse-failure tolerance |
