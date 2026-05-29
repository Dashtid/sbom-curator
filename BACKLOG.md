# Backlog

Open work for sbom-curator. Each item names a **trigger** — the real-world
signal that justifies starting it. Nothing here is urgent; items wait for
their trigger so the codebase stays free of speculative complexity.

## Open

### Auto-suggest `--product-prefix`

Partly shipped (PR #25): tight name clusters in *added* surface as
`Suggested annotations` in the report. Still open: detect a candidate
`--product-prefix` — likely the largest *added* cluster on a first run, or
the cluster whose prefix overlaps the manual's `DESCRIBES` target. Punted
from PR #25 because false-positive auto-apply is high-risk; "suggest in the
report, never auto-apply" is the right shape. Revisit when a new product
onboards and the discovery friction shows up.

### Auto-detect the product's own assemblies on the scan side

Partly shipped (PR #20): `--product-prefix Hermes.` drops the ~470
`Hermes.*` assemblies a directory scan picks up. Still open: infer the
product prefix automatically — from the product name the manual SBOM
`DESCRIBES`, or from the dominant assembly-name cluster — so the curator
doesn't have to supply it. Must not over-filter a real dependency that
legitimately shares a prefix with the product.

**Deferred — config file.** If a curator passes the same handful of flags
on every run, that's the trigger to add `sbom-curator.toml` / `--config
path`. Not before — a flag or two on the command line is fine.

## Decided against

- **CycloneDX (or other non-SPDX) input parser.** The workflow produces SPDX
  JSON (`syft scan ... -o spdx-json=...`); a CycloneDX file is converted
  externally (`syft convert in.json -o spdx-json=out.spdx.json`). Keeping the
  parser SPDX-only avoids a translation layer whose only job is to undo a
  flag the user controls.

- **`ingest --apply`** (write the edit plan back to the manual SBOM). High
  cost (must preserve formatting, comments, groupings, and curated
  relationships — rules out parse-and-re-serialize), low value (reading the
  report and applying changes by hand is the part the curator wants
  control over).

- **Coverage glob support beyond literal prefix.** `Vortice.*WPF.*` would be
  an obvious extension but no real case has shown up.

- **Coverage version-spread sanity check.** A warning when an umbrella's
  sub-packages span an unusually wide version range. Schemes diverge
  between umbrellas (marketing `2022.2`) and sub-packages (`22.2.19`), so
  naive checks are noisy.

- **Dedup residuals from PR #21.** (a) Collapse name-groups with three or
  more distinct versions where only some are precision-variants; (b) key
  dedup on PURL as well as name; (c) `## Collapsed scan duplicates` audit
  appendix. Each is marginal noise reduction; revisit if a real run shows
  it.

- **Snapshot tests for the Markdown report.** `tests/test_report.py` pins
  each rendering primitive; a full-report snapshot would catch cross-section
  layout regressions at the cost of pinning every rendering tweak.

- **Project config file (`sbom-curator.toml`).** Trigger (curator passes
  the same flags on every run) not met — Affinity needs one prefix flag.
  Revisit when a second product onboards and the flag-set stabilises.

## Done

Recorded for context; remove once project memory fully covers them.

| Shipped in | What |
| --- | --- |
| PR #1 | SPDX 2.3 JSON parser (hand-rolled) |
| PR #2 | Switch parser to spdx-tools (gains tag-value, YAML, RDF) |
| PR #3 | Drop CycloneDX from v1 scope |
| PR #4 | dicom-fuzzer 1.11.0 dogfood fixture pair |
| PR #5 | Reconciler + Markdown report + CLI wiring |
| PR #6 | README running example + `[i]` marker escape fix |
| PR #7 | Loose version (PEP 440) + license (SPDX expression) equivalence |
| PR #9 | Content-sniff SPDX tag-value under `.txt` extension |
| PR #12 | Rename project sbom-overlay → sbom-curator |
| PR #13 | Reframe docs around FDA-curator workflow; report file → `-reconcile.md` |
| PR #14 | Re-fatten the dogfood manual SBOM to the comprehensive FDA shape |
| PR #15 | `ingest` command (added / bumped / review / keep change report) |
| PR #16 | Filter the product out of the Syft side |
| PR #17 | Pin GitHub Actions to commit SHAs + add Dependabot |
| PR #19 | Reframe `ingest` as a per-scan change report |
| PR #20 | `--product-prefix` — drop the product's own assemblies from the scan side |
| PR #21 | Scan-side hygiene — drop `UNKNOWN`-version / path-named entries; `dedupe_scan` |
| PR #22 | PURL-aware matching |
| PR #23 | Family-prefix coverage — `PackageComment: ... covers-prefix: <X>` |
| PR #24 | `lint` subcommand — line-numbered SPDX grammar errors + skip warnings |
| PR #25 | Auto-suggest `covers-prefix` — tight name clusters surface in the report |
| PR #26 | `versions_equal` accepts NuGet semver ↔ .NET assembly-version pattern |
| PR #27 | `--fail-on` on `ingest` and `reconcile` |
| PR #28 | `CHANGELOG.md` + v0.1.0 — first tagged release |
| PR #31 | Folder-scan mode — `sbom-curator ingest <PATH>` discovers `manual/`/`syft/` pairs |
| PR #32 | `finalize` subcommand — strip `sbom-curator <key>:` tool annotations for delivery |
