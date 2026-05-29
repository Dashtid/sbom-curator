# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`finalize` subcommand.** Strips `sbom-curator <key>: <value>` tool
  annotations (e.g. `covers-prefix`) from `PackageComment` blocks,
  producing a clean copy of the manual SBOM for delivery.
  - Single file: `sbom-curator finalize --manual M --output O`.
  - Folder: `sbom-curator finalize <PATH>` reads `<PATH>/manual/*.spdx`,
    writes `<PATH>/finalized/<same-name>.spdx`.
  - Namespaced — any future `sbom-curator <key>:` annotation type is
    cleaned automatically.
  - Text-level edit; every byte outside stripped lines preserved. A block
    whose entire content was tool annotations is removed in full; mixed
    blocks keep curator notes. Source SBOM never modified.
  - Tag-value SPDX only.

### Internal

- New `sbom_curator.curate.finalize` module: `strip_tool_annotations(text)`,
  `discover_manuals(root)`.

## [0.2.0] — 2026-05-17

### Added

- **Folder-scan mode for `ingest`.** `sbom-curator ingest <PATH>` discovers
  every `<name>.spdx` in `<PATH>/manual/` that has a matching
  `<name>.syft.spdx.json` in `<PATH>/syft/`, runs the per-pair pipeline, and
  writes one report to `<PATH>/reports/`. Mutually exclusive with
  `--manual`/`--syft`/`--name`.
- `--strict-naming` flag (folder mode) — rejects non-canonical scan
  extensions (`.sbom.spdx.json`, `.spdx.json`). For CI. Default is loose.
- Per-pair console output: one line per pair plus an aggregate footer
  (`processed N pair(s); M gate hit(s); K parse error(s)`). Exit code is
  the worst across pairs (2 parse failure, 1 gate hit, 0 clean). Per-pair
  parse failures don't abort.
- Orphan reporting: manuals without a matching scan and vice versa are
  surfaced as warnings.

### Internal

- `_run_ingest_pair` extracted from the `ingest` command body, callable from
  both single-pair and folder-scan dispatchers.
- `_load_inputs` raises `SpdxParseError` instead of printing + exiting;
  callers decide whether to terminate or continue.
- New `sbom_curator.curate.discover` module: `Pair`, `DiscoveryResult`,
  `discover()`. Loose-by-default stem matching normalizes dots / spaces /
  underscores to dashes; strict mode requires the canonical pattern.

[Unreleased]: https://github.com/Dashtid/sbom-curator/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Dashtid/sbom-curator/releases/tag/v0.2.0

## [0.1.0] — 2026-05-13

The v1 shape: a curator maintains one SPDX 2.x SBOM by hand, drops it next
to a Syft scan, and runs `sbom-curator ingest` for a per-scan change
report. The manual SBOM is never modified.

### Added

- `sbom-curator ingest` — per-scan change report (added, bumped, only in
  your SBOM, unchanged, covered, suggested annotations).
- `sbom-curator reconcile` — raw four-bucket diff (only-in-manual,
  only-in-Syft, version disagreements, license disagreements).
- `sbom-curator lint` — preflight; translates spdx-tools grammar errors
  into line-numbered messages.
- `--product-prefix PREFIX` (repeatable, case-insensitive) on `ingest` and
  `reconcile`: drop scan packages by name prefix.
- `--fail-on BUCKETS` on `ingest` (`added`, `bumped`, `review`, `license`)
  and `reconcile` (`only-in-syft`, `only-in-manual`, `version`, `license`)
  — exit 1 when any listed bucket is non-empty. Defaults: 0 success,
  1 gate hit, 2 parse failure.
- `PackageComment: <text>sbom-curator covers-prefix: PREFIX</text>` on a
  manual entry absorbs every unmatched scan package whose name starts with
  PREFIX into a `covered` bucket.
- "Suggested annotations" section in both reports when *added* contains a
  tight name cluster (≥3 packages sharing a dotted prefix) that no manual
  entry covers.

### Matching

- Three-pass: PURL identity → lowercased name → `covers-prefix:` coverage.
- `versions_equal` accepts the NuGet semver ↔ .NET assembly-version pattern
  (`4.4.1` ↔ `4.4.1.57983`); otherwise PEP 440 with strict fallback.
- `licenses_equal` is SPDX expression equality with strict fallback.

### Scan-side cleanup (automatic)

- Parser drops packages with no usable version (`UNKNOWN`, `NOASSERTION`,
  missing) and packages whose name looks like a filesystem path.
- `dedupe_scan` collapses exact duplicates, PEP-440-equal versions,
  `+local`-segment variants, and NuGet semver ↔ .NET assembly version
  pairs. Genuine multi-version installs are kept.

### Input formats

- `--manual` accepts any SPDX 2.x serialization spdx-tools understands
  (tag-value `.spdx`, JSON, YAML, RDF/XML), including tag-value content
  under a `.txt` extension via content-sniff fallback.
- `--syft` must be SPDX JSON. Convert CycloneDX externally with `syft
  convert in.json -o spdx-json=out.spdx.json`.

### Quality bar

- ruff (E, F, I, UP, B, S, SIM), mypy strict, bandit, pytest with branch
  coverage at 100%. ASCII-only user-facing strings. GitHub Actions pinned
  to commit SHAs; Dependabot active.

[0.1.0]: https://github.com/Dashtid/sbom-curator/releases/tag/v0.1.0
