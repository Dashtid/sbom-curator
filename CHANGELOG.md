# Changelog

All notable changes to sbom-curator are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-05-13

The shape of the v1 tool: a curator maintains one SPDX 2.x SBOM by hand,
drops it next to a Syft scan, and runs `sbom-curator ingest` to get a
per-scan change report (added / bumped / review / keep / covered / suggested
annotations). The manual SBOM is never modified.

### Added

- `sbom-curator ingest` — per-scan change report (added, bumped, only in
  your SBOM, unchanged, covered by family entries, suggested annotations).
- `sbom-curator reconcile` — raw four-bucket diff (only-in-manual,
  only-in-Syft, version disagreements, license disagreements) plus the
  covered/suggested sections.
- `sbom-curator lint` — preflight an SPDX SBOM; translates spdx-tools'
  opaque grammar errors into line-numbered actionable messages (notably
  `PackageVersion: NOASSERTION`) and warns on packages `ingest`/`reconcile`
  would silently skip.
- `--product-prefix PREFIX` (repeatable, case-insensitive) on `ingest` and
  `reconcile`: drop scan packages by name prefix — the product's own
  assemblies a directory scan picks up, or .NET framework noise the
  curator doesn't enumerate.
- `--fail-on BUCKETS` on `ingest` (`added`, `bumped`, `review`, `license`)
  and `reconcile` (`only-in-syft`, `only-in-manual`, `version`, `license`)
  — exit 1 when any listed bucket is non-empty. Default exit codes: 0
  success, 1 gate hit, 2 parse failure.
- `PackageComment: <text>sbom-curator covers-prefix: PREFIX</text>` on a
  manual entry absorbs every still-unmatched scan package whose name
  starts with `PREFIX` into a dedicated "covered" bucket.
- "Suggested annotations" section in both reports: when *added* contains
  a tight name cluster (≥3 packages sharing a dotted prefix) that no
  manual entry covers, the report proposes the exact `covers-prefix:`
  annotation that would absorb them.

### Matching

- Three-pass matcher: PURL identity (case + URL-decoded, version/qualifiers
  /subpath stripped) → lowercased name → manual-side `covers-prefix:`
  coverage. A manual component is consumed by at most one PURL or name
  match; an umbrella can cover many sub-packages.
- `versions_equal` knows the NuGet semver ↔ .NET assembly-revision pattern
  (`4.4.1` ↔ `4.4.1.57983`, length pair (3, 4), first three components
  equal) — kills spurious bumps when the curator records a NuGet semver
  and Syft emits the assembly version.
- `versions_equal` is otherwise PEP 440 with strict-equality fallback.
- `licenses_equal` is SPDX expression equality with strict-equality
  fallback.

### Scan-side cleanup (automatic)

- Parser drops scan packages with no usable version (`UNKNOWN`,
  `NOASSERTION`, missing) and packages whose name looks like a filesystem
  path (contains a backslash) — loose binaries inside vendored source
  trees, not packages.
- `dedupe_scan` collapses exact duplicates, PEP-440-equal versions,
  `+local`-segment variants, and a NuGet semver paired with its .NET
  assembly version. Genuine multi-version installs are kept.

### Input formats

- `--manual` accepts any SPDX 2.x serialization spdx-tools understands
  (tag-value `.spdx`, JSON, YAML, RDF/XML), including tag-value content
  under a `.txt` extension via content-sniff fallback.
- `--syft` must be SPDX JSON. CycloneDX is explicitly out of scope;
  convert externally with `syft convert in.json -o spdx-json=out.spdx.json`.

### Quality bar

- ruff (E, F, I, UP, B, S, SIM), mypy strict, bandit, pytest with branch
  coverage at 100%. ASCII-only user-facing strings (`[+] [-] [!] [i]`).
  GitHub Actions pinned to commit SHAs; Dependabot active.

[Unreleased]: https://github.com/Dashtid/sbom-curator/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dashtid/sbom-curator/releases/tag/v0.1.0
