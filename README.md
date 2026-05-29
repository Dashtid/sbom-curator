# sbom-curator

Reconcile a hand-maintained SPDX SBOM against a Syft scan and report what changed. The manual SBOM is never modified.

[![CI](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/sbom-curator/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/sbom-curator)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dashtid/sbom-curator/badge)](https://scorecard.dev/viewer/?uri=github.com/Dashtid/sbom-curator)
[![Python Versions](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

## Why

For regulated software (e.g. FDA-submitted medical devices), one SBOM is the
deliverable — hand-maintained by someone who knows what ships. Scanners can't
author that artifact: they miss vendored binaries and statically linked libs,
and they can't supply the supplier / license / relationship metadata a
regulator expects. Rewriting from scratch every release is brittle, so periodic
scans surface drift instead.

## Position vs sbom-sentinel

| Tool          | Input                 | Output                              |
| ------------- | --------------------- | ----------------------------------- |
| sbom-sentinel | One SBOM              | Vulnerability + KEV report          |
| sbom-curator  | Manual SBOM + a scan  | Change report (added / bumped / …)  |

Complementary, not coupled.

## Install

```bash
pip install -e .
```

## Usage

```bash
sbom-curator ingest \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0
```

Writes `artifacts/product-1.0.0-ingest.md` with four sections: **added**,
**bumped**, **only in your SBOM**, and **license changed** (otherwise-unchanged
entries with a license diff). Unchanged-and-unchanged entries are counted but
not listed.

`--manual` accepts any SPDX 2.x serialization (`.spdx`, `.spdx.json`,
`.spdx.yaml`, RDF/XML). `--syft` must be SPDX JSON; convert CycloneDX with
`syft convert in.json -o spdx-json=out.spdx.json`. Exit codes: `0` clean, `1`
gate hit (`--fail-on`), `2` parse failure.

### Optional flags

```bash
# Folder mode: discover pairs in <root>/manual/ + <root>/syft/, one report per
# pair to <root>/reports/. Worst exit code across pairs wins.
sbom-curator ingest artifacts/

# Raw four-bucket diff instead of the change report.
sbom-curator reconcile --manual M --syft S --name N

# Preflight: line-numbered errors for the parse blockers.
sbom-curator lint product.spdx

# Drop the product's own DLLs (a .NET app whose assemblies share a prefix
# floods 'added' otherwise). Repeatable.
sbom-curator ingest ... --product-prefix Hermes.

# Gate CI on findings. Ingest buckets: added,bumped,review,license.
# Reconcile buckets: only-in-syft,only-in-manual,version,license.
sbom-curator ingest ... --fail-on added,bumped

# Strip sbom-curator tool annotations (e.g. covers-prefix) for delivery.
sbom-curator finalize artifacts/                # manual/ -> finalized/
sbom-curator finalize --manual M --output O     # single file
```

A manual entry can declare it covers a family by adding
`PackageComment: <text>sbom-curator covers-prefix: Vortice.</text>` —
every unmatched `Vortice.*` from the scan absorbs into that entry. The report
proposes new `covers-prefix:` annotations when it spots tight clusters.

Automatic per-run cleanup: scan packages with no usable version (`UNKNOWN`,
missing) or path-like names (vendored binaries inside source trees) are
dropped; exact duplicates and NuGet semver ↔ .NET assembly-version pairs are
collapsed.

## Try it

The repo ships a fixture pair at
[`tests/fixtures/dogfood/dicom-fuzzer-1.11.0/`](tests/fixtures/dogfood/dicom-fuzzer-1.11.0/) —
a manual SBOM (with two vendored entries the scanner can't see) and a Syft
scan of the project's venv.

```bash
sbom-curator ingest \
    --manual tests/fixtures/dogfood/dicom-fuzzer-1.11.0/manual.spdx \
    --syft   tests/fixtures/dogfood/dicom-fuzzer-1.11.0/syft.spdx.json \
    --name   dicom-fuzzer-1.11.0
```

```text
[+] wrote artifacts/dicom-fuzzer-1.11.0-ingest.md
[!] added: 74
[!] bumped: 2
[i] only in your SBOM: 2
[+] unchanged: 56 (1 with a license change)
```

`74` added (mostly dev/test tooling that doesn't ship), `2` bumped (`cffi`,
`packaging`), `2` only in the SBOM (the vendored entries), `56` unchanged with
`1` license drift (`click`). See [`docs/WORKFLOW.md`](docs/WORKFLOW.md) for the
end-to-end curator guide.

## How matching works

- **Three-pass matcher**: PURL identity → lowercased name → `covers-prefix:`
  family coverage. A PURL on the manual entry bridges renames; coverage is
  opt-in.
- **Version equivalence**: PEP 440, plus the NuGet semver ↔ .NET
  assembly-revision rule (`4.4.1` ↔ `4.4.1.57983`). `1.0` and `1.0.0` agree;
  `1.0.0+local` is distinct.
- **License equivalence**: SPDX expression parsing. A license change is
  reported only when both sides carry a license and they differ.
- **Never writes back**: `ingest` produces a report; the curator applies it by
  hand. Auto-rewrite would clobber formatting, comments, and curated
  relationships.

## Development

```bash
pip install -e ".[dev]"

ruff check .
mypy sbom_curator
pytest --cov=sbom_curator --cov-branch
bandit -c pyproject.toml -r sbom_curator
```

## License

MIT
