# sbom-curator

[![CI](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/sbom-curator/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/sbom-curator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dashtid/sbom-curator/badge)](https://scorecard.dev/viewer/?uri=github.com/Dashtid/sbom-curator)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)

Reconcile a hand-curated SPDX SBOM (the authoritative artifact, e.g. for FDA
submission) against an automatically generated Syft SBOM. Surfaces components
the manual SBOM may have missed, and version or license disagreements between
the two views.

## Why

Manual SBOMs catch what scanners can't see (vendored binaries, statically
linked libraries, runtime-loaded plugins). Scanners catch what humans miss
(transitive deps, build-time tooling, generated artifacts). Neither is
complete on its own; the safe artifact is the union, triaged.

This tool produces that triage report.

## Position vs sbom-sentinel

| Tool          | Job                                              |
| ------------- | ------------------------------------------------ |
| sbom-sentinel | One SBOM in, vulnerability + KEV report out      |
| sbom-curator  | Two SBOMs in, reconciliation triage report out   |

They are complementary, not coupled.

## Install

```bash
pip install -e .
```

## Usage

```bash
sbom-curator reconcile \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0
```

`--manual` accepts any SPDX 2.x serialization spdx-tools understands
(tag-value `.spdx`, JSON, YAML, RDF/XML); `--syft` likewise. The report
lands at `<output-dir>/<name>-overlay.md`. Exit code is `0` on success,
`2` on parse failure.

## Try it

The repo ships a real fixture pair under
`tests/fixtures/dogfood/dicom-fuzzer-1.11.0/` — a slim hand-written manual
SBOM (only the components Syft can't see) plus a Syft scan of the
project's installed venv. Run:

```bash
sbom-curator reconcile \
    --manual tests/fixtures/dogfood/dicom-fuzzer-1.11.0/manual.spdx \
    --syft   tests/fixtures/dogfood/dicom-fuzzer-1.11.0/syft.spdx.json \
    --name   dicom-fuzzer-1.11.0
```

Terminal:

```text
[+] wrote artifacts/dicom-fuzzer-1.11.0-overlay.md
[+] in both, agree: 0
[!] version disagreements: 0
[!] license disagreements: 0
[!] only in Syft: 133
[i] only in manual: 2
```

This is the **healthy shape**: a small `Only in manual` bucket (the
vendored entries), a large `Only in Syft` bucket (everything Syft
found, which the curator correctly didn't re-list), no overlap, no
disagreements. The Markdown report itself:

```markdown
# SBOM reconciliation report — dicom-fuzzer-1.11.0

## Summary

- Only in manual: 2
- Only in Syft: 133
- In both, agree on version: 0
- Version disagreements: 0
- License disagreements: 0

## Only in manual

| Name | Version | License | PURL |
| --- | --- | --- | --- |
| internal-dicom-codec | 1.0.0 | MIT | _n/a_ |
| vendored-zlib | 1.3.1 | Zlib | _n/a_ |

## Version disagreements

(none)
```

Empty buckets render as `(none)` so the report's diff is stable
run-to-run. See [`docs/WORKFLOW.md`](docs/WORKFLOW.md) for the full
curator guide and the slim-manual philosophy.

## v1 limitations (deliberate)

- **Component identity** is lowercase name match. PURL-based matching is
  deferred because PURLs embed the version and cannot match the
  same-name-different-version disagreement bucket.
- **Version equivalence** uses PEP 440. `1.0` and `1.0.0` agree;
  `1.0.0+local` is treated as a distinct release. Unparseable versions
  fall back to strict string equality.
- **License equivalence** uses SPDX expression parsing.
  `Apache-2.0 OR MIT` and `MIT OR Apache-2.0` agree (`OR`/`AND` are
  commutative); `Apache-2.0` and `Apache 2.0` do not (the latter is not
  a valid SPDX identifier). Unparseable expressions fall back to strict
  string equality.
- **No CycloneDX support.** Have Syft emit SPDX
  (`syft scan ... -o spdx-json=...`) — both sides same format, no
  translation layer.

## Development

```bash
pip install -e ".[dev]" || pip install -e .
pip install pytest pytest-cov ruff mypy bandit

ruff check .
mypy sbom_curator
pytest --cov=sbom_curator --cov-branch
bandit -c pyproject.toml -r sbom_curator
```

## License

MIT
