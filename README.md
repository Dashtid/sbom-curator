# sbom-curator

[![CI](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/sbom-curator/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/sbom-curator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dashtid/sbom-curator/badge)](https://scorecard.dev/viewer/?uri=github.com/Dashtid/sbom-curator)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)

Curate one authoritative SPDX SBOM — the kind FDA submissions ask for, meeting
the [NTIA minimum baseline](https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf) —
and use Syft scans as input to keep it current. The tool reads the manual SBOM
and a fresh Syft SBOM and tells the curator what changed: new components,
version drift, license drift.

## Why

For regulated software (medical-device submissions, supply-chain compliance),
**one** authoritative SBOM is the deliverable, hand-maintained by a person who
knows what's actually shipping. Scanners alone don't meet the bar — they miss
vendored binaries and statically linked libraries — and a hand-rolled SBOM
written from scratch every release is brittle and expensive to keep honest.

The curator's loop:

1. Maintain `manual.spdx` by hand, comprehensive enough to cover NTIA baseline.
2. Run Syft against each release build to get a fresh `syft.spdx.json`.
3. Run sbom-curator to surface deltas: new components, version bumps, license
   drift, vendored entries Syft can't see.
4. Decide which deltas land in the manual SBOM. Submit the manual SBOM.

Two commands serve that loop:

- `ingest` — the curator's command. Turns a Syft scan into an edit plan:
  **bumps** (manual has an older version), **adds** (Syft saw it, manual
  doesn't list it), **keeps** (already in agreement; license drift flagged),
  **preserves** (manual lists it, Syft can't see it — leave it alone). The
  curator reads the plan and edits the manual SBOM by hand.
- `reconcile` — the raw four-bucket diff (only-in-manual, only-in-Syft,
  version disagreements, license disagreements). Useful for triage without
  intent to ingest, or as a sanity cross-check.

Neither command rewrites the manual SBOM. An `ingest --apply` mode is
deferred — see [`BACKLOG.md`](BACKLOG.md).

## Position vs sbom-sentinel

| Tool          | Job                                                           |
| ------------- | ------------------------------------------------------------- |
| sbom-sentinel | One SBOM in, vulnerability + KEV report out                   |
| sbom-curator  | Maintain one authoritative SBOM; ingest from periodic scans   |

They are complementary, not coupled.

## Install

```bash
pip install -e .
```

## Usage

```bash
# The curator's command: Syft scan in, edit plan out
sbom-curator ingest \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0

# The raw diff
sbom-curator reconcile \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0
```

`--manual` accepts any SPDX 2.x serialization spdx-tools understands
(tag-value `.spdx`, JSON, YAML, RDF/XML); `--syft` likewise. `ingest` writes
`<output-dir>/<name>-ingest.md`; `reconcile` writes
`<output-dir>/<name>-reconcile.md`. Exit code is `0` on success, `2` on parse
failure.

## Try it

The repo ships a real fixture pair under
[`tests/fixtures/dogfood/dicom-fuzzer-1.11.0/`](tests/fixtures/dogfood/dicom-fuzzer-1.11.0/) —
a hand-curated manual SBOM (comprehensive on shipped components, NTIA-baseline
shape, plus two vendored entries Syft can't see) and a Syft scan of the
project's installed venv. Run:

```bash
sbom-curator ingest \
    --manual tests/fixtures/dogfood/dicom-fuzzer-1.11.0/manual.spdx \
    --syft   tests/fixtures/dogfood/dicom-fuzzer-1.11.0/syft.spdx.json \
    --name   dicom-fuzzer-1.11.0
```

Terminal:

```text
[+] wrote artifacts/dicom-fuzzer-1.11.0-ingest.md
[!] bumps: 2
[!] adds: 75
[i] keeps: 56 (1 with license drift)
[+] preserves: 2
```

This is the **healthy curator shape**: a couple of **bumps** (manual versions
that lag the Syft scan), a modest **adds** list (dev tooling like pytest, ruff,
mypy, pre-commit, type stubs — material that doesn't ship and so doesn't belong
in the FDA SBOM, plus a handful of transitives to consider), a large **keeps**
core (shipped runtime deps already in agreement), and a small **preserves**
list (the vendored entries Syft can't see). The plan at
`artifacts/dicom-fuzzer-1.11.0-ingest.md` enumerates the bumps, adds, preserves,
and any keeps with license drift; quiet keeps are counted but not listed so the
actionable sections stand out.

`reconcile` against the same pair gives the underlying four-bucket diff
(`only in manual: 2 / only in Syft: 75 / in both, agree: 56 / version
disagreements: 2 / license disagreements: 1`). Empty sections render as
`(none)` so reports diff cleanly run-to-run. See
[`docs/WORKFLOW.md`](docs/WORKFLOW.md) for the curator's end-to-end guide.

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
- **Neither command writes back to the manual SBOM.** `ingest` produces an
  edit plan; the curator applies it by hand. Auto-rewrite (`ingest --apply`)
  is deferred and will stay opt-in — see [`BACKLOG.md`](BACKLOG.md). Editing
  by hand keeps the curator's formatting, comments, package groupings, and
  curated relationships intact.

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
