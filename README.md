# sbom-curator

[![CI](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/sbom-curator/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/sbom-curator/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/sbom-curator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dashtid/sbom-curator/badge)](https://scorecard.dev/viewer/?uri=github.com/Dashtid/sbom-curator)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)

You maintain one SPDX SBOM by hand — the artifact your regulator (FDA, in the
medical-device case) receives. sbom-curator compares it against a scan and
tells you **what changed**: what the scan added, what got bumped, what's in
your SBOM but not the scan. You decide what to merge. The tool never modifies
your SBOM.

## Why

For regulated software, **one** SBOM is the deliverable, hand-maintained by a
person who knows what's actually shipping. A scanner can't author that artifact
(it misses vendored binaries and statically linked libs, and it can't add the
supplier/license/relationship metadata a regulator expects) — and rewriting the
SBOM from scratch every release is brittle. So you keep the SBOM authoritative
and use periodic scans to see what's drifted.

The loop:

1. Maintain `manual.spdx` by hand, at whatever granularity your submission
   scope calls for. (A focused list of significant third-party components is a
   valid scope; so is a full closure. Your call — the tool doesn't enforce one.)
2. Scan each release build with Syft, emitting **SPDX JSON**
   (`syft scan ... -o spdx-json=...`).
3. Run `sbom-curator ingest` to get a change report — *added*, *bumped*,
   *only in your SBOM*, plus any *license changes* on otherwise-unchanged
   entries.
4. Apply the changes you accept to `manual.spdx` by hand. Ship the SBOM.

Two commands:

- **`ingest`** — the curator's command. A change report from a scan:
  **added** (in the scan, not in your SBOM), **bumped** (in both, version
  differs), **only in your SBOM** (the scan lists nothing by that name —
  review whether it's vendored, renamed, or gone), **unchanged** (counted, not
  listed — except ones whose license changed). You read it; you edit by hand.
- **`reconcile`** — the raw four-bucket diff (only-in-manual, only-in-Syft,
  version disagreements, license disagreements). The primitive `ingest` is
  built on; handy as a cross-check.

Neither command rewrites your SBOM. An `ingest --apply` mode is deferred —
see [`BACKLOG.md`](BACKLOG.md).

## Position vs sbom-sentinel

| Tool          | Job                                                            |
| ------------- | -------------------------------------------------------------- |
| sbom-sentinel | One SBOM in, vulnerability + KEV report out                    |
| sbom-curator  | Your SBOM + a scan in, "here's what changed" report out        |

They are complementary, not coupled.

## Install

```bash
pip install -e .
```

## Usage

```bash
# The curator's command: your SBOM + a scan -> change report
sbom-curator ingest \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0

# The raw four-bucket diff
sbom-curator reconcile \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0

# Preflight an SPDX file: catch spec violations and silent-skip cases
sbom-curator lint product.spdx
```

`--manual` accepts any SPDX 2.x serialization spdx-tools understands
(tag-value `.spdx`, JSON, YAML, RDF/XML). **`--syft` must be SPDX** — if your
scanner emits CycloneDX, convert first (`syft convert in.json -o
spdx-json=out.spdx.json`) or re-scan with `-o spdx-json=...`. `ingest` writes
`<output-dir>/<name>-ingest.md`; `reconcile` writes
`<output-dir>/<name>-reconcile.md`. Exit code is `0` on success, `2` on parse
failure.

A directory scan of a multi-assembly app (notably .NET) needs two kinds of
cleanup, both applied to the `--syft` side before the diff:

- **Automatic:** loose binaries inside vendored source trees (a name that's a
  path, version `UNKNOWN`) are dropped; a package the scan lists more than
  once — exact duplicates, or a NuGet semver (`9.0.0`) alongside its .NET
  assembly version (`9.0.24.52809`) — is collapsed to one. Genuine
  multi-version installs are kept. The run prints how many it dropped.
- **You point it out:** `--product-prefix` drops the product's own DLLs by
  name prefix, e.g. `--product-prefix Hermes.` for an app whose assemblies
  are all `Hermes.*` (also handy for framework noise you don't track:
  `--product-prefix System. --product-prefix Microsoft.Extensions.`).
  Repeatable, case-insensitive.

## Try it

The repo ships a real fixture pair under
[`tests/fixtures/dogfood/dicom-fuzzer-1.11.0/`](tests/fixtures/dogfood/dicom-fuzzer-1.11.0/) —
a hand-curated manual SBOM (comprehensive on the components dicom-fuzzer ships,
plus two vendored entries the scanner can't see) and a Syft scan of the
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
[!] added: 74
[!] bumped: 2
[i] only in your SBOM: 2
[+] unchanged: 56 (1 with a license change)
```

What that means: the scan turned up **74** components not in the SBOM (mostly
dev/test tooling — pytest, ruff, mypy, pre-commit, type stubs — that doesn't
ship; plus a handful of real transitives to consider); **2** components are
listed at an older version than the scan (`cffi`, `packaging`); **2** are in
the SBOM but not the scan (the vendored entries the scanner can't see — leave
them); and **56** are unchanged, **1** of those with a license that differs
between the SBOM and the scan (`click`). The report at
`artifacts/dicom-fuzzer-1.11.0-ingest.md` enumerates the added / bumped /
only-in-your-SBOM entries and the one license change; unchanged-and-unchanged
entries are counted but not listed so the actionable parts stand out.

`reconcile` against the same pair gives the underlying four-bucket diff
(`only in manual: 2 / only in Syft: 74 / in both, agree: 56 / version
disagreements: 2 / license disagreements: 1`). Empty sections render as
`(none)` so reports diff cleanly run-to-run. See
[`docs/WORKFLOW.md`](docs/WORKFLOW.md) for the curator's end-to-end guide.

## v1 limitations (deliberate)

- **Matching is PURL first, then exact lowercase name, then family coverage.**
  PURL match: if your entry and a scan entry share a package URL (compared
  version-free), they match even when the names differ — recording
  `pkg:nuget/System.Reactive@4.4.1` on your `Reactive` entry bridges it to
  the scan's `System.Reactive`. Name match: literal lowercased equality.
  Family coverage: add `PackageComment: <text>sbom-curator covers-prefix:
  Vortice.</text>` to an entry and the matcher absorbs every still-unmatched
  scan package whose name starts with that prefix — `Vortice` covers
  `Vortice.DXGI`, `Vortice.Direct3D11`, etc. Covered packages land in a
  dedicated `## Covered by a family entry` section, not in `## Added`.
- **Version equivalence** uses PEP 440. `1.0` and `1.0.0` agree;
  `1.0.0+local` is a distinct release. Unparseable versions fall back to strict
  string equality.
- **License equivalence** uses SPDX expression parsing.
  `Apache-2.0 OR MIT` and `MIT OR Apache-2.0` agree; `Apache-2.0` and `Apache
  2.0` do not (the latter isn't a valid SPDX identifier). A *license change* is
  only reported when **both** sides carry a license and they differ — "you say
  MIT, the scan says nothing" is silence, not a finding.
- **SPDX only.** If your scanner emits CycloneDX, convert it to SPDX JSON
  first (`syft convert`) — no in-tree translation layer.
- **Neither command writes back to your SBOM.** `ingest` produces a report;
  you apply it by hand. Auto-rewrite (`ingest --apply`) is deferred and will
  stay opt-in — see [`BACKLOG.md`](BACKLOG.md). Editing by hand keeps your
  formatting, comments, package groupings, and curated relationships intact.

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
