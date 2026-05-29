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

One command, two paths in, one Markdown report out:

```bash
sbom-curator ingest \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0
```

Open `artifacts/product-1.0.0-ingest.md`, read four sections (added /
bumped / only in your SBOM / unchanged), decide what to transfer by hand.
That's the whole workflow. The manual SBOM is never modified.

`--manual` accepts any SPDX 2.x serialization spdx-tools understands
(tag-value `.spdx`, JSON, YAML, RDF/XML). **`--syft` must be SPDX** — if
your scanner emits CycloneDX, convert first (`syft convert in.json -o
spdx-json=out.spdx.json`) or re-scan with `-o spdx-json=...`. Exit code is
`0` on success, `2` on parse failure.

### Optional extras (skip until the basic report is too noisy)

```bash
# Folder-scan mode: discover every (manual, scan) pair in the conventional
# artifacts/manual/ + artifacts/syft/ layout and ingest each. One report
# per pair lands in artifacts/reports/. Worst exit code across pairs wins.
sbom-curator ingest artifacts/

# Raw four-bucket diff instead of the action-relabelled change report.
sbom-curator reconcile --manual ... --syft ... --name ...

# Preflight: actionable line-numbered errors for the few SPDX gotchas
# that block parsing (e.g. PackageVersion: NOASSERTION).
sbom-curator lint product.spdx

# Drop the product's own DLLs (a .NET app whose assemblies share a prefix
# floods 'added' with hundreds of them otherwise). Repeatable.
sbom-curator ingest ... --product-prefix Hermes

# Gate CI on findings -- exit 1 instead of 0 if any listed bucket is
# non-empty. Ingest: added,bumped,review,license. Reconcile:
# only-in-syft,only-in-manual,version,license.
sbom-curator ingest ... --fail-on added,bumped     # exit 1 if either non-empty

# Finalize: strip sbom-curator covers-prefix (and any other sbom-curator
# <key>:) annotations from your manual SBOM, producing a clean copy for
# delivery to the regulator. Source is never modified.
sbom-curator finalize artifacts/                   # folder: manual/ -> finalized/
sbom-curator finalize --manual M --output O        # single file
```

A manual entry can declare it covers a family of scan packages by adding
one line to its `PackageComment` — e.g.
`PackageComment: <text>sbom-curator covers-prefix: Vortice.</text>` makes
that entry absorb every `Vortice.*` the scan finds. The report tells you
when a tight cluster of "added" packages might warrant a new
`covers-prefix:` annotation; you decide whether to add it. None of this
is required.

Cleanup that happens **automatically** every run (no flags, no thought):
loose binaries inside vendored source trees (a name that's a filesystem
path, version `UNKNOWN`) are dropped; a package the scan lists more than
once is collapsed (Syft emitting the same NuGet 12×, or a NuGet semver
alongside its .NET assembly version). Genuine multi-version installs are
kept.

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

## How matching works

- **Matching tries PURL first, then exact lowercased name, then optional
  family coverage.** A PURL on your manual entry bridges renames (record
  `pkg:nuget/System.Reactive@4.4.1` on a `Reactive` entry and it matches
  the scan's `System.Reactive`). Name match is literal. Family coverage
  is opt-in (`covers-prefix:` annotation, above) and only fires for
  entries still unmatched after the first two passes.
- **Version equivalence** uses PEP 440, plus the NuGet semver ↔ .NET
  assembly-revision pattern (`4.4.1` ↔ `4.4.1.57983`). `1.0` and `1.0.0`
  agree; `1.0.0+local` is a distinct release.
- **License equivalence** uses SPDX expression parsing. A *license
  change* is only reported when **both** sides carry a license and they
  differ — "you say MIT, the scan says nothing" is silence, not a finding.
- **Neither command writes back to your SBOM.** `ingest` produces a
  report; you apply it by hand. That's the point — auto-rewrite would
  lose your formatting, comments, package groupings, and curated
  relationships, all of which matter to a regulator.

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
