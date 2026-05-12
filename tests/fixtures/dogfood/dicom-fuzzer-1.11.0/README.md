# dicom-fuzzer 1.11.0 dogfood fixture

Real-shape SPDX-on-SPDX pair. Used by `tests/test_dogfood.py` as an
end-to-end anchor and by the README as the running example.

## Files

- `manual.spdx` — hand-curated SPDX 2.3 tag-value SBOM, comprehensive on
  the components dicom-fuzzer ships plus two vendored entries only a
  hand-curated SBOM can record (one statically linked C++ codec, one
  vendored zlib). Dev/test tooling (pytest, ruff, mypy, pre-commit, type
  stubs, packaging machinery) is deliberately excluded — that material
  doesn't ship, so it shows up in the report's *added* bucket as expected.
  (Comprehensive is one valid curation scope; the tool supports a focused
  list just as well — this fixture happens to use the comprehensive one
  because it exercises more buckets.)
- `syft.spdx.json` — Syft scan of the project's installed venv,
  locked to the version present at scan time. Refresh with
  `scripts/refresh_dogfood.sh`.

## What this demonstrates

A change report with every section populated. See
[`docs/WORKFLOW.md`](../../../../docs/WORKFLOW.md) for the full curator
guide. `sbom-curator ingest` against this pair:

| Section | Count | What it means |
| --- | --- | --- |
| Added | ~74 | In the scan, not in the SBOM — dev/test tooling (pytest, ruff, mypy, pre-commit, type stubs, packaging machinery) plus a handful of transitives. The curator decides which (if any) belong in the SBOM. |
| Bumped | 2 | `cffi` and `packaging` are intentionally one minor behind the scan, exercising the bumped bucket. |
| Only in your SBOM | 2 | The vendored entries the scanner can't see. Left alone. |
| Unchanged | ~56 | The shipped runtime deps the curator captured and the scan confirmed — the bulk of the SBOM. **1** with a license change: `click` is intentionally listed with a different license than the scan's declared value. |

(`reconcile` against the same pair gives the underlying four-bucket diff:
only-in-manual 2 / only-in-Syft 74 / in-both 56 / version disagreements 2
/ license disagreements 1.)

Bucket-level matcher logic is exhaustively tested with synthetic
`Component` records in `tests/test_reconcile.py`; this fixture's job is
to be a real-world end-to-end anchor.

## Reproducibility

`syft.spdx.json` is environment-dependent: a different installed venv
produces different transitive dep versions. The fixture is locked to
dicom-fuzzer 1.11.0's venv state at the time `refresh_dogfood.sh` was
run. When dicom-fuzzer ships a new minor version, add a sibling
directory (`dicom-fuzzer-1.12.0/`) rather than overwriting this one.

`manual.spdx` is committed by hand but its shipped-component entries
match the Syft scan's package names and (mostly) versions on purpose
— a real curator would update both together each release.

## Refresh command

```bash
syft scan dir:c:/code-two/dicom-fuzzer/.venv \
  -o spdx-json=tests/fixtures/dogfood/dicom-fuzzer-1.11.0/syft.spdx.json \
  --source-name dicom-fuzzer \
  --source-version 1.11.0 \
  --override-default-catalogers python-installed-package-cataloger
```

The `python-installed-package-cataloger` override drops Go-binary
detection (iterfzf bundles `fzf`) and `\Scripts\...` entry-point noise.
Both are real artifacts in the venv but neither is a Python dependency
the manual SBOM would track.
