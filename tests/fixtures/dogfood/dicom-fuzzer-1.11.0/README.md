# dicom-fuzzer 1.11.0 dogfood fixture

Real-shape SPDX-on-SPDX reconciliation pair. Used by `tests/test_dogfood.py`
as an end-to-end anchor and by the README as the running example.

## Files

- `manual.spdx` — hand-curated SPDX 2.3 tag-value SBOM modelling the
  FDA-curator philosophy: comprehensive enough on its own to meet
  NTIA minimum baseline for the components dicom-fuzzer ships, plus
  vendored entries only a hand-curated SBOM can record (one
  statically linked C++ codec, one vendored zlib). Dev/test tooling
  (pytest, ruff, mypy, pre-commit, type stubs, packaging machinery)
  is deliberately excluded — that material doesn't ship and lands
  in the report's only-in-Syft bucket.
- `syft.spdx.json` — Syft scan of the project's installed venv,
  locked to the version present at scan time. Refresh with
  `scripts/refresh_dogfood.sh`.

## What this demonstrates

The FDA-curator philosophy in action. See [`docs/WORKFLOW.md`](../../../../docs/WORKFLOW.md)
for the full curator guide. The reconciliation result has every bucket
populated:

| Bucket | Count | What it means |
| --- | --- | --- |
| Only in manual | 2 | The vendored entries the curator added because Syft can't see them. |
| Only in Syft | ~74 | Dev tooling (pytest, ruff, mypy, pre-commit, type stubs, packaging machinery) and a handful of transitives the curator deliberately doesn't track because they don't ship with the product. |
| In both, agree | ~55 | The shipped runtime deps the curator captured and Syft confirmed. The bulk of the SBOM. |
| Version disagreements | 2 | `cffi` and `packaging` are intentionally one minor behind the Syft view, exercising the version_mismatches bucket. |
| License disagreements | 1 | `click` is intentionally listed with a different license than Syft's declared value, exercising the license_mismatches bucket. |

A real-world reconciliation looks like this most of the time: a large
agreed core, a modest TODO list of components to either add to the
manual or explicitly mark as "doesn't ship," and a handful of
disagreements that point at drift the curator hasn't caught up with
yet.

Bucket-level reconciler logic is exhaustively tested with synthetic
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
