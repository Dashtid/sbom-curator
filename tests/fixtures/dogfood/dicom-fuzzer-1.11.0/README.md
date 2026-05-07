# dicom-fuzzer 1.11.0 dogfood fixture

Real-shape SPDX-on-SPDX reconciliation pair. Used by `tests/test_dogfood.py`
as an end-to-end anchor and by the README as the running example.

## Files

- `manual.spdx` — hand-written SPDX 2.3 tag-value SBOM modelling the
  slim-manual philosophy: lists only components a scanner cannot see
  (one statically linked C++ codec, one vendored zlib copy). The real
  PyPI dependencies aren't here because Syft already finds them.
- `syft.spdx.json` — Syft scan of the project's installed venv, locked
  to the version present at scan time. Refresh with
  `scripts/refresh_dogfood.sh`.

## What this demonstrates

The slim-manual philosophy in action. See [`docs/WORKFLOW.md`](../../../../docs/WORKFLOW.md)
for the full curator guide. The reconciliation result is the healthy
shape:

| Bucket | Count | What it means |
| --- | --- | --- |
| Only in manual | 2 | The vendored entries the curator added because Syft can't see them. |
| Only in Syft | ~134 | Everything Syft found — direct deps, transitive deps, dev deps. The curator correctly didn't re-list any of these. |
| In both, agree | 0 | No coincidental name collisions. |
| Version / license disagreements | 0 | Nothing to disagree about — the buckets above don't intersect. |

A "real" disagreement bucket only fires when the curator's slim manual
genuinely overlaps with Syft's view (rare in practice — usually
indicates a vendored component that *also* ships a package manifest
Syft picks up).

Bucket-level reconciler logic is exhaustively tested with synthetic
`Component` records in `tests/test_reconcile.py`; this fixture's job is
to be a real-world end-to-end anchor, not a bucket-coverage demo.

## Reproducibility

`syft.spdx.json` is environment-dependent: a different installed venv
produces different transitive dep versions. The fixture is locked to
dicom-fuzzer 1.11.0's venv state at the time `refresh_dogfood.sh` was
run. When dicom-fuzzer ships a new minor version, add a sibling
directory (`dicom-fuzzer-1.12.0/`) rather than overwriting this one.

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
