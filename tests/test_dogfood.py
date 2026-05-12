"""End-to-end checks on the dicom-fuzzer dogfood fixture pair.

The manual SBOM in this fixture is comprehensive on shipped components
plus a couple of vendored entries only a hand-curated SBOM can record;
Syft's scan covers the same shipped components plus dev/test tooling.
That overlap exercises every bucket end-to-end: a large agreed core,
a modest only-in-Syft / "added" list (build tooling), a small
only-in-manual / "review" list (vendored), and small version/license
deltas. (Comprehensive is one valid curation scope; the tool doesn't
require it — a focused list works too.)

Bucket-level reconciler logic is exhaustively tested with synthetic
Component records in tests/test_reconcile.py; this file is the
real-world end-to-end anchor.
"""

from pathlib import Path

from sbom_curator.curate.ingest import plan
from sbom_curator.parsers.spdx import load
from sbom_curator.reconcile.diff import reconcile

DOGFOOD = Path(__file__).parent / "fixtures" / "dogfood" / "dicom-fuzzer-1.11.0"


def test_manual_sbom_includes_vendored_and_shipped_runtime_components() -> None:
    components = load(DOGFOOD / "manual.spdx", source="manual")
    names = {c.name for c in components}

    # The vendored entries Syft cannot see — only a hand-curated SBOM
    # can record them.
    assert {"internal-dicom-codec", "vendored-zlib"} <= names

    # Comprehensive on shipped runtime deps too. Spot-check that the
    # core DICOM libraries the manual must declare are present.
    assert {"pydicom", "pynetdicom", "numpy", "cryptography"} <= names


def test_syft_sbom_parses_and_covers_more_than_the_manual() -> None:
    syft_components = load(DOGFOOD / "syft.spdx.json", source="syft")
    manual_components = load(DOGFOOD / "manual.spdx", source="manual")

    # Syft sees the whole venv (including dev tooling); the manual
    # covers shipped components + vendored entries only.
    assert len(syft_components) > 100
    assert len(syft_components) > len(manual_components)


def test_dogfood_reconciliation_is_the_healthy_shape() -> None:
    manual = load(DOGFOOD / "manual.spdx", source="manual")
    syft = load(DOGFOOD / "syft.spdx.json", source="syft")
    result = reconcile(manual, syft)

    # The two vendored components Syft cannot see.
    assert {c.name for c in result.only_in_manual} == {
        "internal-dicom-codec",
        "vendored-zlib",
    }

    # Large in-both bucket: the curator captured shipped components and
    # they agree with the Syft scan.
    assert len(result.in_both) > 50

    # Modest only-in-Syft bucket: dev tooling (pytest, ruff, mypy,
    # pre-commit, type stubs, packaging machinery) the curator
    # deliberately doesn't track, plus a handful of transitives.
    assert len(result.only_in_syft) > 30

    # The product itself does not leak into only-in-Syft. Syft lists
    # dicom-fuzzer twice (the scanned-directory root and the installed
    # package); the parser filters both out by name.
    assert "dicom-fuzzer" not in {c.name for c in result.only_in_syft}

    # Two deliberate version mismatches (cffi, packaging) and one
    # deliberate license mismatch (click) exercise those buckets.
    assert {m.name for m, _ in result.version_mismatches} == {"cffi", "packaging"}
    assert {m.name for m, _ in result.license_mismatches} == {"click"}


def test_dogfood_change_report_relabels_the_buckets() -> None:
    manual = load(DOGFOOD / "manual.spdx", source="manual")
    syft = load(DOGFOOD / "syft.spdx.json", source="syft")
    p = plan(manual, syft)

    # The version mismatches become bumps; the vendored entries become
    # the "only in your SBOM" review list; the rest of the in-both
    # bucket is unchanged (keeps).
    assert {b.manual.name for b in p.bumped} == {"cffi", "packaging"}
    assert {a.manual.name for a in p.reviews} == {
        "internal-dicom-codec",
        "vendored-zlib",
    }
    assert len(p.keeps) > 50
    assert len(p.added) > 30

    # The product itself is not a phantom "add".
    assert all(a.syft.name != "dicom-fuzzer" for a in p.added)

    # click's license differs on both sides (Apache-2.0 vs BSD-3-Clause),
    # so it surfaces as an unchanged entry with a license change.
    assert {k.manual.name for k in p.keeps_with_license_change} == {"click"}
