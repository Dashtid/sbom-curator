"""End-to-end checks on the dicom-fuzzer dogfood fixture pair.

The fixture models the slim-manual philosophy: the manual SBOM lists
only what Syft can't see (vendored binaries, statically linked libs),
and Syft fills in the comprehensive dependency picture. These tests
assert that healthy shape.

Bucket-level reconciler logic is exhaustively tested with synthetic
Component records in tests/test_reconcile.py; this file is the
real-world end-to-end anchor.
"""

from pathlib import Path

from sbom_overlay.parsers.spdx import load
from sbom_overlay.reconcile.diff import reconcile

DOGFOOD = Path(__file__).parent / "fixtures" / "dogfood" / "dicom-fuzzer-1.11.0"


def test_manual_sbom_lists_only_vendored_components() -> None:
    components = load(DOGFOOD / "manual.spdx", source="manual")
    names = {c.name for c in components}

    # Slim manual: only the things Syft cannot see.
    assert names == {"internal-dicom-codec", "vendored-zlib"}


def test_syft_sbom_parses_and_dwarfs_manual() -> None:
    syft_components = load(DOGFOOD / "syft.spdx.json", source="syft")
    manual_components = load(DOGFOOD / "manual.spdx", source="manual")

    # Syft finds the comprehensive view; manual is intentionally tiny.
    assert len(syft_components) > 50
    assert len(syft_components) > 10 * len(manual_components)


def test_dogfood_reconciliation_is_the_healthy_shape() -> None:
    manual = load(DOGFOOD / "manual.spdx", source="manual")
    syft = load(DOGFOOD / "syft.spdx.json", source="syft")
    result = reconcile(manual, syft)

    # The two vendored components Syft cannot see.
    assert {c.name for c in result.only_in_manual} == {
        "internal-dicom-codec",
        "vendored-zlib",
    }

    # Syft's comprehensive view, none of which the curator re-listed.
    assert len(result.only_in_syft) > 50

    # Healthy slim manuals don't deliberately overlap with Syft. The
    # vendored entries' names don't collide with any PyPI package, so
    # there are no coincidental matches either.
    assert result.in_both == []
    assert result.version_mismatches == []
    assert result.license_mismatches == []
