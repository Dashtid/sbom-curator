from sbom_curator.curate.ingest import (
    AddAction,
    BumpAction,
    KeepAction,
    ReviewAction,
    plan,
)
from sbom_curator.parsers.model import Component


def _manual(name: str, version: str = "1.0.0", license: str | None = None) -> Component:
    return Component(name=name, version=version, source="manual", license=license)


def _syft(name: str, version: str = "1.0.0", license: str | None = None) -> Component:
    return Component(name=name, version=version, source="syft", license=license)


def test_empty_inputs_produce_empty_plan() -> None:
    p = plan([], [])
    assert p.added == []
    assert p.bumped == []
    assert p.reviews == []
    assert p.keeps == []
    assert p.keeps_with_license_change == []


def test_only_in_manual_becomes_review() -> None:
    p = plan([_manual("vendored-zlib", "1.3.1")], [])
    assert p.added == []
    assert p.bumped == []
    assert p.keeps == []
    assert [a.manual.name for a in p.reviews] == ["vendored-zlib"]
    assert isinstance(p.reviews[0], ReviewAction)


def test_only_in_syft_becomes_added() -> None:
    p = plan([], [_syft("attrs", "25.4.0")])
    assert [a.syft.name for a in p.added] == ["attrs"]
    assert isinstance(p.added[0], AddAction)
    assert p.bumped == []
    assert p.keeps == []
    assert p.reviews == []


def test_matching_versions_become_keep() -> None:
    p = plan([_manual("rich", "13.0.0")], [_syft("rich", "13.0.0")])
    assert [a.manual.name for a in p.keeps] == ["rich"]
    assert isinstance(p.keeps[0], KeepAction)
    assert p.bumped == []
    assert p.added == []
    assert p.reviews == []


def test_pep440_equivalent_versions_become_keep_not_bump() -> None:
    p = plan([_manual("foo", "1.0")], [_syft("foo", "1.0.0")])
    assert len(p.keeps) == 1
    assert p.bumped == []


def test_differing_versions_become_bumped() -> None:
    p = plan([_manual("packaging", "24.2")], [_syft("packaging", "25.0")])
    assert len(p.bumped) == 1
    assert isinstance(p.bumped[0], BumpAction)
    assert p.bumped[0].manual.version == "24.2"
    assert p.bumped[0].syft.version == "25.0"
    assert p.keeps == []


def test_keep_with_license_change_is_flagged() -> None:
    # Both sides carry a license and they differ -> a real change.
    p = plan(
        [_manual("click", "8.3.1", license="Apache-2.0")],
        [_syft("click", "8.3.1", license="BSD-3-Clause")],
    )
    assert p.keeps[0].license_changed is True
    assert [k.manual.name for k in p.keeps_with_license_change] == ["click"]


def test_keep_with_matching_license_is_not_flagged() -> None:
    p = plan(
        [_manual("click", "8.3.1", license="MIT")],
        [_syft("click", "8.3.1", license="MIT")],
    )
    assert p.keeps[0].license_changed is False
    assert p.keeps_with_license_change == []


def test_keep_with_scanner_license_missing_is_not_a_change() -> None:
    # "You say MIT, the scan says nothing" is not a change — the scanner
    # just has no opinion.
    p = plan(
        [_manual("foo", "1.0", license="MIT")],
        [_syft("foo", "1.0", license=None)],
    )
    assert p.keeps[0].license_changed is False
    assert p.keeps_with_license_change == []


def test_keep_with_manual_license_missing_is_not_a_change() -> None:
    p = plan(
        [_manual("foo", "1.0", license=None)],
        [_syft("foo", "1.0", license="MIT")],
    )
    assert p.keeps[0].license_changed is False


def test_keep_with_both_licenses_missing_is_not_a_change() -> None:
    p = plan([_manual("foo", "1.0")], [_syft("foo", "1.0")])
    assert p.keeps[0].license_changed is False


def test_bump_carries_license_change_flag() -> None:
    p = plan(
        [_manual("foo", "1.0.0", license="MIT")],
        [_syft("foo", "2.0.0", license="Apache-2.0")],
    )
    assert p.bumped[0].license_changed is True


def test_bump_with_matching_license_is_not_flagged() -> None:
    p = plan(
        [_manual("foo", "1.0.0", license="MIT")],
        [_syft("foo", "2.0.0", license="MIT")],
    )
    assert p.bumped[0].license_changed is False


def test_bump_with_scanner_license_missing_is_not_a_change() -> None:
    p = plan(
        [_manual("foo", "1.0.0", license="MIT")],
        [_syft("foo", "2.0.0", license=None)],
    )
    assert p.bumped[0].license_changed is False


def test_mixed_plan_partitions_every_bucket() -> None:
    manual = [
        _manual("agree", "1.0.0"),
        _manual("stale", "1.0.0"),
        _manual("vendored", "9.9.9"),
    ]
    syft = [
        _syft("agree", "1.0.0"),
        _syft("stale", "2.0.0"),
        _syft("brandnew", "0.1.0"),
    ]
    p = plan(manual, syft)
    assert [k.manual.name for k in p.keeps] == ["agree"]
    assert [b.manual.name for b in p.bumped] == ["stale"]
    assert [a.syft.name for a in p.added] == ["brandnew"]
    assert [a.manual.name for a in p.reviews] == ["vendored"]


def test_duplicate_manual_names_follow_reconciler_pairing() -> None:
    # Two manual entries for the same name: one matches Syft (and agrees,
    # so KEEP), the other spills to only_in_manual (REVIEW).
    p = plan(
        [_manual("foo", "1.0.0"), _manual("foo", "2.0.0")],
        [_syft("foo", "1.0.0")],
    )
    assert len(p.keeps) == 1
    assert [a.manual.version for a in p.reviews] == ["2.0.0"]
