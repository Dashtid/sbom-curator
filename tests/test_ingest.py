from sbom_curator.curate.ingest import (
    AddAction,
    BumpAction,
    KeepAction,
    PreserveAction,
    plan,
)
from sbom_curator.parsers.model import Component


def _manual(name: str, version: str = "1.0.0", license: str | None = None) -> Component:
    return Component(name=name, version=version, source="manual", license=license)


def _syft(name: str, version: str = "1.0.0", license: str | None = None) -> Component:
    return Component(name=name, version=version, source="syft", license=license)


def test_empty_inputs_produce_empty_plan() -> None:
    p = plan([], [])
    assert p.bumps == []
    assert p.adds == []
    assert p.keeps == []
    assert p.preserves == []
    assert p.keeps_with_license_drift == []


def test_only_in_manual_becomes_preserve() -> None:
    p = plan([_manual("vendored-zlib", "1.3.1")], [])
    assert p.adds == []
    assert p.bumps == []
    assert p.keeps == []
    assert [a.manual.name for a in p.preserves] == ["vendored-zlib"]
    assert isinstance(p.preserves[0], PreserveAction)


def test_only_in_syft_becomes_add() -> None:
    p = plan([], [_syft("attrs", "25.4.0")])
    assert [a.syft.name for a in p.adds] == ["attrs"]
    assert isinstance(p.adds[0], AddAction)
    assert p.bumps == []
    assert p.keeps == []
    assert p.preserves == []


def test_matching_versions_become_keep() -> None:
    p = plan([_manual("rich", "13.0.0")], [_syft("rich", "13.0.0")])
    assert [a.manual.name for a in p.keeps] == ["rich"]
    assert isinstance(p.keeps[0], KeepAction)
    assert p.bumps == []
    assert p.adds == []
    assert p.preserves == []


def test_pep440_equivalent_versions_become_keep_not_bump() -> None:
    # 1.0 and 1.0.0 are the same release under PEP 440.
    p = plan([_manual("foo", "1.0")], [_syft("foo", "1.0.0")])
    assert len(p.keeps) == 1
    assert p.bumps == []


def test_differing_versions_become_bump() -> None:
    p = plan([_manual("packaging", "24.2")], [_syft("packaging", "25.0")])
    assert len(p.bumps) == 1
    assert isinstance(p.bumps[0], BumpAction)
    assert p.bumps[0].manual.version == "24.2"
    assert p.bumps[0].syft.version == "25.0"
    assert p.keeps == []


def test_keep_with_license_drift_is_flagged() -> None:
    p = plan(
        [_manual("click", "8.3.1", license="Apache-2.0")],
        [_syft("click", "8.3.1", license="BSD-3-Clause")],
    )
    assert len(p.keeps) == 1
    assert p.keeps[0].license_drift is True
    assert [k.manual.name for k in p.keeps_with_license_drift] == ["click"]


def test_keep_without_license_drift_is_not_flagged() -> None:
    p = plan(
        [_manual("click", "8.3.1", license="MIT")],
        [_syft("click", "8.3.1", license="MIT")],
    )
    assert p.keeps[0].license_drift is False
    assert p.keeps_with_license_drift == []


def test_keep_with_both_licenses_none_is_not_drift() -> None:
    p = plan([_manual("foo", "1.0")], [_syft("foo", "1.0")])
    assert p.keeps[0].license_drift is False


def test_keep_with_one_license_none_is_drift() -> None:
    p = plan(
        [_manual("foo", "1.0", license=None)],
        [_syft("foo", "1.0", license="MIT")],
    )
    assert p.keeps[0].license_drift is True


def test_bump_carries_license_drift_flag() -> None:
    p = plan(
        [_manual("foo", "1.0.0", license="MIT")],
        [_syft("foo", "2.0.0", license="Apache-2.0")],
    )
    assert p.bumps[0].license_drift is True


def test_bump_without_license_drift() -> None:
    p = plan(
        [_manual("foo", "1.0.0", license="MIT")],
        [_syft("foo", "2.0.0", license="MIT")],
    )
    assert p.bumps[0].license_drift is False


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
    assert [b.manual.name for b in p.bumps] == ["stale"]
    assert [a.syft.name for a in p.adds] == ["brandnew"]
    assert [a.manual.name for a in p.preserves] == ["vendored"]


def test_duplicate_manual_names_follow_reconciler_pairing() -> None:
    # Two manual entries for the same name: one matches Syft (and agrees,
    # so KEEP), the other spills to only_in_manual (PRESERVE).
    p = plan(
        [_manual("foo", "1.0.0"), _manual("foo", "2.0.0")],
        [_syft("foo", "1.0.0")],
    )
    assert len(p.keeps) == 1
    assert [a.manual.version for a in p.preserves] == ["2.0.0"]
