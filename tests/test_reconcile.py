from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import reconcile


def _manual(name: str, version: str = "1.0.0", license: str | None = None) -> Component:
    return Component(name=name, version=version, source="manual", license=license)


def _syft(name: str, version: str = "1.0.0", license: str | None = None) -> Component:
    return Component(name=name, version=version, source="syft", license=license)


def test_empty_inputs_produce_empty_reconciliation() -> None:
    result = reconcile([], [])
    assert result.only_in_manual == []
    assert result.only_in_syft == []
    assert result.in_both == []


def test_only_in_manual_when_syft_lacks_component() -> None:
    result = reconcile([_manual("zlib")], [])
    assert [c.name for c in result.only_in_manual] == ["zlib"]
    assert result.only_in_syft == []
    assert result.in_both == []


def test_only_in_syft_when_manual_lacks_component() -> None:
    result = reconcile([], [_syft("attrs")])
    assert result.only_in_manual == []
    assert [c.name for c in result.only_in_syft] == ["attrs"]
    assert result.in_both == []


def test_in_both_when_versions_agree() -> None:
    result = reconcile([_manual("rich", "13.0.0")], [_syft("rich", "13.0.0")])
    assert result.only_in_manual == []
    assert result.only_in_syft == []
    assert len(result.in_both) == 1
    assert result.version_mismatches == []


def test_in_both_with_version_mismatch() -> None:
    result = reconcile([_manual("pydantic", "2.0.0")], [_syft("pydantic", "2.12.5")])
    assert len(result.in_both) == 1
    mismatches = result.version_mismatches
    assert len(mismatches) == 1
    manual, syft = mismatches[0]
    assert manual.version == "2.0.0"
    assert syft.version == "2.12.5"


def test_in_both_with_license_mismatch() -> None:
    result = reconcile(
        [_manual("foo", license="MIT")],
        [_syft("foo", license="Apache-2.0")],
    )
    assert len(result.license_mismatches) == 1


def test_license_mismatches_treats_one_none_as_disagreement() -> None:
    result = reconcile(
        [_manual("foo", license=None)],
        [_syft("foo", license="MIT")],
    )
    assert len(result.license_mismatches) == 1


def test_license_mismatches_treats_both_none_as_agreement() -> None:
    result = reconcile([_manual("foo", license=None)], [_syft("foo", license=None)])
    assert result.license_mismatches == []


def test_name_match_is_case_insensitive() -> None:
    result = reconcile([_manual("Newtonsoft.Json")], [_syft("newtonsoft.json")])
    assert len(result.in_both) == 1


def test_buckets_are_sorted_by_lowercase_name() -> None:
    result = reconcile(
        [_manual("zeta"), _manual("alpha"), _manual("Beta")],
        [],
    )
    assert [c.name for c in result.only_in_manual] == ["alpha", "Beta", "zeta"]


def test_duplicate_names_in_manual_pair_one_to_one_with_syft() -> None:
    # Two manual entries for the same name: one matches a Syft entry, one
    # spills into only_in_manual.
    result = reconcile(
        [_manual("foo", "1.0.0"), _manual("foo", "2.0.0")],
        [_syft("foo", "1.0.0")],
    )
    assert len(result.in_both) == 1
    assert [c.version for c in result.only_in_manual] == ["2.0.0"]
