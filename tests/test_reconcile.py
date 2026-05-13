from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import _normalize_purl, reconcile


def _manual(
    name: str, version: str = "1.0.0", license: str | None = None, purl: str | None = None
) -> Component:
    return Component(name=name, version=version, source="manual", license=license, purl=purl)


def _syft(
    name: str, version: str = "1.0.0", license: str | None = None, purl: str | None = None
) -> Component:
    return Component(name=name, version=version, source="syft", license=license, purl=purl)


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


def test_duplicate_names_consume_each_manual_entry_at_most_once() -> None:
    result = reconcile(
        [_manual("foo", "1.0.0"), _manual("foo", "2.0.0")],
        [_syft("foo", "1.0.0"), _syft("foo", "2.0.0")],
    )
    assert len(result.in_both) == 2
    assert result.only_in_manual == []
    assert result.only_in_syft == []


# ----- PURL-aware matching -----


def test_purl_match_links_components_with_different_names() -> None:
    # The curator recorded the canonical PURL but a coarser display name.
    result = reconcile(
        [_manual("CommunityToolkit", "8.2.2", purl="pkg:nuget/CommunityToolkit.Mvvm@8.2.2")],
        [_syft("CommunityToolkit.Mvvm", "8.2.2", purl="pkg:nuget/CommunityToolkit.Mvvm@8.2.2")],
    )
    assert result.only_in_manual == []
    assert result.only_in_syft == []
    assert len(result.in_both) == 1
    assert result.version_mismatches == []


def test_purl_match_ignores_version_qualifiers_and_subpath() -> None:
    # Manual `8.2.2` (NuGet) paired with scan `8.2.2.1+sha` (assembly
    # revision of the same release) via PURL. Versions are still
    # compared on the pair; the NuGet semver <-> .NET assembly-revision
    # rule (versions_equal) reads them as agreement, so no bump.
    result = reconcile(
        [_manual("ToolkitMvvm", "8.2.2", purl="pkg:nuget/CommunityToolkit.Mvvm@8.2.2")],
        [
            _syft(
                "CommunityToolkit.Mvvm",
                "8.2.2.1+4c21e0294b",
                purl="pkg:nuget/CommunityToolkit.Mvvm@8.2.2.1%2B4c21e0294b?foo=bar#sub",
            )
        ],
    )
    assert len(result.in_both) == 1
    assert result.version_mismatches == []


def test_purl_match_falls_back_to_name_when_one_side_lacks_a_purl() -> None:
    # Scan has no PURL: only the lowercased-name path can match it.
    result = reconcile(
        [_manual("attrs", "25.4.0", purl="pkg:pypi/attrs@25.4.0")],
        [_syft("attrs", "25.4.0")],
    )
    assert len(result.in_both) == 1
    result2 = reconcile(
        [_manual("attrs", "25.4.0", purl="pkg:pypi/attrs@25.4.0")],
        [_syft("different-name", "1.0.0")],
    )
    assert [c.name for c in result2.only_in_manual] == ["attrs"]
    assert [c.name for c in result2.only_in_syft] == ["different-name"]


def test_purl_match_takes_precedence_over_a_name_match_to_another_entry() -> None:
    # Scan entry is named "bar" but its PURL says it's "foo": pair it with
    # the manual "foo", leaving the manual "bar" unmatched.
    result = reconcile(
        [
            _manual("foo", "1.0.0", purl="pkg:nuget/foo@1.0.0"),
            _manual("bar", "1.0.0", purl="pkg:nuget/bar@1.0.0"),
        ],
        [_syft("bar", "2.0.0", purl="pkg:nuget/foo@2.0.0")],
    )
    matched_manual = result.in_both[0][0]
    assert matched_manual.name == "foo"
    assert [c.name for c in result.only_in_manual] == ["bar"]
    assert result.only_in_syft == []


def test_purl_and_name_pointing_at_the_same_entry_match_once() -> None:
    result = reconcile(
        [_manual("rich", "14.2.0", purl="pkg:pypi/rich@14.2.0")],
        [_syft("rich", "14.2.0", purl="pkg:pypi/rich@14.2.0")],
    )
    assert len(result.in_both) == 1
    assert result.only_in_manual == []
    assert result.only_in_syft == []


def test_normalize_purl_strips_version_qualifiers_subpath_and_lowercases() -> None:
    assert _normalize_purl(
        "pkg:nuget/Infragistics%20Ultimate@22.2.20222.19?arch=x64#bin"
    ) == "pkg:nuget/infragistics ultimate"


def test_normalize_purl_returns_none_for_missing_or_non_purl_strings() -> None:
    assert _normalize_purl(None) is None
    assert _normalize_purl("") is None
    assert _normalize_purl("not-a-purl") is None


# ----- prefix coverage -----


def _umbrella(name: str, version: str = "1.0.0", *, covers: tuple[str, ...]) -> Component:
    return Component(
        name=name, version=version, source="manual", covers_prefixes=covers
    )


def test_covers_prefix_absorbs_matching_scan_entries_into_covered_bucket() -> None:
    result = reconcile(
        [_umbrella("Vortice", "3.2.0", covers=("Vortice.",))],
        [
            _syft("Vortice.Direct3D11", "3.2.0"),
            _syft("Vortice.DXGI", "3.2.0"),
            _syft("attrs", "25.4.0"),
        ],
    )
    covered_names = [s.name for _m, s in result.covered]
    assert covered_names == ["Vortice.Direct3D11", "Vortice.DXGI"]
    # The umbrella covers but isn't consumed; it doesn't leak into only_in_manual.
    assert result.only_in_manual == []
    # Unrelated scan entries still flow to only_in_syft.
    assert [c.name for c in result.only_in_syft] == ["attrs"]


def test_covers_prefix_match_is_case_insensitive() -> None:
    result = reconcile(
        [_umbrella("Vortice", covers=("Vortice.",))],
        [_syft("VORTICE.Direct3D11")],
    )
    assert len(result.covered) == 1


def test_covers_prefix_longest_prefix_wins() -> None:
    # "Vortice.WPF." is more specific than "Vortice." — it should claim
    # "Vortice.WPF.Foo" even though both prefixes match.
    result = reconcile(
        [
            _umbrella("Vortice", covers=("Vortice.",)),
            _umbrella("Vortice WPF", covers=("Vortice.WPF.",)),
        ],
        [_syft("Vortice.WPF.Foo")],
    )
    assert len(result.covered) == 1
    assert result.covered[0][0].name == "Vortice WPF"


def test_covers_prefix_does_not_absorb_entries_already_matched_by_name() -> None:
    # The scan entry "Vortice" name-matches the manual "Vortice" exactly;
    # coverage only runs on what's still unmatched.
    result = reconcile(
        [_umbrella("Vortice", "3.2.0", covers=("Vortice.",))],
        [_syft("Vortice", "3.2.0")],
    )
    assert len(result.in_both) == 1
    assert result.covered == []


def test_covers_prefix_does_not_absorb_entries_matched_by_purl() -> None:
    # PURL match wins over coverage too.
    result = reconcile(
        [
            Component(
                name="Vortice",
                version="3.2.0",
                source="manual",
                purl="pkg:nuget/Vortice.DXGI@3.2.0",
                covers_prefixes=("Vortice.",),
            )
        ],
        [_syft("Vortice.DXGI", "3.2.0", purl="pkg:nuget/Vortice.DXGI@3.2.0")],
    )
    assert len(result.in_both) == 1
    assert result.covered == []


def test_umbrella_with_no_matching_scan_entries_stays_in_only_in_manual() -> None:
    # "I declared coverage but the family isn't installed" — visible to
    # the curator, not absorbed silently.
    result = reconcile(
        [_umbrella("Vortice", covers=("Vortice.",))],
        [_syft("attrs", "25.4.0")],
    )
    assert [c.name for c in result.only_in_manual] == ["Vortice"]
    assert result.covered == []


def test_blank_covers_prefix_is_ignored() -> None:
    # A blank prefix would match everything — guard against accidental
    # `covers-prefix:` (empty value) absorbing the world.
    result = reconcile(
        [_umbrella("Vortice", covers=("",))],
        [_syft("attrs", "25.4.0")],
    )
    assert result.covered == []
    assert [c.name for c in result.only_in_syft] == ["attrs"]
