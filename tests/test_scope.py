from sbom_curator.curate.scope import _canonical_variant, dedupe_scan, drop_by_name_prefix
from sbom_curator.parsers.model import Component


def _c(name: str, version: str = "1.0.0") -> Component:
    return Component(name=name, version=version, source="syft")


def test_no_prefixes_keeps_everything() -> None:
    comps = [_c("Hermes.Module.Viewport"), _c("attrs")]
    kept, dropped = drop_by_name_prefix(comps, [])
    assert [c.name for c in kept] == ["Hermes.Module.Viewport", "attrs"]
    assert dropped == []


def test_drops_components_matching_a_prefix() -> None:
    # The prefix is literal: "Hermes." catches "Hermes.Module.*" but not the
    # bare "Hermes" root assembly — pass "Hermes" (no dot) for that.
    comps = [_c("Hermes.Module.Viewport"), _c("Hermes"), _c("attrs"), _c("click")]
    kept, dropped = drop_by_name_prefix(comps, ["Hermes."])
    assert [c.name for c in kept] == ["Hermes", "attrs", "click"]
    assert [c.name for c in dropped] == ["Hermes.Module.Viewport"]


def test_prefix_match_is_case_insensitive() -> None:
    kept, dropped = drop_by_name_prefix([_c("HERMES.Core"), _c("attrs")], ["hermes."])
    assert [c.name for c in kept] == ["attrs"]
    assert [c.name for c in dropped] == ["HERMES.Core"]


def test_multiple_prefixes_are_all_applied() -> None:
    comps = [_c("Hermes.Core"), _c("Acme.Widget"), _c("attrs")]
    kept, dropped = drop_by_name_prefix(comps, ["Hermes.", "Acme."])
    assert [c.name for c in kept] == ["attrs"]
    assert {c.name for c in dropped} == {"Hermes.Core", "Acme.Widget"}


def test_blank_prefixes_are_ignored() -> None:
    kept, dropped = drop_by_name_prefix([_c("Hermes.Core"), _c("attrs")], [""])
    assert [c.name for c in kept] == ["Hermes.Core", "attrs"]
    assert dropped == []


# ----- dedupe_scan -----


def test_dedupe_keeps_distinct_packages_untouched() -> None:
    kept, dropped = dedupe_scan([_c("attrs", "25.4.0"), _c("click", "8.3.1")])
    assert [(c.name, c.version) for c in kept] == [("attrs", "25.4.0"), ("click", "8.3.1")]
    assert dropped == []


def test_dedupe_collapses_exact_duplicates() -> None:
    # Syft lists Infragistics once per referencing project — same everything.
    comps = [_c("Infragistics Ultimate", "22.2.20222.19") for _ in range(3)]
    kept, dropped = dedupe_scan(comps)
    assert [(c.name, c.version) for c in kept] == [("Infragistics Ultimate", "22.2.20222.19")]
    assert len(dropped) == 2


def test_dedupe_collapses_nuget_semver_and_assembly_version() -> None:
    comps = [
        _c("Microsoft.Extensions.Configuration", "9.0.0"),
        _c("Microsoft.Extensions.Configuration", "9.0.24.52809"),
    ]
    kept, dropped = dedupe_scan(comps)
    assert [c.version for c in kept] == ["9.0.0"]
    assert [c.version for c in dropped] == ["9.0.24.52809"]


def test_dedupe_collapses_local_build_segment_variant() -> None:
    comps = [
        _c("CommunityToolkit.Mvvm", "8.2.2"),
        _c("CommunityToolkit.Mvvm", "8.2.2.1+4c21e0294b"),
    ]
    kept, dropped = dedupe_scan(comps)
    assert [c.version for c in kept] == ["8.2.2"]
    assert [c.version for c in dropped] == ["8.2.2.1+4c21e0294b"]


def test_dedupe_collapses_pep440_equal_versions() -> None:
    kept, dropped = dedupe_scan([_c("DryIoc", "5.4.3"), _c("DryIoc", "5.4.3.0")])
    assert [c.version for c in kept] == ["5.4.3"]
    assert [c.version for c in dropped] == ["5.4.3.0"]


def test_dedupe_keeps_genuine_multi_version_installs() -> None:
    comps = [_c("Newtonsoft.Json", "12.0.3"), _c("Newtonsoft.Json", "13.0.3")]
    kept, dropped = dedupe_scan(comps)
    assert sorted(c.version for c in kept) == ["12.0.3", "13.0.3"]
    assert dropped == []


def test_dedupe_keeps_three_distinct_versions() -> None:
    comps = [_c("foo", "1.0.0"), _c("foo", "2.0.0"), _c("foo", "3.0.0")]
    kept, dropped = dedupe_scan(comps)
    assert len(kept) == 3
    assert dropped == []


def test_dedupe_keeps_unparseable_versions() -> None:
    # "rev23" / "rev24" don't parse as PEP 440 — can't tell if they're the
    # same package, so keep both.
    comps = [_c("HCryptLib", "rev23"), _c("HCryptLib", "rev24")]
    kept, dropped = dedupe_scan(comps)
    assert sorted(c.version for c in kept) == ["rev23", "rev24"]
    assert dropped == []


def test_dedupe_returns_kept_in_deterministic_order() -> None:
    comps = [_c("zlib", "1.3"), _c("attrs", "25.4.0"), _c("attrs", "25.4.0")]
    kept, _ = dedupe_scan(comps)
    assert [c.name for c in kept] == ["attrs", "zlib"]


def test_canonical_variant_returns_none_for_distinct_releases() -> None:
    assert _canonical_variant(["1.0.0", "2.0.0"]) is None


def test_canonical_variant_prefers_shortest_when_only_local_segments_differ() -> None:
    assert _canonical_variant(
        ["2.0.0-beta.13", "2.0.0-beta.13+461a942deb05"]
    ) == "2.0.0-beta.13"
