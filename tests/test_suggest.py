from sbom_curator.curate.suggest import (
    CoversPrefixSuggestion,
    suggest_covers_prefixes,
)
from sbom_curator.parsers.model import Component


def _added(*names: str) -> list[Component]:
    return [Component(name=n, version="1.0.0", source="syft") for n in names]


def test_no_suggestions_when_added_is_empty() -> None:
    assert suggest_covers_prefixes([], []) == []


def test_no_suggestions_when_no_cluster_meets_threshold() -> None:
    # Two `Vortice.*` is below the default threshold of 3.
    assert suggest_covers_prefixes(_added("Vortice.DXGI", "Vortice.Direct3D11"), []) == []


def test_proposes_a_prefix_for_a_cluster_at_threshold() -> None:
    suggestions = suggest_covers_prefixes(
        _added("Vortice.DXGI", "Vortice.Direct3D11", "Vortice.DirectX"), []
    )
    assert len(suggestions) == 1
    assert suggestions[0].prefix == "Vortice."
    assert suggestions[0].packages == ("Vortice.DXGI", "Vortice.Direct3D11", "Vortice.DirectX")


def test_skips_a_prefix_already_declared_in_an_existing_covers_prefix() -> None:
    suggestions = suggest_covers_prefixes(
        _added("Vortice.DXGI", "Vortice.Direct3D11", "Vortice.DirectX"),
        ["Vortice."],
    )
    assert suggestions == []


def test_existing_prefix_match_is_case_insensitive() -> None:
    suggestions = suggest_covers_prefixes(
        _added("Vortice.DXGI", "Vortice.Direct3D11", "Vortice.DirectX"),
        ["vortice."],
    )
    assert suggestions == []


def test_prefers_the_most_specific_prefix_when_two_capture_the_same_set() -> None:
    # All five packages share both `Microsoft.` and `Microsoft.Extensions.`
    # exactly — propose the more specific one, not the broad `Microsoft.`.
    suggestions = suggest_covers_prefixes(
        _added(
            "Microsoft.Extensions.Configuration",
            "Microsoft.Extensions.Hosting",
            "Microsoft.Extensions.Logging",
            "Microsoft.Extensions.Options",
            "Microsoft.Extensions.Primitives",
        ),
        [],
    )
    assert [s.prefix for s in suggestions] == ["Microsoft.Extensions."]


def test_proposes_multiple_distinct_clusters_ordered_by_size() -> None:
    suggestions = suggest_covers_prefixes(
        _added(
            "Vortice.A", "Vortice.B", "Vortice.C",
            "Infragistics.WPF.Calendar", "Infragistics.WPF.Charts",
            "Infragistics.WPF.DataGrids", "Infragistics.WPF.DataVisualization",
        ),
        [],
    )
    # Infragistics.WPF. has 4, Vortice. has 3 -> larger first.
    assert [s.prefix for s in suggestions] == ["Infragistics.WPF.", "Vortice."]


def test_respects_max_suggestions_cap() -> None:
    added = []
    for fam in ("A", "B", "C", "D", "E", "F"):
        added.extend(_added(f"{fam}.x", f"{fam}.y", f"{fam}.z"))
    suggestions = suggest_covers_prefixes(added, [], max_suggestions=3)
    assert len(suggestions) == 3


def test_threshold_is_configurable() -> None:
    suggestions = suggest_covers_prefixes(
        _added("Vortice.DXGI", "Vortice.Direct3D11"),
        [],
        threshold=2,
    )
    assert len(suggestions) == 1


def test_names_without_a_dot_are_ignored() -> None:
    suggestions = suggest_covers_prefixes(_added("attrs", "click", "rich"), [])
    assert suggestions == []


def test_blank_existing_prefixes_are_ignored() -> None:
    suggestions = suggest_covers_prefixes(
        _added("Vortice.DXGI", "Vortice.Direct3D11", "Vortice.DirectX"),
        ["", "  "],
    )
    assert [s.prefix for s in suggestions] == ["Vortice."]


def test_dataclass_is_frozen() -> None:
    s = CoversPrefixSuggestion(prefix="X.", packages=("X.A",))
    assert s.prefix == "X."
    assert s.packages == ("X.A",)
