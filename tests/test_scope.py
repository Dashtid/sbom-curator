from sbom_curator.curate.scope import drop_by_name_prefix
from sbom_curator.parsers.model import Component


def _c(name: str) -> Component:
    return Component(name=name, version="1.0.0", source="syft")


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
