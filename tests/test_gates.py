import click
import pytest

from sbom_curator.cli import (
    _INGEST_GATES,
    _RECONCILE_GATES,
    _ingest_gate_hits,
    _parse_gates,
    _reconcile_gate_hits,
)
from sbom_curator.curate.ingest import (
    AddAction,
    BumpAction,
    EditPlan,
    KeepAction,
    ReviewAction,
)
from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import Reconciliation


def _c(name: str, version: str = "1.0.0", source: str = "manual",
       license: str | None = None) -> Component:
    return Component(name=name, version=version, source=source, license=license)  # type: ignore[arg-type]


# ----- _parse_gates -----


def test_parse_gates_returns_empty_set_for_none_or_blank() -> None:
    assert _parse_gates(None, _INGEST_GATES) == set()
    assert _parse_gates("", _INGEST_GATES) == set()
    assert _parse_gates(" , ", _INGEST_GATES) == set()


def test_parse_gates_splits_and_lowercases() -> None:
    assert _parse_gates("Added, Bumped", _INGEST_GATES) == {"added", "bumped"}


def test_parse_gates_raises_on_unknown_value() -> None:
    with pytest.raises(click.BadParameter):
        _parse_gates("added,bogus", _INGEST_GATES)


# ----- _ingest_gate_hits -----


def _empty_plan() -> EditPlan:
    return EditPlan(added=[], bumped=[], reviews=[], keeps=[])


def test_ingest_gate_hits_returns_empty_when_no_gates() -> None:
    plan = EditPlan(
        added=[AddAction(syft=_c("x", source="syft"))],
        bumped=[BumpAction(manual=_c("y"), syft=_c("y", "2.0.0", source="syft"))],
        reviews=[ReviewAction(manual=_c("z"))],
        keeps=[],
    )
    assert _ingest_gate_hits(plan, set()) == set()


def test_ingest_gate_hits_fires_on_added() -> None:
    plan = EditPlan(
        added=[AddAction(syft=_c("x", source="syft"))],
        bumped=[], reviews=[], keeps=[],
    )
    assert _ingest_gate_hits(plan, {"added"}) == {"added"}


def test_ingest_gate_hits_skips_empty_bucket_even_when_gated() -> None:
    assert _ingest_gate_hits(_empty_plan(), {"added", "bumped", "review"}) == set()


def test_ingest_gate_hits_fires_on_bumped_and_review() -> None:
    plan = EditPlan(
        added=[],
        bumped=[BumpAction(manual=_c("y"), syft=_c("y", "2.0.0", source="syft"))],
        reviews=[ReviewAction(manual=_c("z"))],
        keeps=[],
    )
    assert _ingest_gate_hits(plan, {"bumped", "review"}) == {"bumped", "review"}


def test_ingest_gate_hits_license_fires_on_keep_with_license_change() -> None:
    manual = _c("foo", license="MIT")
    syft = _c("foo", source="syft", license="Apache-2.0")
    plan = EditPlan(
        added=[], bumped=[], reviews=[],
        keeps=[KeepAction(manual=manual, syft=syft)],
    )
    assert _ingest_gate_hits(plan, {"license"}) == {"license"}


def test_ingest_gate_hits_license_fires_on_bump_with_license_change() -> None:
    manual = _c("foo", license="MIT")
    syft = _c("foo", "2.0.0", source="syft", license="Apache-2.0")
    plan = EditPlan(
        added=[], bumped=[BumpAction(manual=manual, syft=syft)], reviews=[], keeps=[],
    )
    assert _ingest_gate_hits(plan, {"license"}) == {"license"}


def test_ingest_gate_hits_license_quiet_when_no_change() -> None:
    plan = EditPlan(
        added=[], bumped=[], reviews=[],
        keeps=[KeepAction(manual=_c("foo", license="MIT"),
                          syft=_c("foo", source="syft", license="MIT"))],
    )
    assert _ingest_gate_hits(plan, {"license"}) == set()


# ----- _reconcile_gate_hits -----


def test_reconcile_gate_hits_returns_empty_when_no_gates() -> None:
    rec = Reconciliation(
        only_in_manual=[_c("a")], only_in_syft=[_c("b", source="syft")], in_both=[],
    )
    assert _reconcile_gate_hits(rec, set()) == set()


def test_reconcile_gate_hits_fires_on_each_bucket() -> None:
    manual = _c("foo", license="MIT")
    syft = _c("foo", "2.0.0", source="syft", license="Apache-2.0")
    rec = Reconciliation(
        only_in_manual=[_c("stale")],
        only_in_syft=[_c("new", source="syft")],
        in_both=[(manual, syft)],
    )
    hit = _reconcile_gate_hits(rec, set(_RECONCILE_GATES))
    assert hit == {"only-in-manual", "only-in-syft", "version", "license"}


def test_reconcile_gate_hits_skips_empty_buckets() -> None:
    rec = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[])
    assert _reconcile_gate_hits(rec, set(_RECONCILE_GATES)) == set()
