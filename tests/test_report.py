from sbom_curator.curate.ingest import (
    AddAction,
    BumpAction,
    EditPlan,
    KeepAction,
    PreserveAction,
)
from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import Reconciliation
from sbom_curator.report.markdown import render, render_ingest_plan


def _component(
    name: str,
    version: str = "1.0.0",
    *,
    source: str = "manual",
    license: str | None = None,
    purl: str | None = None,
) -> Component:
    return Component(
        name=name,
        version=version,
        source=source,  # type: ignore[arg-type]
        license=license,
        purl=purl,
    )


def test_render_includes_title_and_summary_with_zero_counts() -> None:
    empty = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[])
    out = render(empty, name="demo-1.0.0")

    assert out.startswith("# SBOM reconciliation report — demo-1.0.0\n")
    assert "## Summary" in out
    assert "- Only in manual: 0" in out
    assert "- Only in Syft: 0" in out
    assert "- In both, agree on version: 0" in out
    assert "- Version disagreements: 0" in out
    assert "- License disagreements: 0" in out


def test_render_renders_empty_buckets_as_none_placeholders() -> None:
    empty = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[])
    out = render(empty, name="x")

    assert "## Only in manual" in out
    assert "## Only in Syft" in out
    assert "## Version disagreements" in out
    assert "## License disagreements" in out
    assert out.count("(none)") == 4


def test_render_only_in_manual_table() -> None:
    rec = Reconciliation(
        only_in_manual=[
            _component("internal-codec", "1.0.0", license="MIT"),
            _component("vendored-zlib", "1.3.1", license="Zlib", purl="pkg:generic/zlib@1.3.1"),
        ],
        only_in_syft=[],
        in_both=[],
    )
    out = render(rec, name="x")

    assert "| internal-codec | 1.0.0 | MIT | _n/a_ |" in out
    assert "| vendored-zlib | 1.3.1 | Zlib | pkg:generic/zlib@1.3.1 |" in out


def test_render_version_disagreement_table() -> None:
    pair = (
        _component("pydantic", "2.0.0"),
        _component("pydantic", "2.12.5", source="syft"),
    )
    rec = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[pair])
    out = render(rec, name="x")

    assert "## Version disagreements" in out
    assert "| pydantic | 2.0.0 | 2.12.5 |" in out


def test_render_license_disagreement_table() -> None:
    pair = (
        _component("foo", "1.0", license="MIT"),
        _component("foo", "1.0", source="syft", license="Apache-2.0"),
    )
    rec = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[pair])
    out = render(rec, name="x")

    assert "## License disagreements" in out
    assert "| foo | MIT | Apache-2.0 |" in out


def test_render_escapes_pipe_characters_in_cells() -> None:
    rec = Reconciliation(
        only_in_manual=[_component("weird|name", license="A | B")],
        only_in_syft=[],
        in_both=[],
    )
    out = render(rec, name="x")

    assert "weird\\|name" in out
    assert "A \\| B" in out


def test_render_renders_empty_string_license_as_na() -> None:
    rec = Reconciliation(
        only_in_manual=[_component("foo", license="")],
        only_in_syft=[],
        in_both=[],
    )
    out = render(rec, name="x")

    assert "| foo | 1.0.0 | _n/a_ | _n/a_ |" in out


# ----- render_ingest_plan -----


def _empty_plan() -> EditPlan:
    return EditPlan(bumps=[], adds=[], keeps=[], preserves=[])


def test_render_ingest_plan_title_and_summary_with_zero_counts() -> None:
    out = render_ingest_plan(_empty_plan(), name="demo-1.0.0")

    assert out.startswith("# SBOM ingest plan — demo-1.0.0\n")
    assert "## Summary" in out
    assert "- Bumps: 0" in out
    assert "- Adds: 0" in out
    assert "- Keeps: 0 (manual matches Syft)" in out
    assert "- Preserves: 0" in out


def test_render_ingest_plan_empty_sections_render_as_none() -> None:
    out = render_ingest_plan(_empty_plan(), name="x")

    assert "## Bumps" in out
    assert "## Adds" in out
    assert "## Keeps with license drift" in out
    assert "## Preserves" in out
    assert out.count("(none)") == 4


def test_render_ingest_plan_bumps_table() -> None:
    manual = _component("cffi", "1.17.1", license="MIT")
    syft = _component("cffi", "2.0.0", source="syft", license="MIT")
    out = render_ingest_plan(
        EditPlan(bumps=[BumpAction(manual=manual, syft=syft)], adds=[], keeps=[], preserves=[]),
        name="x",
    )

    assert "| Name | Manual version | Syft version | License drift |" in out
    assert "| cffi | 1.17.1 | 2.0.0 | _no_ |" in out


def test_render_ingest_plan_bump_with_license_drift_flagged_yes() -> None:
    manual = _component("foo", "1.0.0", license="MIT")
    syft = _component("foo", "2.0.0", source="syft", license="Apache-2.0")
    out = render_ingest_plan(
        EditPlan(bumps=[BumpAction(manual=manual, syft=syft)], adds=[], keeps=[], preserves=[]),
        name="x",
    )

    assert "| foo | 1.0.0 | 2.0.0 | _yes_ |" in out


def test_render_ingest_plan_adds_table() -> None:
    syft = _component("attrs", "25.4.0", source="syft", license="MIT",
                      purl="pkg:pypi/attrs@25.4.0")
    out = render_ingest_plan(
        EditPlan(bumps=[], adds=[AddAction(syft=syft)], keeps=[], preserves=[]),
        name="x",
    )

    assert "| attrs | 25.4.0 | MIT | pkg:pypi/attrs@25.4.0 |" in out


def test_render_ingest_plan_keeps_with_license_drift_table() -> None:
    manual = _component("click", "8.3.1", license="Apache-2.0")
    syft = _component("click", "8.3.1", source="syft", license="BSD-3-Clause")
    out = render_ingest_plan(
        EditPlan(bumps=[], adds=[], keeps=[KeepAction(manual=manual, syft=syft)], preserves=[]),
        name="x",
    )

    assert "- Keeps: 1 (manual matches Syft; 1 with license drift)" in out
    assert "| Name | Version | Manual license | Syft license |" in out
    assert "| click | 8.3.1 | Apache-2.0 | BSD-3-Clause |" in out


def test_render_ingest_plan_quiet_keeps_counted_not_listed() -> None:
    manual = _component("rich", "14.2.0", license="MIT")
    syft = _component("rich", "14.2.0", source="syft", license="MIT")
    out = render_ingest_plan(
        EditPlan(bumps=[], adds=[], keeps=[KeepAction(manual=manual, syft=syft)], preserves=[]),
        name="x",
    )

    assert "- Keeps: 1 (manual matches Syft)" in out
    # A quiet keep is not enumerated; the license-drift section is (none).
    assert "rich" not in out


def test_render_ingest_plan_preserves_table() -> None:
    manual = _component("vendored-zlib", "1.3.1", license="Zlib")
    out = render_ingest_plan(
        EditPlan(bumps=[], adds=[], keeps=[], preserves=[PreserveAction(manual=manual)]),
        name="x",
    )

    assert "| Name | Version | License |" in out
    assert "| vendored-zlib | 1.3.1 | Zlib |" in out


def test_render_ingest_plan_escapes_pipe_characters() -> None:
    manual = _component("weird|name", "1.0", license="A | B")
    out = render_ingest_plan(
        EditPlan(bumps=[], adds=[], keeps=[], preserves=[PreserveAction(manual=manual)]),
        name="x",
    )

    assert "weird\\|name" in out
    assert "A \\| B" in out
