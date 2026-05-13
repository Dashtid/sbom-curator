from sbom_curator.curate.ingest import (
    AddAction,
    BumpAction,
    CoveredAction,
    EditPlan,
    KeepAction,
    ReviewAction,
)
from sbom_curator.curate.suggest import CoversPrefixSuggestion
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
    assert "## Covered by a family entry" in out
    assert "## Suggested annotations" in out
    assert out.count("(none)") == 6


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


# ----- render_ingest_plan (change report) -----


def _empty_plan() -> EditPlan:
    return EditPlan(added=[], bumped=[], reviews=[], keeps=[])


def test_render_change_report_title_and_summary_with_zero_counts() -> None:
    out = render_ingest_plan(_empty_plan(), name="demo-1.0.0")

    assert out.startswith("# SBOM change report — demo-1.0.0\n")
    assert "## Summary" in out
    assert "- Added: 0" in out
    assert "- Bumped: 0" in out
    assert "- Only in your SBOM: 0" in out
    assert "- Unchanged: 0" in out


def test_render_change_report_empty_sections_render_as_none() -> None:
    out = render_ingest_plan(_empty_plan(), name="x")

    assert "## Added" in out
    assert "## Bumped" in out
    assert "## Only in your SBOM" in out
    assert "## License changed (otherwise unchanged)" in out
    assert "## Covered by a family entry" in out
    assert "## Suggested annotations" in out
    assert out.count("(none)") == 6


def test_render_change_report_added_table() -> None:
    syft = _component("attrs", "25.4.0", source="syft", license="MIT",
                      purl="pkg:pypi/attrs@25.4.0")
    out = render_ingest_plan(
        EditPlan(added=[AddAction(syft=syft)], bumped=[], reviews=[], keeps=[]),
        name="x",
    )

    assert "| attrs | 25.4.0 | MIT | pkg:pypi/attrs@25.4.0 |" in out


def test_render_change_report_bumped_table() -> None:
    manual = _component("cffi", "1.17.1", license="MIT")
    syft = _component("cffi", "2.0.0", source="syft", license="MIT")
    out = render_ingest_plan(
        EditPlan(added=[], bumped=[BumpAction(manual=manual, syft=syft)], reviews=[], keeps=[]),
        name="x",
    )

    assert "| Name | Your version | Scan version | License change |" in out
    assert "| cffi | 1.17.1 | 2.0.0 | _no_ |" in out


def test_render_change_report_bump_with_license_change_flagged_yes() -> None:
    manual = _component("foo", "1.0.0", license="MIT")
    syft = _component("foo", "2.0.0", source="syft", license="Apache-2.0")
    out = render_ingest_plan(
        EditPlan(added=[], bumped=[BumpAction(manual=manual, syft=syft)], reviews=[], keeps=[]),
        name="x",
    )

    assert "| foo | 1.0.0 | 2.0.0 | _yes_ |" in out


def test_render_change_report_reviews_table() -> None:
    manual = _component("vendored-zlib", "1.3.1", license="Zlib")
    out = render_ingest_plan(
        EditPlan(added=[], bumped=[], reviews=[ReviewAction(manual=manual)], keeps=[]),
        name="x",
    )

    assert "## Only in your SBOM" in out
    assert "| Name | Version | License |" in out
    assert "| vendored-zlib | 1.3.1 | Zlib |" in out


def test_render_change_report_license_changed_table() -> None:
    manual = _component("click", "8.3.1", license="Apache-2.0")
    syft = _component("click", "8.3.1", source="syft", license="BSD-3-Clause")
    out = render_ingest_plan(
        EditPlan(added=[], bumped=[], reviews=[], keeps=[KeepAction(manual=manual, syft=syft)]),
        name="x",
    )

    assert "- Unchanged: 1 (1 with a license change)" in out
    assert "| Name | Version | Your license | Scan license |" in out
    assert "| click | 8.3.1 | Apache-2.0 | BSD-3-Clause |" in out


def test_render_change_report_quiet_keep_counted_not_listed() -> None:
    manual = _component("rich", "14.2.0", license="MIT")
    syft = _component("rich", "14.2.0", source="syft", license="MIT")
    out = render_ingest_plan(
        EditPlan(added=[], bumped=[], reviews=[], keeps=[KeepAction(manual=manual, syft=syft)]),
        name="x",
    )

    assert "- Unchanged: 1\n" in out  # no "(... license change)" suffix
    # A quiet keep is not enumerated; the license-changed section is (none).
    assert "rich" not in out


def test_render_change_report_keep_with_missing_scan_license_is_not_a_change() -> None:
    manual = _component("rich", "14.2.0", license="MIT")
    syft = _component("rich", "14.2.0", source="syft", license=None)
    out = render_ingest_plan(
        EditPlan(added=[], bumped=[], reviews=[], keeps=[KeepAction(manual=manual, syft=syft)]),
        name="x",
    )

    assert "- Unchanged: 1\n" in out
    assert "rich" not in out


def test_render_change_report_escapes_pipe_characters() -> None:
    manual = _component("weird|name", "1.0", license="A | B")
    out = render_ingest_plan(
        EditPlan(added=[], bumped=[], reviews=[ReviewAction(manual=manual)], keeps=[]),
        name="x",
    )

    assert "weird\\|name" in out
    assert "A \\| B" in out


# ----- Covered by a family entry -----


def test_render_change_report_covered_section() -> None:
    manual = _component("Vortice", "3.2.0")
    sub_a = _component("Vortice.DXGI", "3.2.0", source="syft")
    sub_b = _component("Vortice.Direct3D11", "3.2.0", source="syft")
    out = render_ingest_plan(
        EditPlan(
            added=[],
            bumped=[],
            reviews=[],
            keeps=[],
            covered=[
                CoveredAction(manual=manual, syft=sub_a),
                CoveredAction(manual=manual, syft=sub_b),
            ],
        ),
        name="x",
    )

    assert "- Covered by family entries: 2" in out
    assert "## Covered by a family entry" in out
    assert "| Name | Version | Covered by (your entry) |" in out
    assert "| Vortice.DXGI | 3.2.0 | Vortice |" in out
    assert "| Vortice.Direct3D11 | 3.2.0 | Vortice |" in out


def test_render_reconcile_report_covered_section() -> None:
    manual = _component("Vortice", "3.2.0")
    sub = _component("Vortice.DXGI", "3.2.0", source="syft")
    rec = Reconciliation(
        only_in_manual=[], only_in_syft=[], in_both=[], covered=[(manual, sub)]
    )
    out = render(rec, name="x")

    assert "- Covered by family entries: 1" in out
    assert "## Covered by a family entry" in out
    assert "| Vortice.DXGI | 3.2.0 | Vortice |" in out


# ----- Suggested annotations -----


def test_render_change_report_suggestions_section() -> None:
    suggestions = (
        CoversPrefixSuggestion(
            prefix="Vortice.",
            packages=("Vortice.Direct3D11", "Vortice.DXGI", "Vortice.DirectX"),
        ),
    )
    out = render_ingest_plan(EditPlan(added=[], bumped=[], reviews=[], keeps=[]),
                             name="x", suggestions=suggestions)

    assert "- Suggested annotations: 1" in out
    assert "## Suggested annotations" in out
    assert "**`Vortice.`**" in out
    assert "covers-prefix: Vortice." in out
    assert "`Vortice.Direct3D11`" in out


def test_render_reconcile_report_suggestions_section() -> None:
    suggestions = (
        CoversPrefixSuggestion(prefix="X.", packages=("X.a", "X.b", "X.c")),
    )
    rec = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[])
    out = render(rec, name="x", suggestions=suggestions)

    assert "- Suggested annotations: 1" in out
    assert "## Suggested annotations" in out
    assert "**`X.`**" in out


def test_render_suggestions_truncates_long_package_lists() -> None:
    long_list = tuple(f"X.pkg{i}" for i in range(20))
    suggestions = (CoversPrefixSuggestion(prefix="X.", packages=long_list),)
    out = render_ingest_plan(EditPlan(added=[], bumped=[], reviews=[], keeps=[]),
                             name="x", suggestions=suggestions)

    # First five packages listed; remainder summarised.
    assert "`X.pkg0`" in out
    assert "`X.pkg4`" in out
    assert "and 15 more" in out
