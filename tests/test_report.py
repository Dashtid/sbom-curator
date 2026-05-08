from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import Reconciliation
from sbom_curator.report.markdown import render


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
