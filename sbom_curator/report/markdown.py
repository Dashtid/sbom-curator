"""Render a Reconciliation as a Markdown triage report."""

from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import Reconciliation


def render(reconciliation: Reconciliation, *, name: str) -> str:
    """Format a reconciliation as a Markdown triage report.

    Layout is intentionally section-stable: empty buckets render as a
    section with "(none)" rather than being omitted, so the report's diff
    is meaningful run-to-run when buckets fluctuate.
    """
    agreed = len(reconciliation.in_both) - len(reconciliation.version_mismatches)
    lines: list[str] = []
    lines.append(f"# SBOM reconciliation report — {name}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Only in manual: {len(reconciliation.only_in_manual)}")
    lines.append(f"- Only in Syft: {len(reconciliation.only_in_syft)}")
    lines.append(f"- In both, agree on version: {agreed}")
    lines.append(f"- Version disagreements: {len(reconciliation.version_mismatches)}")
    lines.append(f"- License disagreements: {len(reconciliation.license_mismatches)}")
    lines.append("")
    lines.extend(_render_single_section("Only in manual", reconciliation.only_in_manual))
    lines.extend(_render_single_section("Only in Syft", reconciliation.only_in_syft))
    lines.extend(_render_pair_section("Version disagreements", reconciliation.version_mismatches))
    lines.extend(_render_pair_section("License disagreements", reconciliation.license_mismatches))
    return "\n".join(lines) + "\n"


def _render_single_section(heading: str, components: list[Component]) -> list[str]:
    out = [f"## {heading}", ""]
    if not components:
        out.append("(none)")
        out.append("")
        return out
    out.append("| Name | Version | License | PURL |")
    out.append("| --- | --- | --- | --- |")
    for c in components:
        out.append(
            f"| {_cell(c.name)} | {_cell(c.version)} | {_cell(c.license)} | {_cell(c.purl)} |"
        )
    out.append("")
    return out


def _render_pair_section(
    heading: str, pairs: list[tuple[Component, Component]]
) -> list[str]:
    out = [f"## {heading}", ""]
    if not pairs:
        out.append("(none)")
        out.append("")
        return out
    out.append("| Name | Manual | Syft |")
    out.append("| --- | --- | --- |")
    for manual, syft in pairs:
        left: str | None
        right: str | None
        if heading.startswith("Version"):
            left, right = manual.version, syft.version
        else:
            left, right = manual.license, syft.license
        out.append(f"| {_cell(manual.name)} | {_cell(left)} | {_cell(right)} |")
    out.append("")
    return out


def _cell(value: str | None) -> str:
    if value is None or value == "":
        return "_n/a_"
    return value.replace("|", "\\|")
