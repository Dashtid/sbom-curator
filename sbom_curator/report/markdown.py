"""Render reconcile and ingest results as Markdown.

Two entry points:

- :func:`render` — a reconciliation as a four-bucket triage report.
- :func:`render_ingest_plan` — an edit plan as a curator TODO list
  (bumps, adds, keeps-with-license-drift, preserves).

Both layouts are section-stable: empty sections render as ``(none)``
rather than being omitted, so a report's diff is meaningful run-to-run
when buckets fluctuate.
"""

from sbom_curator.curate.ingest import (
    AddAction,
    BumpAction,
    EditPlan,
    KeepAction,
    PreserveAction,
)
from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import Reconciliation


def render(reconciliation: Reconciliation, *, name: str) -> str:
    """Format a reconciliation as a Markdown triage report."""
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


def render_ingest_plan(edit_plan: EditPlan, *, name: str) -> str:
    """Format an edit plan as a Markdown curator TODO list.

    Quiet keeps (manual already matches Syft, no license drift) are
    counted in the summary but not enumerated — listing every
    no-action row would drown the actionable sections. Keeps that *do*
    show license drift get their own section.
    """
    drift = edit_plan.keeps_with_license_drift
    keep_note = f"; {len(drift)} with license drift" if drift else ""
    lines: list[str] = []
    lines.append(f"# SBOM ingest plan — {name}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Bumps: {len(edit_plan.bumps)} (manual SBOM has older versions)")
    lines.append(f"- Adds: {len(edit_plan.adds)} (Syft saw, manual does not list)")
    lines.append(f"- Keeps: {len(edit_plan.keeps)} (manual matches Syft{keep_note})")
    lines.append(f"- Preserves: {len(edit_plan.preserves)} (manual lists; Syft can't see)")
    lines.append("")
    lines.extend(_render_bumps(edit_plan.bumps))
    lines.extend(_render_adds(edit_plan.adds))
    lines.extend(_render_keep_drifts(drift))
    lines.extend(_render_preserves(edit_plan.preserves))
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


def _render_bumps(bumps: list[BumpAction]) -> list[str]:
    out = ["## Bumps", ""]
    if not bumps:
        out += ["(none)", ""]
        return out
    out.append("| Name | Manual version | Syft version | License drift |")
    out.append("| --- | --- | --- | --- |")
    for b in bumps:
        flag = "_yes_" if b.license_drift else "_no_"
        out.append(_row(_cell(b.manual.name), _cell(b.manual.version), _cell(b.syft.version), flag))
    out.append("")
    return out


def _render_adds(adds: list[AddAction]) -> list[str]:
    out = ["## Adds", ""]
    if not adds:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | License | PURL |")
    out.append("| --- | --- | --- | --- |")
    for a in adds:
        c = a.syft
        out.append(_row(_cell(c.name), _cell(c.version), _cell(c.license), _cell(c.purl)))
    out.append("")
    return out


def _render_keep_drifts(keeps: list[KeepAction]) -> list[str]:
    out = ["## Keeps with license drift", ""]
    if not keeps:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | Manual license | Syft license |")
    out.append("| --- | --- | --- | --- |")
    for k in keeps:
        out.append(
            _row(_cell(k.manual.name), _cell(k.manual.version),
                 _cell(k.manual.license), _cell(k.syft.license))
        )
    out.append("")
    return out


def _render_preserves(preserves: list[PreserveAction]) -> list[str]:
    out = ["## Preserves", ""]
    if not preserves:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | License |")
    out.append("| --- | --- | --- |")
    for p in preserves:
        c = p.manual
        out.append(_row(_cell(c.name), _cell(c.version), _cell(c.license)))
    out.append("")
    return out


def _row(*cells: str) -> str:
    return "| " + " | ".join(cells) + " |"


def _cell(value: str | None) -> str:
    if value is None or value == "":
        return "_n/a_"
    return value.replace("|", "\\|")
