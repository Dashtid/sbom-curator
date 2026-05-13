"""Render reconcile and ingest results as Markdown.

Two entry points:

- :func:`render` — a reconciliation as a four-bucket triage report.
- :func:`render_ingest_plan` — a change report: what the latest scan
  *added*, *bumped*, what's *only in your SBOM* (review), and which
  unchanged entries had a *license change*.

Both layouts are section-stable: empty sections render as ``(none)``
rather than being omitted, so a report's diff is meaningful run-to-run
when buckets fluctuate.
"""

from sbom_curator.curate.ingest import (
    AddAction,
    BumpAction,
    CoveredAction,
    EditPlan,
    KeepAction,
    ReviewAction,
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
    lines.append(f"- Covered by family entries: {len(reconciliation.covered)}")
    lines.append("")
    lines.extend(_render_single_section("Only in manual", reconciliation.only_in_manual))
    lines.extend(_render_single_section("Only in Syft", reconciliation.only_in_syft))
    lines.extend(_render_pair_section("Version disagreements", reconciliation.version_mismatches))
    lines.extend(_render_pair_section("License disagreements", reconciliation.license_mismatches))
    lines.extend(_render_covered_pairs(reconciliation.covered))
    return "\n".join(lines) + "\n"


def render_ingest_plan(edit_plan: EditPlan, *, name: str) -> str:
    """Format a change report — what the latest scan changed, relative to your SBOM.

    Unchanged entries are counted in the summary, not enumerated; the
    only unchanged ones that get their own section are those whose
    license changed. The manual SBOM is never modified — this is a
    report the curator acts on by hand.
    """
    changed = edit_plan.keeps_with_license_change
    keep_note = f" ({len(changed)} with a license change)" if changed else ""
    lines: list[str] = []
    lines.append(f"# SBOM change report — {name}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Added: {len(edit_plan.added)} (in the scan, not in your SBOM)")
    lines.append(f"- Bumped: {len(edit_plan.bumped)} (in both, version differs)")
    lines.append(f"- Only in your SBOM: {len(edit_plan.reviews)} (not in the scan — see below)")
    lines.append(f"- Unchanged: {len(edit_plan.keeps)}{keep_note}")
    lines.append(f"- Covered by family entries: {len(edit_plan.covered)}")
    lines.append("")
    lines.extend(_render_added(edit_plan.added))
    lines.extend(_render_bumped(edit_plan.bumped))
    lines.extend(_render_reviews(edit_plan.reviews))
    lines.extend(_render_license_changes(changed))
    lines.extend(_render_covered(edit_plan.covered))
    return "\n".join(lines) + "\n"


# ----- reconcile report sections -----


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


# ----- change-report sections -----


def _render_added(added: list[AddAction]) -> list[str]:
    out = [
        "## Added",
        "",
        "_In the scan, not in your SBOM. Some is build/dev tooling that "
        "doesn't ship — add the ones that do._",
        "",
    ]
    if not added:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | License | PURL |")
    out.append("| --- | --- | --- | --- |")
    for a in added:
        c = a.syft
        out.append(_row(_cell(c.name), _cell(c.version), _cell(c.license), _cell(c.purl)))
    out.append("")
    return out


def _render_bumped(bumped: list[BumpAction]) -> list[str]:
    out = ["## Bumped", ""]
    if not bumped:
        out += ["(none)", ""]
        return out
    out.append("| Name | Your version | Scan version | License change |")
    out.append("| --- | --- | --- | --- |")
    for b in bumped:
        flag = "_yes_" if b.license_changed else "_no_"
        out.append(_row(_cell(b.manual.name), _cell(b.manual.version), _cell(b.syft.version), flag))
    out.append("")
    return out


def _render_reviews(reviews: list[ReviewAction]) -> list[str]:
    out = [
        "## Only in your SBOM",
        "",
        "_Not found in the scan. Either the scanner can't see it (vendored / "
        "statically linked — fine, leave it), the scan lists it under a "
        "different name, or it's gone (then remove it)._",
        "",
    ]
    if not reviews:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | License |")
    out.append("| --- | --- | --- |")
    for rv in reviews:
        c = rv.manual
        out.append(_row(_cell(c.name), _cell(c.version), _cell(c.license)))
    out.append("")
    return out


def _render_license_changes(keeps: list[KeepAction]) -> list[str]:
    out = ["## License changed (otherwise unchanged)", ""]
    if not keeps:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | Your license | Scan license |")
    out.append("| --- | --- | --- | --- |")
    for k in keeps:
        out.append(
            _row(_cell(k.manual.name), _cell(k.manual.version),
                 _cell(k.manual.license), _cell(k.syft.license))
        )
    out.append("")
    return out


def _render_covered(covered: list[CoveredAction]) -> list[str]:
    out = [
        "## Covered by a family entry",
        "",
        "_Scan packages absorbed by an entry's `covers-prefix` annotation — "
        "not in 'added' because you've declared them already._",
        "",
    ]
    if not covered:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | Covered by (your entry) |")
    out.append("| --- | --- | --- |")
    for c in covered:
        out.append(_row(_cell(c.syft.name), _cell(c.syft.version), _cell(c.manual.name)))
    out.append("")
    return out


def _render_covered_pairs(covered: list[tuple[Component, Component]]) -> list[str]:
    out = [
        "## Covered by a family entry",
        "",
        "_Scan packages absorbed by an entry's `covers-prefix` annotation._",
        "",
    ]
    if not covered:
        out += ["(none)", ""]
        return out
    out.append("| Name | Version | Covered by (your entry) |")
    out.append("| --- | --- | --- |")
    for manual, syft in covered:
        out.append(_row(_cell(syft.name), _cell(syft.version), _cell(manual.name)))
    out.append("")
    return out


def _row(*cells: str) -> str:
    return "| " + " | ".join(cells) + " |"


def _cell(value: str | None) -> str:
    if value is None or value == "":
        return "_n/a_"
    return value.replace("|", "\\|")
