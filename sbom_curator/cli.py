from pathlib import Path
from typing import NamedTuple

import click
from rich.console import Console

from sbom_curator import __version__
from sbom_curator.curate.ingest import EditPlan
from sbom_curator.curate.ingest import plan as build_plan
from sbom_curator.curate.scope import dedupe_scan, drop_by_name_prefix
from sbom_curator.curate.suggest import (
    CoversPrefixSuggestion,
    suggest_covers_prefixes,
)
from sbom_curator.lint import lint as lint_document
from sbom_curator.parsers.model import Component
from sbom_curator.parsers.spdx import SpdxParseError, load
from sbom_curator.reconcile.diff import Reconciliation
from sbom_curator.reconcile.diff import reconcile as reconcile_components
from sbom_curator.report.markdown import render, render_ingest_plan
from sbom_curator.support.log import setup_logging

console = Console()

_MANUAL_HELP = "Your hand-maintained SPDX 2.x SBOM (tag-value or JSON). Never modified."
_SYFT_HELP = "An SPDX 2.x scan SBOM to compare against (e.g. from `syft scan ... -o spdx-json`)."
_NAME_HELP = "Product name + version, e.g. 'affinity-6.0.0'. Used as the join key + report name."
_OUTPUT_HELP = "Where to write the report."
_PRODUCT_PREFIX_HELP = (
    "Drop scan packages whose name starts with PREFIX — the product's own "
    "assemblies a directory scan picks up (e.g. 'Hermes.'). Repeatable; "
    "case-insensitive."
)

_INGEST_GATES = ("added", "bumped", "review", "license")
_RECONCILE_GATES = ("only-in-syft", "only-in-manual", "version", "license")
_INGEST_FAIL_ON_HELP = (
    "Exit 1 when any of the listed buckets is non-empty (default: never). "
    f"Comma-separated; valid: {', '.join(_INGEST_GATES)}."
)
_RECONCILE_FAIL_ON_HELP = (
    "Exit 1 when any of the listed buckets is non-empty (default: never). "
    f"Comma-separated; valid: {', '.join(_RECONCILE_GATES)}."
)


@click.group()
@click.version_option(__version__, prog_name="sbom-curator")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug-level logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Curate one SPDX SBOM by hand; use scans to see what changed."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose=verbose, log_dir=Path("logs"))


@cli.command()
@click.option("--manual", "manual", type=click.Path(exists=True, path_type=Path),
              required=True, help=_MANUAL_HELP)
@click.option("--syft", "syft", type=click.Path(exists=True, path_type=Path),
              required=True, help=_SYFT_HELP)
@click.option("--name", "name", required=True, help=_NAME_HELP)
@click.option("--output-dir", "output_dir", type=click.Path(path_type=Path),
              default=Path("artifacts"), show_default=True, help=_OUTPUT_HELP)
@click.option("--product-prefix", "product_prefixes", multiple=True, metavar="PREFIX",
              help=_PRODUCT_PREFIX_HELP)
@click.option("--fail-on", "fail_on", type=str, default=None, metavar="BUCKETS",
              help=_INGEST_FAIL_ON_HELP)
def ingest(manual: Path, syft: Path, name: str, output_dir: Path,
           product_prefixes: tuple[str, ...], fail_on: str | None) -> None:
    """Report what a scan changed relative to your SBOM: added / bumped / review.

    Writes a change report you act on by hand. This command does not
    modify the manual SBOM.
    """
    gates = _parse_gates(fail_on, _INGEST_GATES)
    result = _run_ingest_pair(manual, syft, name, output_dir, product_prefixes, gates)
    plan = result.plan

    changed = len(plan.keeps_with_license_change)
    keep_note = f" ({changed} with a license change)" if changed else ""
    console.print(f"[green][+][/green] wrote {result.path}")
    console.print(f"[yellow][!][/yellow] added: {len(plan.added)}")
    console.print(f"[yellow][!][/yellow] bumped: {len(plan.bumped)}")
    console.print(f"[blue]\\[i][/blue] only in your SBOM: {len(plan.reviews)}")
    console.print(f"[green][+][/green] unchanged: {len(plan.keeps)}{keep_note}")
    if plan.covered:
        console.print(
            f"[green][+][/green] covered by family entries: {len(plan.covered)}"
        )
    if result.suggestions:
        console.print(
            f"[blue]\\[i][/blue] {len(result.suggestions)} suggested annotation(s) — see the report"
        )
    if result.gate_hits:
        console.print(f"[red][-][/red] gate hit: {', '.join(sorted(result.gate_hits))}")
        raise click.exceptions.Exit(code=1)


@cli.command()
@click.option("--manual", "manual", type=click.Path(exists=True, path_type=Path),
              required=True, help=_MANUAL_HELP)
@click.option("--syft", "syft", type=click.Path(exists=True, path_type=Path),
              required=True, help=_SYFT_HELP)
@click.option("--name", "name", required=True, help=_NAME_HELP)
@click.option("--output-dir", "output_dir", type=click.Path(path_type=Path),
              default=Path("artifacts"), show_default=True, help=_OUTPUT_HELP)
@click.option("--product-prefix", "product_prefixes", multiple=True, metavar="PREFIX",
              help=_PRODUCT_PREFIX_HELP)
@click.option("--fail-on", "fail_on", type=str, default=None, metavar="BUCKETS",
              help=_RECONCILE_FAIL_ON_HELP)
def reconcile(manual: Path, syft: Path, name: str, output_dir: Path,
              product_prefixes: tuple[str, ...], fail_on: str | None) -> None:
    """Raw four-bucket diff of the two SBOMs (only-in-manual / only-in-Syft / disagreements)."""
    gates = _parse_gates(fail_on, _RECONCILE_GATES)
    manual_components, syft_components = _load_inputs(manual, syft, product_prefixes)

    result = reconcile_components(manual_components, syft_components)
    suggestions = _suggestions_from(manual_components, result.only_in_syft)
    report = render(result, name=name, suggestions=suggestions)
    out_path = _write(output_dir, f"{name}-reconcile.md", report)

    agreed = len(result.in_both) - len(result.version_mismatches)
    console.print(f"[green][+][/green] wrote {out_path}")
    console.print(f"[green][+][/green] in both, agree: {agreed}")
    console.print(f"[yellow][!][/yellow] version disagreements: "
                  f"{len(result.version_mismatches)}")
    console.print(f"[yellow][!][/yellow] license disagreements: "
                  f"{len(result.license_mismatches)}")
    console.print(f"[yellow][!][/yellow] only in Syft: {len(result.only_in_syft)}")
    console.print(f"[blue]\\[i][/blue] only in manual: {len(result.only_in_manual)}")
    if result.covered:
        console.print(
            f"[green][+][/green] covered by family entries: {len(result.covered)}"
        )
    if suggestions:
        console.print(
            f"[blue]\\[i][/blue] {len(suggestions)} suggested annotation(s) — see the report"
        )
    hit = _reconcile_gate_hits(result, gates)
    if hit:
        console.print(f"[red][-][/red] gate hit: {', '.join(sorted(hit))}")
        raise click.exceptions.Exit(code=1)


@cli.command(name="lint")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def lint_cmd(path: Path) -> None:
    """Preflight an SPDX SBOM: catch the parse errors and silent skips
    that would otherwise bite ``ingest``/``reconcile``.

    Exit 0 if clean (warnings are OK); exit 2 if any error is found.
    """
    result = lint_document(path)
    for issue in result.issues:
        marker = "[red][-][/red]" if issue.severity == "error" else "[yellow][!][/yellow]"
        location = f"line {issue.line}: " if issue.line is not None else ""
        console.print(f"{marker} {location}{issue.message}")
    errors = result.errors
    warnings = result.warnings
    if not result.issues:
        console.print(f"[green][+][/green] {path}: no issues")
        return
    console.print(
        f"[blue]\\[i][/blue] {len(errors)} error(s), {len(warnings)} warning(s)"
    )
    if errors:
        raise click.exceptions.Exit(code=2)


class _IngestPairResult(NamedTuple):
    path: Path
    plan: EditPlan
    suggestions: tuple[CoversPrefixSuggestion, ...]
    gate_hits: set[str]


def _run_ingest_pair(
    manual: Path,
    syft: Path,
    name: str,
    output_dir: Path,
    product_prefixes: tuple[str, ...],
    gates: set[str],
) -> _IngestPairResult:
    """Parse a manual/scan pair, build the edit plan, write the report.

    Returns the report path, the plan, the covers-prefix suggestions, and
    any ``--fail-on`` gate bucket names that fired.
    """
    manual_components, syft_components = _load_inputs(manual, syft, product_prefixes)
    edit_plan = build_plan(manual_components, syft_components)
    suggestions = _suggestions_from(manual_components, [a.syft for a in edit_plan.added])
    report = render_ingest_plan(edit_plan, name=name, suggestions=suggestions)
    out_path = _write(output_dir, f"{name}-ingest.md", report)
    return _IngestPairResult(
        path=out_path,
        plan=edit_plan,
        suggestions=suggestions,
        gate_hits=_ingest_gate_hits(edit_plan, gates),
    )


def _suggestions_from(
    manual: list[Component], added: list[Component]
) -> tuple[CoversPrefixSuggestion, ...]:
    existing = {prefix for c in manual for prefix in c.covers_prefixes}
    return tuple(suggest_covers_prefixes(added, existing))


def _parse_gates(value: str | None, allowed: tuple[str, ...]) -> set[str]:
    """Split a comma-separated ``--fail-on`` value and validate it."""
    if not value:
        return set()
    raw = [piece.strip().lower() for piece in value.split(",")]
    gates = {piece for piece in raw if piece}
    unknown = gates - set(allowed)
    if unknown:
        raise click.BadParameter(
            f"unknown gate(s): {', '.join(sorted(unknown))}; "
            f"valid: {', '.join(allowed)}",
            param_hint="--fail-on",
        )
    return gates


def _ingest_gate_hits(plan: EditPlan, gates: set[str]) -> set[str]:
    hit: set[str] = set()
    if "added" in gates and plan.added:
        hit.add("added")
    if "bumped" in gates and plan.bumped:
        hit.add("bumped")
    if "review" in gates and plan.reviews:
        hit.add("review")
    if "license" in gates and (
        plan.keeps_with_license_change or any(b.license_changed for b in plan.bumped)
    ):
        hit.add("license")
    return hit


def _reconcile_gate_hits(result: Reconciliation, gates: set[str]) -> set[str]:
    hit: set[str] = set()
    if "only-in-syft" in gates and result.only_in_syft:
        hit.add("only-in-syft")
    if "only-in-manual" in gates and result.only_in_manual:
        hit.add("only-in-manual")
    if "version" in gates and result.version_mismatches:
        hit.add("version")
    if "license" in gates and result.license_mismatches:
        hit.add("license")
    return hit


def _load_inputs(
    manual: Path, syft: Path, product_prefixes: tuple[str, ...]
) -> tuple[list[Component], list[Component]]:
    """Parse both SBOMs and clean up the scan side.

    Drops the product's own assemblies (``--product-prefix``) and collapses
    duplicate scan entries (:func:`~sbom_curator.curate.scope.dedupe_scan`),
    printing a count for each step that removed anything. Exits 2 with a
    message on parse failure.
    """
    try:
        manual_components = load(manual, source="manual")
        syft_components = load(syft, source="syft")
    except SpdxParseError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc
    syft_components, filtered = drop_by_name_prefix(syft_components, product_prefixes)
    if filtered:
        console.print(
            f"[blue]\\[i][/blue] filtered {len(filtered)} scan packages "
            f"matching: {', '.join(product_prefixes)}"
        )
    syft_components, deduped = dedupe_scan(syft_components)
    if deduped:
        console.print(f"[blue]\\[i][/blue] collapsed {len(deduped)} duplicate scan packages")
    return manual_components, syft_components


def _write(output_dir: Path, filename: str, content: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / filename
    out_path.write_text(content, encoding="utf-8")
    return out_path
