from pathlib import Path

import click
from rich.console import Console

from sbom_curator import __version__
from sbom_curator.curate.ingest import plan as build_plan
from sbom_curator.curate.scope import dedupe_scan, drop_by_name_prefix
from sbom_curator.curate.suggest import (
    CoversPrefixSuggestion,
    suggest_covers_prefixes,
)
from sbom_curator.lint import lint as lint_document
from sbom_curator.parsers.model import Component
from sbom_curator.parsers.spdx import SpdxParseError, load
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
def ingest(manual: Path, syft: Path, name: str, output_dir: Path,
           product_prefixes: tuple[str, ...]) -> None:
    """Report what a scan changed relative to your SBOM: added / bumped / review.

    Writes a change report you act on by hand. This command does not
    modify the manual SBOM.
    """
    manual_components, syft_components = _load_inputs(manual, syft, product_prefixes)

    edit_plan = build_plan(manual_components, syft_components)
    suggestions = _suggestions_from(manual_components, [a.syft for a in edit_plan.added])
    report = render_ingest_plan(edit_plan, name=name, suggestions=suggestions)
    out_path = _write(output_dir, f"{name}-ingest.md", report)

    changed = len(edit_plan.keeps_with_license_change)
    keep_note = f" ({changed} with a license change)" if changed else ""
    console.print(f"[green][+][/green] wrote {out_path}")
    console.print(f"[yellow][!][/yellow] added: {len(edit_plan.added)}")
    console.print(f"[yellow][!][/yellow] bumped: {len(edit_plan.bumped)}")
    console.print(f"[blue]\\[i][/blue] only in your SBOM: {len(edit_plan.reviews)}")
    console.print(f"[green][+][/green] unchanged: {len(edit_plan.keeps)}{keep_note}")
    if edit_plan.covered:
        console.print(
            f"[green][+][/green] covered by family entries: {len(edit_plan.covered)}"
        )
    if suggestions:
        console.print(
            f"[blue]\\[i][/blue] {len(suggestions)} suggested annotation(s) — see the report"
        )


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
def reconcile(manual: Path, syft: Path, name: str, output_dir: Path,
              product_prefixes: tuple[str, ...]) -> None:
    """Raw four-bucket diff of the two SBOMs (only-in-manual / only-in-Syft / disagreements)."""
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


def _suggestions_from(
    manual: list[Component], added: list[Component]
) -> tuple[CoversPrefixSuggestion, ...]:
    existing = {prefix for c in manual for prefix in c.covers_prefixes}
    return tuple(suggest_covers_prefixes(added, existing))


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
