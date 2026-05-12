from pathlib import Path

import click
from rich.console import Console

from sbom_curator import __version__
from sbom_curator.curate.ingest import plan as build_plan
from sbom_curator.curate.scope import drop_by_name_prefix
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
    report = render_ingest_plan(edit_plan, name=name)
    out_path = _write(output_dir, f"{name}-ingest.md", report)

    changed = len(edit_plan.keeps_with_license_change)
    keep_note = f" ({changed} with a license change)" if changed else ""
    console.print(f"[green][+][/green] wrote {out_path}")
    console.print(f"[yellow][!][/yellow] added: {len(edit_plan.added)}")
    console.print(f"[yellow][!][/yellow] bumped: {len(edit_plan.bumped)}")
    console.print(f"[blue]\\[i][/blue] only in your SBOM: {len(edit_plan.reviews)}")
    console.print(f"[green][+][/green] unchanged: {len(edit_plan.keeps)}{keep_note}")


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
    report = render(result, name=name)
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


def _load_inputs(
    manual: Path, syft: Path, product_prefixes: tuple[str, ...]
) -> tuple[list[Component], list[Component]]:
    """Parse both SBOMs and drop product assemblies from the scan side.

    Exits 2 with a message on parse failure. When ``--product-prefix`` was
    given and matched anything, prints how many scan packages were dropped.
    """
    try:
        manual_components = load(manual, source="manual")
        syft_components = load(syft, source="syft")
    except SpdxParseError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc
    syft_components, dropped = drop_by_name_prefix(syft_components, product_prefixes)
    if dropped:
        console.print(
            f"[blue]\\[i][/blue] filtered {len(dropped)} scan packages "
            f"matching: {', '.join(product_prefixes)}"
        )
    return manual_components, syft_components


def _write(output_dir: Path, filename: str, content: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / filename
    out_path.write_text(content, encoding="utf-8")
    return out_path
