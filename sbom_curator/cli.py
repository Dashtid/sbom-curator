from pathlib import Path

import click
from rich.console import Console

from sbom_curator import __version__
from sbom_curator.curate.ingest import plan as build_plan
from sbom_curator.parsers.model import Component
from sbom_curator.parsers.spdx import SpdxParseError, load
from sbom_curator.reconcile.diff import reconcile as reconcile_components
from sbom_curator.report.markdown import render, render_ingest_plan
from sbom_curator.support.log import setup_logging

console = Console()

_MANUAL_HELP = "Authoritative SPDX 2.x manual SBOM (the deliverable)."
_SYFT_HELP = "Syft-generated SPDX 2.x SBOM (periodic input)."
_NAME_HELP = "Product name + version, e.g. 'affinity-6.0.0'. Used as the join key."
_OUTPUT_HELP = "Where to write the report."


@click.group()
@click.version_option(__version__, prog_name="sbom-curator")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug-level logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Curate one authoritative SPDX SBOM, using Syft scans as input."""
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
def reconcile(manual: Path, syft: Path, name: str, output_dir: Path) -> None:
    """Diff the manual SBOM against a Syft SBOM; write a four-bucket report."""
    manual_components, syft_components = _load_inputs(manual, syft)

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


@cli.command()
@click.option("--manual", "manual", type=click.Path(exists=True, path_type=Path),
              required=True, help=_MANUAL_HELP)
@click.option("--syft", "syft", type=click.Path(exists=True, path_type=Path),
              required=True, help=_SYFT_HELP)
@click.option("--name", "name", required=True, help=_NAME_HELP)
@click.option("--output-dir", "output_dir", type=click.Path(path_type=Path),
              default=Path("artifacts"), show_default=True, help=_OUTPUT_HELP)
def ingest(manual: Path, syft: Path, name: str, output_dir: Path) -> None:
    """Turn a Syft scan into a curator edit plan (bumps, adds, keeps, preserves).

    Writes a plan the curator reads and applies by hand. This command does
    not rewrite the manual SBOM.
    """
    manual_components, syft_components = _load_inputs(manual, syft)

    edit_plan = build_plan(manual_components, syft_components)
    report = render_ingest_plan(edit_plan, name=name)
    out_path = _write(output_dir, f"{name}-ingest.md", report)

    drift = len(edit_plan.keeps_with_license_drift)
    keep_note = f" ({drift} with license drift)" if drift else ""
    console.print(f"[green][+][/green] wrote {out_path}")
    console.print(f"[yellow][!][/yellow] bumps: {len(edit_plan.bumps)}")
    console.print(f"[yellow][!][/yellow] adds: {len(edit_plan.adds)}")
    console.print(f"[blue]\\[i][/blue] keeps: {len(edit_plan.keeps)}{keep_note}")
    console.print(f"[green][+][/green] preserves: {len(edit_plan.preserves)}")


def _load_inputs(manual: Path, syft: Path) -> tuple[list[Component], list[Component]]:
    """Parse both SBOMs; exit 2 with a message on parse failure."""
    try:
        return load(manual, source="manual"), load(syft, source="syft")
    except SpdxParseError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc


def _write(output_dir: Path, filename: str, content: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / filename
    out_path.write_text(content, encoding="utf-8")
    return out_path
