from pathlib import Path

import click
from rich.console import Console

from sbom_curator import __version__
from sbom_curator.parsers.spdx import SpdxParseError, load
from sbom_curator.reconcile.diff import reconcile as reconcile_components
from sbom_curator.report.markdown import render
from sbom_curator.support.log import setup_logging

console = Console()


@click.group()
@click.version_option(__version__, prog_name="sbom-curator")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug-level logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Reconcile a manual SPDX SBOM against a Syft-generated SPDX SBOM."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose=verbose, log_dir=Path("logs"))


@cli.command()
@click.option("--manual", "manual", type=click.Path(exists=True, path_type=Path),
              required=True, help="Authoritative SPDX 2.3 JSON SBOM.")
@click.option("--syft", "syft", type=click.Path(exists=True, path_type=Path),
              required=True, help="Syft-generated SPDX 2.3 JSON SBOM.")
@click.option("--name", "name", required=True,
              help="Product name + version, e.g. 'affinity-5.0.0'.")
@click.option("--output-dir", "output_dir", type=click.Path(path_type=Path),
              default=Path("artifacts"), show_default=True, help="Where to write the report.")
def reconcile(manual: Path, syft: Path, name: str, output_dir: Path) -> None:
    """Compare two SBOMs and write a reconciliation report."""
    try:
        manual_components = load(manual, source="manual")
        syft_components = load(syft, source="syft")
    except SpdxParseError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc

    result = reconcile_components(manual_components, syft_components)
    report = render(result, name=name)

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{name}-reconcile.md"
    out_path.write_text(report, encoding="utf-8")

    agreed = len(result.in_both) - len(result.version_mismatches)
    console.print(f"[green][+][/green] wrote {out_path}")
    console.print(f"[green][+][/green] in both, agree: {agreed}")
    console.print(f"[yellow][!][/yellow] version disagreements: "
                  f"{len(result.version_mismatches)}")
    console.print(f"[yellow][!][/yellow] license disagreements: "
                  f"{len(result.license_mismatches)}")
    console.print(f"[yellow][!][/yellow] only in Syft: {len(result.only_in_syft)}")
    console.print(f"[blue]\\[i][/blue] only in manual: {len(result.only_in_manual)}")
