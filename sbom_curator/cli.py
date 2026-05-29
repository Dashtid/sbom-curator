from pathlib import Path
from typing import NamedTuple

import click
from rich.console import Console

from sbom_curator import __version__
from sbom_curator.curate.discover import (
    DiscoveryError,
    DiscoveryResult,
    Pair,
    discover,
)
from sbom_curator.curate.finalize import discover_manuals, strip_tool_annotations
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
_PATH_HELP = (
    "Folder-scan mode: discover (manual, scan) pairs under PATH/manual/ + "
    "PATH/syft/ and ingest each. Mutually exclusive with --manual/--syft/--name."
)
_STRICT_NAMING_HELP = (
    "Folder-scan only: reject non-canonical scan extensions "
    "(.sbom.spdx.json, .spdx.json). Use in CI to enforce the convention."
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
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path),
                required=False)
@click.option("--manual", "manual", type=click.Path(exists=True, path_type=Path),
              required=False, default=None, help=_MANUAL_HELP)
@click.option("--syft", "syft", type=click.Path(exists=True, path_type=Path),
              required=False, default=None, help=_SYFT_HELP)
@click.option("--name", "name", required=False, default=None, help=_NAME_HELP)
@click.option("--output-dir", "output_dir", type=click.Path(path_type=Path),
              default=None, help=_OUTPUT_HELP)
@click.option("--product-prefix", "product_prefixes", multiple=True, metavar="PREFIX",
              help=_PRODUCT_PREFIX_HELP)
@click.option("--fail-on", "fail_on", type=str, default=None, metavar="BUCKETS",
              help=_INGEST_FAIL_ON_HELP)
@click.option("--strict-naming", "strict_naming", is_flag=True, default=False,
              help=_STRICT_NAMING_HELP)
def ingest(path: Path | None, manual: Path | None, syft: Path | None,
           name: str | None, output_dir: Path | None,
           product_prefixes: tuple[str, ...], fail_on: str | None,
           strict_naming: bool) -> None:
    """Report what a scan changed relative to your SBOM: added / bumped / review.

    Two invocation modes:

    \b
    * Single pair (explicit flags):
        sbom-curator ingest --manual M --syft S --name N
    * Folder scan (discovers pairs in <PATH>/manual/ + <PATH>/syft/):
        sbom-curator ingest <PATH>

    Writes one Markdown change report per pair. Does not modify the
    manual SBOM.
    """
    gates = _parse_gates(fail_on, _INGEST_GATES)

    if path is not None:
        # Folder-scan mode
        if manual or syft or name:
            raise click.UsageError(
                "PATH is mutually exclusive with --manual/--syft/--name; "
                "use folder-scan or single-pair, not both."
            )
        _run_ingest_folder(
            path, output_dir, product_prefixes, gates, strict_naming
        )
        return

    # Single-pair mode
    if manual is None or syft is None or name is None:
        missing = [
            flag for flag, val in [("--manual", manual), ("--syft", syft), ("--name", name)]
            if val is None
        ]
        raise click.UsageError(
            f"Missing required option(s): {', '.join(missing)} "
            "(or provide PATH for folder-scan mode)."
        )
    if strict_naming:
        raise click.UsageError("--strict-naming is only valid in folder-scan mode.")
    resolved_output = output_dir or Path("artifacts")
    try:
        result = _run_ingest_pair(
            manual, syft, name, resolved_output, product_prefixes, gates
        )
    except SpdxParseError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc
    _print_single_pair_summary(result)
    if result.gate_hits:
        console.print(f"[red][-][/red] gate hit: {', '.join(sorted(result.gate_hits))}")
        raise click.exceptions.Exit(code=1)


def _print_single_pair_summary(result: "_IngestPairResult") -> None:
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


def _run_ingest_folder(
    root: Path,
    output_dir: Path | None,
    product_prefixes: tuple[str, ...],
    gates: set[str],
    strict_naming: bool,
) -> None:
    """Discover (manual, scan) pairs under ``root`` and ingest each one.

    Per-pair errors don't abort the whole run — they're reported and
    counted, with the aggregate exit code reflecting the worst outcome
    across pairs (2 = parse failure, 1 = gate hit, 0 = clean).
    """
    try:
        discovery = discover(root, strict=strict_naming)
    except DiscoveryError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc

    if not discovery.pairs:
        console.print(f"[red][-][/red] no (manual, scan) pairs found in {root}")
        _print_orphans(discovery)
        raise click.exceptions.Exit(code=2)

    resolved_output = output_dir or (root / "reports")
    console.print(
        f"[blue]\\[i][/blue] discovered {len(discovery.pairs)} pair(s) in {root}"
    )
    _print_orphans(discovery)

    n_processed = 0
    n_gate_hits = 0
    n_parse_errors = 0
    for pair in discovery.pairs:
        outcome = _process_folder_pair(
            pair, resolved_output, product_prefixes, gates
        )
        if outcome == "parse_error":
            n_parse_errors += 1
        elif outcome == "gate_hit":
            n_processed += 1
            n_gate_hits += 1
        else:
            n_processed += 1

    console.print(
        f"[blue]\\[i][/blue] processed {n_processed} pair(s); "
        f"{n_gate_hits} gate hit(s); {n_parse_errors} parse error(s)"
    )

    if n_parse_errors > 0:
        raise click.exceptions.Exit(code=2)
    if n_gate_hits > 0:
        raise click.exceptions.Exit(code=1)


def _process_folder_pair(
    pair: Pair,
    output_dir: Path,
    product_prefixes: tuple[str, ...],
    gates: set[str],
) -> str:
    """Run a single pair in folder mode. Returns 'ok', 'gate_hit', or 'parse_error'."""
    try:
        result = _run_ingest_pair(
            pair.manual, pair.syft, pair.name, output_dir, product_prefixes, gates
        )
    except SpdxParseError as exc:
        console.print(f"[red][-][/red] {pair.name}: {exc}")
        return "parse_error"
    plan = result.plan
    gate_marker = (
        f" [GATE: {', '.join(sorted(result.gate_hits))}]" if result.gate_hits else ""
    )
    console.print(
        f"[green][+][/green] {pair.name}: "
        f"added={len(plan.added)} bumped={len(plan.bumped)} "
        f"review={len(plan.reviews)} covered={len(plan.covered)} "
        f"→ {result.path}{gate_marker}"
    )
    return "gate_hit" if result.gate_hits else "ok"


def _print_orphans(discovery: DiscoveryResult) -> None:
    for p in discovery.orphan_manuals:
        console.print(
            f"[yellow][!][/yellow] orphan manual (no matching scan): {p.name}"
        )
    for p in discovery.orphan_scans:
        console.print(
            f"[yellow][!][/yellow] orphan scan (no matching manual): {p.name}"
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
@click.option("--fail-on", "fail_on", type=str, default=None, metavar="BUCKETS",
              help=_RECONCILE_FAIL_ON_HELP)
def reconcile(manual: Path, syft: Path, name: str, output_dir: Path,
              product_prefixes: tuple[str, ...], fail_on: str | None) -> None:
    """Raw four-bucket diff of the two SBOMs (only-in-manual / only-in-Syft / disagreements)."""
    gates = _parse_gates(fail_on, _RECONCILE_GATES)
    try:
        manual_components, syft_components = _load_inputs(manual, syft, product_prefixes)
    except SpdxParseError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc

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


_FINALIZE_PATH_HELP = (
    "Folder mode: read <PATH>/manual/*.spdx, write <PATH>/finalized/<same>.spdx. "
    "Mutually exclusive with --manual/--output."
)
_FINALIZE_MANUAL_HELP = (
    "Single-file mode: source SPDX tag-value SBOM to strip. Not modified."
)
_FINALIZE_OUTPUT_HELP = (
    "Single-file mode: path to write the finalized (stripped) SBOM."
)


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path),
                required=False)
@click.option("--manual", "manual", type=click.Path(exists=True, path_type=Path),
              required=False, default=None, help=_FINALIZE_MANUAL_HELP)
@click.option("--output", "output", type=click.Path(path_type=Path),
              required=False, default=None, help=_FINALIZE_OUTPUT_HELP)
def finalize(path: Path | None, manual: Path | None, output: Path | None) -> None:
    """Strip ``sbom-curator`` tool annotations for delivery to authorities.

    Removes ``sbom-curator <key>: ...`` lines (e.g. ``covers-prefix``) from
    ``PackageComment`` blocks. Preserves all other content byte-for-byte; a
    block whose entire content was tool annotations is removed in full. The
    source SBOM is not modified.

    Two modes:

    \b
    * Single file:
        sbom-curator finalize --manual M --output O
    * Folder mode:
        sbom-curator finalize <PATH>
            reads  <PATH>/manual/*.spdx
            writes <PATH>/finalized/<same-name>.spdx

    Tag-value SPDX only.
    """
    if path is not None:
        if manual is not None or output is not None:
            raise click.UsageError(
                "PATH is mutually exclusive with --manual/--output; "
                "use folder mode or single-file mode, not both."
            )
        _run_finalize_folder(path)
        return

    if manual is None or output is None:
        missing = [
            flag for flag, val in [("--manual", manual), ("--output", output)]
            if val is None
        ]
        raise click.UsageError(
            f"Missing required option(s): {', '.join(missing)} "
            "(or provide PATH for folder mode)."
        )
    _run_finalize_single(manual, output)


def _run_finalize_single(manual: Path, output: Path) -> None:
    n_stripped = _finalize_one(manual, output)
    console.print(f"[green][+][/green] wrote {output}")
    if n_stripped:
        console.print(
            f"[blue]\\[i][/blue] stripped {n_stripped} tool annotation(s)"
        )
    else:
        console.print("[blue]\\[i][/blue] no tool annotations to strip")


def _run_finalize_folder(root: Path) -> None:
    try:
        manuals = discover_manuals(root)
    except DiscoveryError as exc:
        console.print(f"[red][-][/red] {exc}")
        raise click.exceptions.Exit(code=2) from exc
    if not manuals:
        console.print(
            f"[red][-][/red] no .spdx manuals found in {root / 'manual'}"
        )
        raise click.exceptions.Exit(code=2)

    finalized_dir = root / "finalized"
    finalized_dir.mkdir(parents=True, exist_ok=True)
    console.print(
        f"[blue]\\[i][/blue] discovered {len(manuals)} manual(s) in "
        f"{root / 'manual'}"
    )

    total_stripped = 0
    for source in manuals:
        target = finalized_dir / source.name
        n = _finalize_one(source, target)
        total_stripped += n
        console.print(
            f"[green][+][/green] {source.name}: stripped {n} -> {target}"
        )
    console.print(
        f"[blue]\\[i][/blue] finalized {len(manuals)} file(s); "
        f"stripped {total_stripped} tool annotation(s) total"
    )


def _finalize_one(source: Path, target: Path) -> int:
    text = source.read_text(encoding="utf-8")
    cleaned, n_stripped = strip_tool_annotations(text)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(cleaned, encoding="utf-8")
    return n_stripped


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
    printing a count for each step that removed anything. Raises
    :class:`SpdxParseError` on parse failure — caller decides whether to
    exit (single-pair) or print + continue (folder mode).
    """
    manual_components = load(manual, source="manual")
    syft_components = load(syft, source="syft")
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
