"""CLI tests for folder-scan mode (``sbom-curator ingest <PATH>``)."""

import shutil
from pathlib import Path

from click.testing import CliRunner

from sbom_curator.cli import cli

FIXTURES = Path(__file__).parent / "fixtures" / "spdx"
_MANUAL_SRC = FIXTURES / "tagvalue_minimal.spdx"
_SCAN_SRC = FIXTURES / "affinity_minimal.spdx.json"


def _make_layout(root: Path, pairs: list[tuple[str, Path, Path]]) -> None:
    """Create root/manual/ + root/syft/ with the given (name, manual_src, scan_src) pairs.

    Pair tuples: (stem, manual_source_path, scan_source_path). The stem
    becomes the filename ``manual/<stem>.spdx`` and ``syft/<stem>.syft.spdx.json``.
    """
    (root / "manual").mkdir(parents=True, exist_ok=True)
    (root / "syft").mkdir(parents=True, exist_ok=True)
    for stem, manual_src, scan_src in pairs:
        shutil.copy(manual_src, root / "manual" / f"{stem}.spdx")
        shutil.copy(scan_src, root / "syft" / f"{stem}.syft.spdx.json")


def test_folder_scan_processes_multiple_pairs(tmp_path: Path) -> None:
    _make_layout(tmp_path, [
        ("alpha-1.0.0", _MANUAL_SRC, _SCAN_SRC),
        ("beta-2.0.0", _MANUAL_SRC, _SCAN_SRC),
    ])

    result = CliRunner().invoke(cli, ["ingest", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "discovered 2 pair(s)" in result.output
    assert "alpha-1.0.0" in result.output
    assert "beta-2.0.0" in result.output
    assert "processed 2 pair(s)" in result.output
    # Reports written under <PATH>/reports/ by default
    assert (tmp_path / "reports" / "alpha-1.0.0-ingest.md").exists()
    assert (tmp_path / "reports" / "beta-2.0.0-ingest.md").exists()


def test_folder_scan_strict_mode_accepts_canonical_extension(tmp_path: Path) -> None:
    _make_layout(tmp_path, [("alpha", _MANUAL_SRC, _SCAN_SRC)])

    result = CliRunner().invoke(cli, ["ingest", str(tmp_path), "--strict-naming"])

    assert result.exit_code == 0, result.output


def test_folder_scan_strict_mode_rejects_non_syft_infix(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "syft").mkdir()
    shutil.copy(_MANUAL_SRC, tmp_path / "manual" / "alpha.spdx")
    shutil.copy(_SCAN_SRC, tmp_path / "syft" / "alpha.sbom.spdx.json")

    result = CliRunner().invoke(cli, ["ingest", str(tmp_path), "--strict-naming"])

    # In strict mode the .sbom. extension is skipped; the manual becomes orphan.
    assert result.exit_code == 2, result.output
    assert "no (manual, scan) pairs found" in result.output


def test_folder_scan_warns_on_orphans_but_processes_real_pairs(tmp_path: Path) -> None:
    _make_layout(tmp_path, [("alpha", _MANUAL_SRC, _SCAN_SRC)])
    # Add an orphan manual + orphan scan
    shutil.copy(_MANUAL_SRC, tmp_path / "manual" / "lonely.spdx")
    shutil.copy(_SCAN_SRC, tmp_path / "syft" / "orphan.syft.spdx.json")

    result = CliRunner().invoke(cli, ["ingest", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "orphan manual (no matching scan): lonely.spdx" in result.output
    assert "orphan scan (no matching manual): orphan.syft.spdx.json" in result.output
    assert (tmp_path / "reports" / "alpha-ingest.md").exists()


def test_folder_scan_exits_two_when_no_pairs_found(tmp_path: Path) -> None:
    # Only manuals, no scans (or vice versa) -> zero pairs.
    (tmp_path / "manual").mkdir()
    (tmp_path / "syft").mkdir()
    shutil.copy(_MANUAL_SRC, tmp_path / "manual" / "alpha.spdx")

    result = CliRunner().invoke(cli, ["ingest", str(tmp_path)])

    assert result.exit_code == 2, result.output
    assert "no (manual, scan) pairs found" in result.output
    assert "orphan manual" in result.output


def test_folder_scan_exits_two_when_subdirs_missing(tmp_path: Path) -> None:
    # No manual/ or syft/ subdir -> discovery error.
    result = CliRunner().invoke(cli, ["ingest", str(tmp_path)])

    assert result.exit_code == 2, result.output
    assert "missing 'manual' subdirectory" in result.output


def test_folder_scan_continues_past_per_pair_parse_error(tmp_path: Path) -> None:
    # One good pair, one with a corrupt manual.
    (tmp_path / "manual").mkdir()
    (tmp_path / "syft").mkdir()
    shutil.copy(_MANUAL_SRC, tmp_path / "manual" / "good.spdx")
    shutil.copy(_SCAN_SRC, tmp_path / "syft" / "good.syft.spdx.json")
    (tmp_path / "manual" / "bad.spdx").write_text("not an SPDX document at all",
                                                   encoding="utf-8")
    shutil.copy(_SCAN_SRC, tmp_path / "syft" / "bad.syft.spdx.json")

    result = CliRunner().invoke(cli, ["ingest", str(tmp_path)])

    # Parse error on one pair → overall exit 2; good pair still written.
    assert result.exit_code == 2, result.output
    assert "bad:" in result.output  # error line for the bad pair
    assert (tmp_path / "reports" / "good-ingest.md").exists()
    assert "processed 1 pair(s)" in result.output
    assert "1 parse error(s)" in result.output


def test_folder_scan_fail_on_aggregates_to_exit_one(tmp_path: Path) -> None:
    _make_layout(tmp_path, [("alpha", _MANUAL_SRC, _SCAN_SRC)])

    # The affinity_minimal scan fixture has "added" components vs the
    # tagvalue_minimal manual, so --fail-on added will fire.
    result = CliRunner().invoke(
        cli, ["ingest", str(tmp_path), "--fail-on", "added"]
    )

    assert result.exit_code == 1, result.output
    assert "[GATE: added]" in result.output
    assert "1 gate hit(s)" in result.output


def test_folder_scan_applies_product_prefix_globally(tmp_path: Path) -> None:
    _make_layout(tmp_path, [
        ("alpha", _MANUAL_SRC, _SCAN_SRC),
        ("beta", _MANUAL_SRC, _SCAN_SRC),
    ])

    result = CliRunner().invoke(
        cli, ["ingest", str(tmp_path), "--product-prefix", "Zzz"]
    )

    assert result.exit_code == 0, result.output
    # Both pairs were processed (prefix doesn't drop anything; just exercising the flow)
    assert "alpha" in result.output
    assert "beta" in result.output


def test_folder_scan_output_dir_override(tmp_path: Path) -> None:
    _make_layout(tmp_path, [("alpha", _MANUAL_SRC, _SCAN_SRC)])
    custom_out = tmp_path / "elsewhere"

    result = CliRunner().invoke(
        cli, ["ingest", str(tmp_path), "--output-dir", str(custom_out)]
    )

    assert result.exit_code == 0, result.output
    assert (custom_out / "alpha-ingest.md").exists()
    assert not (tmp_path / "reports" / "alpha-ingest.md").exists()


def test_folder_scan_rejects_combining_path_with_manual(tmp_path: Path) -> None:
    _make_layout(tmp_path, [("alpha", _MANUAL_SRC, _SCAN_SRC)])

    result = CliRunner().invoke(
        cli, ["ingest", str(tmp_path), "--manual", str(_MANUAL_SRC)]
    )

    assert result.exit_code == 2, result.output  # click UsageError
    assert "mutually exclusive" in result.output


def test_folder_scan_rejects_combining_path_with_syft(tmp_path: Path) -> None:
    _make_layout(tmp_path, [("alpha", _MANUAL_SRC, _SCAN_SRC)])

    result = CliRunner().invoke(
        cli, ["ingest", str(tmp_path), "--syft", str(_SCAN_SRC)]
    )

    assert result.exit_code == 2, result.output
    assert "mutually exclusive" in result.output


def test_folder_scan_rejects_combining_path_with_name(tmp_path: Path) -> None:
    _make_layout(tmp_path, [("alpha", _MANUAL_SRC, _SCAN_SRC)])

    result = CliRunner().invoke(
        cli, ["ingest", str(tmp_path), "--name", "x"]
    )

    assert result.exit_code == 2, result.output
    assert "mutually exclusive" in result.output


def test_single_pair_mode_rejects_strict_naming_flag(tmp_path: Path) -> None:
    # --strict-naming is folder-mode only.
    result = CliRunner().invoke(cli, [
        "ingest",
        "--manual", str(_MANUAL_SRC),
        "--syft", str(_SCAN_SRC),
        "--name", "x",
        "--strict-naming",
    ])

    assert result.exit_code == 2, result.output
    assert "--strict-naming" in result.output


def test_single_pair_mode_rejects_missing_required_flags(tmp_path: Path) -> None:
    # Neither PATH nor full --manual/--syft/--name set.
    result = CliRunner().invoke(cli, ["ingest", "--manual", str(_MANUAL_SRC)])

    assert result.exit_code == 2, result.output
    assert "--syft" in result.output
    assert "--name" in result.output


def test_single_pair_mode_parse_error_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "garbage.spdx"
    bad.write_text("not an SPDX document at all", encoding="utf-8")

    result = CliRunner().invoke(cli, [
        "ingest",
        "--manual", str(bad),
        "--syft", str(_SCAN_SRC),
        "--name", "x",
        "--output-dir", str(tmp_path / "out"),
    ])

    assert result.exit_code == 2, result.output


def test_reconcile_parse_error_still_exits_two(tmp_path: Path) -> None:
    # Regression check on the reconcile branch after the _load_inputs refactor.
    bad = tmp_path / "garbage.spdx"
    bad.write_text("not an SPDX document at all", encoding="utf-8")

    result = CliRunner().invoke(cli, [
        "reconcile",
        "--manual", str(bad),
        "--syft", str(_SCAN_SRC),
        "--name", "x",
        "--output-dir", str(tmp_path / "out"),
    ])

    assert result.exit_code == 2, result.output
