from pathlib import Path

from click.testing import CliRunner

from sbom_curator import __version__
from sbom_curator.cli import cli
from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import Reconciliation
from sbom_curator.support.log import get_logger, setup_logging, strip_ansi

DOGFOOD = Path(__file__).parent / "fixtures" / "dogfood" / "dicom-fuzzer-1.11.0"
SPDX_FIXTURES = Path(__file__).parent / "fixtures" / "spdx"


def test_version_flag() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_reconcile_command_writes_report_and_exits_zero(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifacts"
    result = CliRunner().invoke(
        cli,
        [
            "-v", "reconcile",
            "--manual", str(DOGFOOD / "manual.spdx"),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "dicom-fuzzer-1.11.0",
            "--output-dir", str(out_dir),
        ],
    )
    assert result.exit_code == 0, result.output
    report_path = out_dir / "dicom-fuzzer-1.11.0-reconcile.md"
    assert report_path.exists()
    assert "# SBOM reconciliation report — dicom-fuzzer-1.11.0" in report_path.read_text(
        encoding="utf-8"
    )

    # Each summary line must keep its ASCII marker. [i] in particular needs
    # escaping because Rich treats unescaped [i]...[/i] as italic markup
    # and would silently swallow the literal characters.
    assert "[+] in both, agree:" in result.output
    assert "[!] version disagreements:" in result.output
    assert "[i] only in manual:" in result.output


def test_reconcile_command_reports_parse_error_with_exit_code_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.spdx.json"
    bad.write_text("{not valid json", encoding="utf-8")
    result = CliRunner().invoke(
        cli,
        [
            "reconcile",
            "--manual", str(bad),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "demo-1.0.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2
    assert "[-]" in result.output


def test_ingest_command_writes_change_report_and_exits_zero(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifacts"
    result = CliRunner().invoke(
        cli,
        [
            "-v", "ingest",
            "--manual", str(DOGFOOD / "manual.spdx"),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "dicom-fuzzer-1.11.0",
            "--output-dir", str(out_dir),
        ],
    )
    assert result.exit_code == 0, result.output
    report_path = out_dir / "dicom-fuzzer-1.11.0-ingest.md"
    assert report_path.exists()
    assert "# SBOM change report — dicom-fuzzer-1.11.0" in report_path.read_text(encoding="utf-8")

    # ASCII markers survive Rich markup. [i] in particular needs escaping.
    assert "[!] added:" in result.output
    assert "[!] bumped:" in result.output
    assert "[i] only in your SBOM:" in result.output
    assert "[+] unchanged:" in result.output
    assert "with a license change" in result.output  # dogfood: click


def test_ingest_command_product_prefix_drops_scan_packages(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(DOGFOOD / "manual.spdx"),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "dicom-fuzzer-1.11.0",
            "--output-dir", str(tmp_path / "out"),
            "--product-prefix", "types-",
        ],
    )
    assert result.exit_code == 0, result.output
    # The dogfood scan carries six `types-*` stub packages.
    assert "[i] filtered 6 scan packages matching: types-" in result.output


def test_ingest_command_suggests_covers_prefix_for_added_cluster(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(SPDX_FIXTURES / "tagvalue_minimal.spdx"),
            "--syft", str(SPDX_FIXTURES / "cluster_scan.spdx.json"),
            "--name", "suggest-1.0.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "1 suggested annotation" in result.output
    report = (tmp_path / "out" / "suggest-1.0.0-ingest.md").read_text(encoding="utf-8")
    assert "## Suggested annotations" in report
    assert "**`Vortice.`**" in report
    assert "covers-prefix: Vortice." in report


def test_reconcile_command_suggests_covers_prefix_for_only_in_syft_cluster(
    tmp_path: Path,
) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "reconcile",
            "--manual", str(SPDX_FIXTURES / "tagvalue_minimal.spdx"),
            "--syft", str(SPDX_FIXTURES / "cluster_scan.spdx.json"),
            "--name", "suggest-1.0.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "1 suggested annotation" in result.output


def test_ingest_command_reports_covered_family_packages(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(SPDX_FIXTURES / "coverage_manual.spdx"),
            "--syft", str(SPDX_FIXTURES / "coverage_scan.spdx.json"),
            "--name", "coverage-1.0.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "[+] covered by family entries: 2" in result.output
    report = (tmp_path / "out" / "coverage-1.0.0-ingest.md").read_text(encoding="utf-8")
    assert "## Covered by a family entry" in report
    assert "| Vortice.DXGI | 3.2.0 | Vortice |" in report
    assert "| Vortice.Direct3D11 | 3.2.0 | Vortice |" in report


def test_reconcile_command_reports_covered_family_packages(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "reconcile",
            "--manual", str(SPDX_FIXTURES / "coverage_manual.spdx"),
            "--syft", str(SPDX_FIXTURES / "coverage_scan.spdx.json"),
            "--name", "coverage-1.0.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "[+] covered by family entries: 2" in result.output


def test_ingest_command_collapses_duplicate_scan_packages(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(SPDX_FIXTURES / "tagvalue_minimal.spdx"),
            "--syft", str(SPDX_FIXTURES / "scan_with_duplicates.spdx.json"),
            "--name", "demo-1.0.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    # attrs listed twice (exact dup) + Microsoft.Extensions.Configuration as
    # both 9.0.0 and 9.0.24.52809 (NuGet semver + assembly version).
    assert "[i] collapsed 2 duplicate scan packages" in result.output


def test_ingest_command_fail_on_added_exits_one_when_bucket_non_empty(
    tmp_path: Path,
) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(DOGFOOD / "manual.spdx"),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "dicom-fuzzer-1.11.0",
            "--output-dir", str(tmp_path / "out"),
            "--fail-on", "added",
        ],
    )
    # The dogfood scan adds ~74 packages so the gate fires.
    assert result.exit_code == 1, result.output
    assert "gate hit: added" in result.output


def test_ingest_command_no_gate_means_exit_zero(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(DOGFOOD / "manual.spdx"),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "dicom-fuzzer-1.11.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output


def test_ingest_command_fail_on_unknown_bucket_exits_two(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(DOGFOOD / "manual.spdx"),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "dicom-fuzzer-1.11.0",
            "--output-dir", str(tmp_path / "out"),
            "--fail-on", "bogus",
        ],
    )
    assert result.exit_code == 2
    assert "unknown gate" in result.output or "Invalid value" in result.output


def test_reconcile_command_fail_on_only_in_syft_exits_one(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "reconcile",
            "--manual", str(DOGFOOD / "manual.spdx"),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "dicom-fuzzer-1.11.0",
            "--output-dir", str(tmp_path / "out"),
            "--fail-on", "only-in-syft",
        ],
    )
    assert result.exit_code == 1, result.output
    assert "gate hit: only-in-syft" in result.output


def test_ingest_command_reports_parse_error_with_exit_code_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.spdx"
    bad.write_text("not spdx at all", encoding="utf-8")
    result = CliRunner().invoke(
        cli,
        [
            "ingest",
            "--manual", str(bad),
            "--syft", str(DOGFOOD / "syft.spdx.json"),
            "--name", "demo-1.0.0",
            "--output-dir", str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2
    assert "[-]" in result.output


def test_component_dataclass_defaults() -> None:
    c = Component(name="openssl", version="3.0.0", source="manual")
    assert c.purl is None
    assert c.license is None


def test_reconciliation_dataclass() -> None:
    r = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[])
    assert r.only_in_manual == []


def test_strip_ansi() -> None:
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_setup_logging_with_file_sink(tmp_path: Path) -> None:
    setup_logging(verbose=True, log_dir=tmp_path / "logs")
    log = get_logger("sbom_curator.test")
    log.info("hello")
    log_file = tmp_path / "logs" / "sbom-curator.log"
    assert log_file.exists()


def test_setup_logging_console_only() -> None:
    setup_logging(verbose=False, log_dir=None)
    log = get_logger("sbom_curator.test2")
    log.info("hello")
