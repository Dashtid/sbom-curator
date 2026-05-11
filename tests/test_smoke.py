from pathlib import Path

from click.testing import CliRunner

from sbom_curator import __version__
from sbom_curator.cli import cli
from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import Reconciliation
from sbom_curator.support.log import get_logger, setup_logging, strip_ansi

DOGFOOD = Path(__file__).parent / "fixtures" / "dogfood" / "dicom-fuzzer-1.11.0"


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


def test_ingest_command_writes_plan_and_exits_zero(tmp_path: Path) -> None:
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
    plan_path = out_dir / "dicom-fuzzer-1.11.0-ingest.md"
    assert plan_path.exists()
    assert "# SBOM ingest plan — dicom-fuzzer-1.11.0" in plan_path.read_text(encoding="utf-8")

    # ASCII markers survive Rich markup. [i] in particular needs escaping.
    assert "[!] bumps:" in result.output
    assert "[!] adds:" in result.output
    assert "[i] keeps:" in result.output
    assert "with license drift" in result.output
    assert "[+] preserves:" in result.output


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
