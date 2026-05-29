"""CLI tests for ``sbom-curator finalize`` (single-file + folder modes)."""

from pathlib import Path

from click.testing import CliRunner

from sbom_curator.cli import cli

_TOOL_LINE = "PackageComment: <text>sbom-curator covers-prefix: foo</text>\n"
_PLAIN_SBOM = (
    "SPDXVersion: SPDX-2.3\n"
    "DataLicense: CC0-1.0\n"
    "SPDXID: SPDXRef-DOCUMENT\n"
    "DocumentName: minimal\n"
    "DocumentNamespace: https://example.com/minimal\n"
    "Creator: Tool: test\n"
    "Created: 2026-01-01T00:00:00Z\n"
    "\n"
    "PackageName: Foo\n"
    "SPDXID: SPDXRef-Foo\n"
    "PackageVersion: 1.0\n"
    "PackageDownloadLocation: NOASSERTION\n"
    "PackageLicenseConcluded: NOASSERTION\n"
    "PackageLicenseDeclared: NOASSERTION\n"
    "PackageCopyrightText: NOASSERTION\n"
    "FilesAnalyzed: false\n"
)
_ANNOTATED_SBOM = _PLAIN_SBOM + _TOOL_LINE


def test_finalize_single_file_strips_annotations(tmp_path: Path) -> None:
    manual = tmp_path / "in.spdx"
    output = tmp_path / "out.spdx"
    manual.write_text(_ANNOTATED_SBOM, encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["finalize", "--manual", str(manual), "--output", str(output)]
    )

    assert result.exit_code == 0, result.output
    assert "stripped 1 tool annotation" in result.output
    assert output.read_text(encoding="utf-8") == _PLAIN_SBOM


def test_finalize_single_file_no_annotations_to_strip(tmp_path: Path) -> None:
    manual = tmp_path / "in.spdx"
    output = tmp_path / "out.spdx"
    manual.write_text(_PLAIN_SBOM, encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["finalize", "--manual", str(manual), "--output", str(output)]
    )

    assert result.exit_code == 0, result.output
    assert "no tool annotations to strip" in result.output
    assert output.read_text(encoding="utf-8") == _PLAIN_SBOM


def test_finalize_single_file_does_not_modify_source(tmp_path: Path) -> None:
    manual = tmp_path / "in.spdx"
    output = tmp_path / "out.spdx"
    manual.write_text(_ANNOTATED_SBOM, encoding="utf-8")

    CliRunner().invoke(
        cli, ["finalize", "--manual", str(manual), "--output", str(output)]
    )

    assert manual.read_text(encoding="utf-8") == _ANNOTATED_SBOM


def test_finalize_single_file_creates_parent_directories(tmp_path: Path) -> None:
    manual = tmp_path / "in.spdx"
    output = tmp_path / "nested" / "deep" / "out.spdx"
    manual.write_text(_ANNOTATED_SBOM, encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["finalize", "--manual", str(manual), "--output", str(output)]
    )

    assert result.exit_code == 0, result.output
    assert output.exists()


def test_finalize_single_file_missing_both_flags(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["finalize"])

    assert result.exit_code != 0
    assert "--manual" in result.output
    assert "--output" in result.output


def test_finalize_single_file_missing_one_flag(tmp_path: Path) -> None:
    manual = tmp_path / "in.spdx"
    manual.write_text(_ANNOTATED_SBOM, encoding="utf-8")

    result = CliRunner().invoke(cli, ["finalize", "--manual", str(manual)])

    assert result.exit_code != 0
    assert "--output" in result.output


def test_finalize_folder_mode_processes_all_manuals(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "alpha.spdx").write_text(_ANNOTATED_SBOM, encoding="utf-8")
    (tmp_path / "manual" / "beta.spdx").write_text(_ANNOTATED_SBOM, encoding="utf-8")

    result = CliRunner().invoke(cli, ["finalize", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "discovered 2 manual(s)" in result.output
    assert "finalized 2 file(s)" in result.output
    assert "stripped 2 tool annotation(s) total" in result.output
    assert (tmp_path / "finalized" / "alpha.spdx").read_text(encoding="utf-8") == _PLAIN_SBOM
    assert (tmp_path / "finalized" / "beta.spdx").read_text(encoding="utf-8") == _PLAIN_SBOM


def test_finalize_folder_mode_preserves_source_filenames(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "P60-199-01 Affinity 6.0.0.spdx").write_text(
        _ANNOTATED_SBOM, encoding="utf-8"
    )

    result = CliRunner().invoke(cli, ["finalize", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "finalized" / "P60-199-01 Affinity 6.0.0.spdx").exists()


def test_finalize_folder_mode_does_not_require_syft_subdirectory(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "alpha.spdx").write_text(_ANNOTATED_SBOM, encoding="utf-8")

    result = CliRunner().invoke(cli, ["finalize", str(tmp_path)])

    assert result.exit_code == 0, result.output


def test_finalize_folder_mode_missing_manual_dir_exits_two(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["finalize", str(tmp_path)])

    assert result.exit_code == 2, result.output
    assert "missing 'manual' subdirectory" in result.output


def test_finalize_folder_mode_no_spdx_files_exits_two(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "readme.txt").write_text("", encoding="utf-8")

    result = CliRunner().invoke(cli, ["finalize", str(tmp_path)])

    assert result.exit_code == 2, result.output
    assert "no .spdx manuals found" in result.output


def test_finalize_path_and_manual_mutually_exclusive(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "alpha.spdx").write_text(_ANNOTATED_SBOM, encoding="utf-8")
    fake_manual = tmp_path / "elsewhere.spdx"
    fake_manual.write_text(_ANNOTATED_SBOM, encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["finalize", str(tmp_path), "--manual", str(fake_manual)]
    )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_finalize_path_and_output_mutually_exclusive(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "alpha.spdx").write_text(_ANNOTATED_SBOM, encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["finalize", str(tmp_path), "--output", str(tmp_path / "x.spdx")]
    )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_finalize_folder_mode_idempotent(tmp_path: Path) -> None:
    """Running finalize twice yields the same output as running once."""
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "alpha.spdx").write_text(_ANNOTATED_SBOM, encoding="utf-8")

    CliRunner().invoke(cli, ["finalize", str(tmp_path)])
    first = (tmp_path / "finalized" / "alpha.spdx").read_text(encoding="utf-8")

    # Run again over the same source
    result = CliRunner().invoke(cli, ["finalize", str(tmp_path)])
    second = (tmp_path / "finalized" / "alpha.spdx").read_text(encoding="utf-8")

    assert result.exit_code == 0
    assert first == second == _PLAIN_SBOM
