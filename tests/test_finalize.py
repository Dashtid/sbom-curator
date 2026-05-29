"""Unit tests for the strip-tool-annotations function (finalize stage)."""

from pathlib import Path

import pytest

from sbom_curator.curate.discover import DiscoveryError
from sbom_curator.curate.finalize import discover_manuals, strip_tool_annotations


def test_strip_removes_single_line_block() -> None:
    text = "PackageComment: <text>sbom-curator covers-prefix: NVIDIA CUDA</text>\n"
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == ""
    assert n == 1


def test_strip_removes_multi_line_block_all_tool_lines() -> None:
    text = (
        "PackageName: Foo\n"
        "PackageComment: <text>sbom-curator covers-prefix: System\n"
        "sbom-curator covers-prefix: .NET\n"
        "sbom-curator covers-prefix: Microsoft.Bcl.</text>\n"
        "PackageVersion: 1.0\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == "PackageName: Foo\nPackageVersion: 1.0\n"
    assert n == 3


def test_strip_preserves_mixed_block_keeps_curator_notes() -> None:
    text = (
        "PackageComment: <text>This component is vendored from upstream X.\n"
        "sbom-curator covers-prefix: foo.\n"
        "Replaced the default config.</text>\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == (
        "PackageComment: <text>This component is vendored from upstream X.\n"
        "Replaced the default config.</text>\n"
    )
    assert n == 1


def test_strip_is_idempotent_on_clean_text() -> None:
    text = (
        "PackageName: Foo\n"
        "PackageComment: <text>This is a real curator note.</text>\n"
        "PackageVersion: 1.0\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == text
    assert n == 0


def test_strip_handles_text_with_no_package_comments() -> None:
    text = "PackageName: Foo\nPackageVersion: 1.0\n"
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == text
    assert n == 0


def test_strip_leaves_non_tool_keyed_lines_alone() -> None:
    """A free-text line beginning with `sbom-curator was used` is not a key:value annotation."""
    text = (
        "PackageComment: <text>Note: sbom-curator was used to draft this entry.</text>\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == text
    assert n == 0


def test_strip_handles_arbitrary_namespaced_keys() -> None:
    """Any `sbom-curator <key>:` is stripped, not just covers-prefix."""
    text = (
        "PackageComment: <text>sbom-curator suggestion: foo\n"
        "sbom-curator note: bar</text>\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == ""
    assert n == 2


def test_strip_does_not_match_indented_tool_line_outside_text_block() -> None:
    """Tool-pattern lines outside any <text>...</text> block are left untouched."""
    text = (
        "PackageName: Foo\n"
        "  sbom-curator covers-prefix: bar.\n"
        "PackageVersion: 1.0\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == text
    assert n == 0


def test_strip_preserves_crlf_line_endings() -> None:
    text = (
        "PackageName: Foo\r\n"
        "PackageComment: <text>real note.\r\n"
        "sbom-curator covers-prefix: foo.</text>\r\n"
        "PackageVersion: 1.0\r\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == (
        "PackageName: Foo\r\n"
        "PackageComment: <text>real note.</text>\r\n"
        "PackageVersion: 1.0\r\n"
    )
    assert n == 1


def test_strip_preserves_surrounding_lines_byte_for_byte() -> None:
    """The stripped text differs from the original only by the dropped lines."""
    text = (
        "SPDXVersion: SPDX-2.3\n"
        "PackageName: Foo\n"
        "PackageComment: <text>sbom-curator covers-prefix: A</text>\n"
        "PackageLicenseDeclared: MIT\n"
        "PackageCopyrightText: Copyright (C) X\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == (
        "SPDXVersion: SPDX-2.3\n"
        "PackageName: Foo\n"
        "PackageLicenseDeclared: MIT\n"
        "PackageCopyrightText: Copyright (C) X\n"
    )
    assert n == 1


def test_strip_handles_block_at_end_of_file_without_trailing_newline() -> None:
    text = "PackageComment: <text>sbom-curator covers-prefix: A</text>"
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == ""
    assert n == 1


def test_strip_handles_empty_input() -> None:
    cleaned, n = strip_tool_annotations("")
    assert cleaned == ""
    assert n == 0


def test_strip_preserves_block_when_only_some_tool_lines_stripped() -> None:
    text = (
        "PackageComment: <text>sbom-curator covers-prefix: A\n"
        "Keep this curator note.\n"
        "sbom-curator covers-prefix: B</text>\n"
    )
    cleaned, n = strip_tool_annotations(text)
    assert cleaned == "PackageComment: <text>Keep this curator note.</text>\n"
    assert n == 2


def test_discover_manuals_returns_only_spdx_files(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "alpha.spdx").write_text("", encoding="utf-8")
    (tmp_path / "manual" / "beta.spdx").write_text("", encoding="utf-8")
    (tmp_path / "manual" / "ignored.txt").write_text("", encoding="utf-8")
    (tmp_path / "manual" / "ignored.spdx.json").write_text("", encoding="utf-8")

    result = discover_manuals(tmp_path)

    assert [p.name for p in result] == ["alpha.spdx", "beta.spdx"]


def test_discover_manuals_raises_when_manual_dir_missing(tmp_path: Path) -> None:
    with pytest.raises(DiscoveryError, match="missing 'manual' subdirectory"):
        discover_manuals(tmp_path)


def test_discover_manuals_returns_empty_list_when_no_spdx_files(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "readme.txt").write_text("", encoding="utf-8")

    result = discover_manuals(tmp_path)

    assert result == []


def test_discover_manuals_ignores_subdirectories(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "nested").mkdir()
    (tmp_path / "manual" / "alpha.spdx").write_text("", encoding="utf-8")

    result = discover_manuals(tmp_path)

    assert [p.name for p in result] == ["alpha.spdx"]


def test_discover_manuals_handles_uppercase_extension(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "manual" / "ALPHA.SPDX").write_text("", encoding="utf-8")

    result = discover_manuals(tmp_path)

    assert len(result) == 1
