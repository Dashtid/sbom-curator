"""Tests for the folder-scan discovery module."""

from pathlib import Path

import pytest

from sbom_curator.curate.discover import (
    DiscoveryError,
    DiscoveryResult,
    Pair,
    discover,
)


def _touch(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_discover_finds_conforming_pairs(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "manual" / "beta-2.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")
    _touch(tmp_path / "syft" / "beta-2.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 2
    assert [p.name for p in result.pairs] == ["alpha-1.0.0", "beta-2.0.0"]
    assert all(isinstance(p, Pair) for p in result.pairs)
    assert result.orphan_manuals == ()
    assert result.orphan_scans == ()


def test_discover_returns_paths_pointing_to_real_files(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx", "manual content")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json", "scan content")

    result = discover(tmp_path)

    pair = result.pairs[0]
    assert pair.manual.read_text(encoding="utf-8") == "manual content"
    assert pair.syft.read_text(encoding="utf-8") == "scan content"


def test_discover_tolerates_sbom_infix_in_loose_mode(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.sbom.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    assert result.pairs[0].name == "alpha-1.0.0"


def test_discover_tolerates_plain_spdx_json_in_loose_mode(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1


def test_discover_strict_rejects_sbom_infix(tmp_path: Path) -> None:
    # In strict mode only .syft.spdx.json is accepted as a scan; an .sbom.
    # file becomes a skipped extension, the manual ends up orphaned.
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.sbom.spdx.json")

    result = discover(tmp_path, strict=True)

    assert result.pairs == ()
    assert len(result.orphan_manuals) == 1
    assert result.orphan_manuals[0].name == "alpha-1.0.0.spdx"
    assert any(
        p.name == "alpha-1.0.0.sbom.spdx.json" and "unrecognized" in reason
        for p, reason in result.skipped
    )


def test_discover_strict_accepts_canonical_syft_extension(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")

    result = discover(tmp_path, strict=True)

    assert len(result.pairs) == 1


def test_discover_reports_orphan_manual_and_scan(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "manual" / "lonely.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")
    _touch(tmp_path / "syft" / "orphan.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    assert result.pairs[0].name == "alpha-1.0.0"
    assert [p.name for p in result.orphan_manuals] == ["lonely.spdx"]
    assert [p.name for p in result.orphan_scans] == ["orphan.syft.spdx.json"]


def test_discover_raises_when_manual_subdir_missing(tmp_path: Path) -> None:
    _touch(tmp_path / "syft" / "alpha.syft.spdx.json")

    with pytest.raises(DiscoveryError, match="manual"):
        discover(tmp_path)


def test_discover_raises_when_syft_subdir_missing(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha.spdx")

    with pytest.raises(DiscoveryError, match="syft"):
        discover(tmp_path)


def test_discover_normalizes_dotted_versions_for_matching(tmp_path: Path) -> None:
    # Manual uses dashes ('alpha-1.0.0'), scan uses dots ('alpha.1.0.0').
    # After normalization both become 'alpha-1-0-0' and pair.
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha.1.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    # The pair's display name comes from the manual's stem
    assert result.pairs[0].name == "alpha-1.0.0"


def test_discover_skips_non_sbom_files(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "README.md")
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    assert any(p.name == "README.md" for p, _ in result.skipped)


def test_discover_handles_empty_subdirs(tmp_path: Path) -> None:
    (tmp_path / "manual").mkdir()
    (tmp_path / "syft").mkdir()

    result = discover(tmp_path)

    assert result == DiscoveryResult(pairs=(), orphan_manuals=(), orphan_scans=(), skipped=())


def test_discover_ignores_subdirectories_silently(tmp_path: Path) -> None:
    (tmp_path / "manual" / "nested").mkdir(parents=True)
    (tmp_path / "syft" / "nested").mkdir(parents=True)
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    # The 'nested/' subdirectories are silently ignored (not in skipped)
    assert all(p.is_file() for p, _ in result.skipped)


def test_discover_duplicate_normalized_stem_is_skipped(tmp_path: Path) -> None:
    # Two manuals with different exact names that collide after normalization.
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx")
    _touch(tmp_path / "manual" / "alpha.1.0.0.spdx")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    # The second manual file (alphabetically later or earlier) became "skipped"
    assert any("duplicate" in reason for _p, reason in result.skipped)


def test_discover_handles_uppercase_extensions(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.SPDX")
    _touch(tmp_path / "syft" / "alpha-1.0.0.SYFT.SPDX.JSON")

    result = discover(tmp_path)

    assert len(result.pairs) == 1


def test_discover_preserves_human_filename_casing_in_display_name(tmp_path: Path) -> None:
    # A curator's real-world filename with spaces and mixed case.
    _touch(tmp_path / "manual" / "Product Alpha 1.0.0.spdx")
    _touch(tmp_path / "syft" / "Product Alpha 1.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    # Spaces -> dashes, casing preserved
    assert result.pairs[0].name == "Product-Alpha-1.0.0"


def test_discover_pairs_sorted_by_normalized_key(tmp_path: Path) -> None:
    # Three pairs; verify deterministic alphabetical ordering.
    for name in ["gamma-3.0.0", "alpha-1.0.0", "beta-2.0.0"]:
        _touch(tmp_path / "manual" / f"{name}.spdx")
        _touch(tmp_path / "syft" / f"{name}.syft.spdx.json")

    result = discover(tmp_path)

    assert [p.name for p in result.pairs] == ["alpha-1.0.0", "beta-2.0.0", "gamma-3.0.0"]


def test_discover_manual_spdx_json_extension_supported(tmp_path: Path) -> None:
    # Curators may also use .spdx.json for the manual (JSON serialization).
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx.json")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    assert result.pairs[0].manual.suffix == ".json"


def test_discover_manual_spdx_yaml_extension_supported(tmp_path: Path) -> None:
    _touch(tmp_path / "manual" / "alpha-1.0.0.spdx.yaml")
    _touch(tmp_path / "syft" / "alpha-1.0.0.syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1


def test_discover_display_name_falls_back_to_raw_stem_for_pathological_input(
    tmp_path: Path,
) -> None:
    # A degenerate filename of only separator chars: ``...---....spdx``.
    # The two cleanup passes (whitespace-to-dash + strip dashes/dots, then
    # the broader _normalize) both produce empty strings, so the fallback
    # returns the raw stem to keep the Pair's ``name`` non-empty.
    _touch(tmp_path / "manual" / "...---....spdx")
    _touch(tmp_path / "syft" / "...---....syft.spdx.json")

    result = discover(tmp_path)

    assert len(result.pairs) == 1
    # Raw stem is preserved as the last-resort name (ugly but functional).
    assert result.pairs[0].name == "...---..."
