import json
from pathlib import Path

import pytest

from sbom_curator.parsers.spdx import SpdxParseError, load

FIXTURES = Path(__file__).parent / "fixtures" / "spdx"


def test_load_returns_components_in_deterministic_order() -> None:
    components = load(FIXTURES / "affinity_minimal.spdx.json")

    # Affinity (DESCRIBES target) and no-version-pkg (no versionInfo) skipped.
    assert [c.name for c in components] == [
        "internal.tool",
        "Newtonsoft.Json",
        "openssl",
        "weird-ref-pkg",
    ]


def test_load_tags_components_as_manual_with_versions() -> None:
    components = load(FIXTURES / "affinity_minimal.spdx.json")
    by_name = {c.name: c for c in components}

    assert all(c.source == "manual" for c in components)
    assert by_name["openssl"].version == "3.0.12"
    assert by_name["Newtonsoft.Json"].version == "13.0.3"


def test_load_extracts_purl_when_well_formed() -> None:
    by_name = {c.name: c for c in load(FIXTURES / "affinity_minimal.spdx.json")}

    assert by_name["openssl"].purl == "pkg:nuget/openssl@3.0.12"
    assert by_name["weird-ref-pkg"].purl is None
    assert by_name["Newtonsoft.Json"].purl is None


def test_load_falls_back_from_concluded_to_declared_license() -> None:
    by_name = {c.name: c for c in load(FIXTURES / "affinity_minimal.spdx.json")}

    assert by_name["openssl"].license == "Apache-2.0"
    assert by_name["Newtonsoft.Json"].license == "MIT"
    assert by_name["internal.tool"].license is None
    assert by_name["weird-ref-pkg"].license is None


def test_load_parses_tag_value_format() -> None:
    components = load(FIXTURES / "tagvalue_minimal.spdx")

    # zlib is the DESCRIBES target and is skipped; only lz4 remains.
    assert [c.name for c in components] == ["lz4"]
    assert components[0].version == "1.9.4"
    assert components[0].license == "BSD-2-Clause"


def test_load_invalid_json_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.spdx.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(SpdxParseError):
        load(p)


def test_load_top_level_array_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "array.spdx.json"
    p.write_text('["array at top"]', encoding="utf-8")
    with pytest.raises(SpdxParseError):
        load(p)


def test_load_missing_required_fields_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "missing.spdx.json"
    p.write_text(json.dumps({"packages": []}), encoding="utf-8")
    with pytest.raises(SpdxParseError):
        load(p)


def test_load_spdx_3_document_raises_parse_error(tmp_path: Path) -> None:
    # spdx-tools accepts the version string but cannot interpret SPDX 3.0;
    # our explicit check rejects it before that produces silent garbage.
    p = tmp_path / "spdx3.spdx.json"
    p.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-3.0",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "x",
                "documentNamespace": "https://example.invalid/x",
                "creationInfo": {
                    "created": "2026-01-01T00:00:00Z",
                    "creators": ["Tool: x"],
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SpdxParseError, match="SPDX-2"):
        load(p)


def test_load_handles_tag_value_under_txt_extension(tmp_path: Path) -> None:
    # Hand-curated SPDX SBOMs commonly land on disk as .txt files. spdx-tools'
    # extension-based dispatch rejects those with "Unsupported SPDX file
    # type"; our parser falls back to content-sniffing the SPDXVersion line.
    src = (FIXTURES / "tagvalue_minimal.spdx").read_text(encoding="utf-8")
    txt = tmp_path / "manual_sbom.txt"
    txt.write_text(src, encoding="utf-8")

    components = load(txt, source="manual")
    assert [c.name for c in components] == ["lz4"]


def test_load_unrecognized_extension_without_spdx_signature_raises(tmp_path: Path) -> None:
    # Content that isn't tag-value SPDX should still fail loudly even when
    # the extension is unknown — we don't silently accept arbitrary content.
    p = tmp_path / "garbage.xyz"
    p.write_text("not an SPDX document at all", encoding="utf-8")
    with pytest.raises(SpdxParseError):
        load(p)


def test_load_handles_document_with_no_packages(tmp_path: Path) -> None:
    p = tmp_path / "empty.spdx.json"
    p.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "empty",
                "documentNamespace": "https://example.invalid/empty",
                "creationInfo": {
                    "created": "2026-01-01T00:00:00Z",
                    "creators": ["Tool: empty"],
                },
            }
        ),
        encoding="utf-8",
    )
    assert load(p) == []
