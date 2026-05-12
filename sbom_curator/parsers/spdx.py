"""Parser for SPDX 2.x SBOMs (JSON, tag-value, YAML, RDF/XML)."""

import logging
from pathlib import Path

from license_expression import LicenseExpression
from spdx_tools.spdx.model.document import Document as SpdxDocument
from spdx_tools.spdx.model.package import Package as SpdxPackage
from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.parser.tagvalue.tagvalue_parser import parse_from_file as parse_tag_value

from sbom_curator.parsers.model import Component, Source

_log = logging.getLogger(__name__)


class SpdxParseError(ValueError):
    """Raised when an SPDX document cannot be parsed as SPDX 2.x."""


def load(path: Path, source: Source = "manual") -> list[Component]:
    """Parse an SPDX 2.x SBOM into normalized Component records.

    Accepts any SPDX 2.x serialization that spdx-tools understands: JSON
    (.spdx.json), tag-value (.spdx, .txt), YAML (.spdx.yaml), and RDF/XML.
    Components are tagged with the given ``source`` and returned in
    deterministic order (lowercase name, then version).

    File extension is the primary dispatch hint, but tag-value content
    under an unrecognized extension (notably ``.txt``, which is how
    hand-curated SPDX SBOMs commonly land on disk) falls back to a
    content-sniff: if the first non-blank line begins with
    ``SPDXVersion``, parse as tag-value regardless of extension.

    Skips the product itself: packages targeted by the document's DESCRIBES
    relationship, and packages whose name matches one of those targets. The
    name check matters for Syft scans of a directory — Syft's document
    DESCRIBES a synthetic ``...DocumentRoot-Directory-<name>`` package *and*
    separately lists the installed package of the same name; without the
    name check the latter shows up as a phantom "add". (A scanned directory
    that coincidentally shares a name with a real dependency would
    over-filter that dependency — rare, and the curator would notice the
    gap.)

    Also skips non-package noise a directory scan emits: packages with no
    usable version (missing, or the literal string ``UNKNOWN`` / a
    ``NOASSERTION`` sentinel) and packages whose name is a filesystem path
    (contains a backslash) — e.g. ``\\3p\\dcmtk-3.6.7\\bin\\dcmconv`` with
    version ``UNKNOWN``. Those are loose binaries inside vendored source
    trees, not dependencies; left in, they flood the "added" bucket.

    Raises SpdxParseError on parse failure or non-2.x spdxVersion. SPDX 3.0
    is rejected explicitly because spdx-tools accepts the version string but
    cannot interpret the underlying graph-based format.
    """
    try:
        doc = _parse(path)
    except Exception as exc:
        raise SpdxParseError(f"{path}: {exc}") from exc

    version = doc.creation_info.spdx_version
    if not version.startswith("SPDX-2."):
        raise SpdxParseError(f"{path}: expected SPDX-2.x, got {version!r}")

    described = _document_describes(doc)
    described_names = {pkg.name for pkg in doc.packages if pkg.spdx_id in described}
    components: list[Component] = []
    for pkg in doc.packages:
        if pkg.spdx_id in described:
            continue
        if pkg.name in described_names:
            _log.debug("skipping package %r: shares a name with a described element", pkg.name)
            continue
        version = "" if pkg.version is None else str(pkg.version).strip()
        if not version or version.upper() in {"UNKNOWN", "NOASSERTION"}:
            _log.debug("skipping package %r: no usable version (%r)", pkg.name, pkg.version)
            continue
        if "\\" in pkg.name:
            _log.debug("skipping package %r: name looks like a filesystem path", pkg.name)
            continue
        components.append(
            Component(
                name=pkg.name,
                version=version,
                source=source,
                purl=_extract_purl(pkg),
                license=_extract_license(pkg),
            )
        )
    components.sort(key=lambda c: (c.name.lower(), c.version))
    return components


def _parse(path: Path) -> SpdxDocument:
    """Dispatch to spdx-tools, with a content-sniff fallback for tag-value.

    spdx-tools' ``parse_anything`` keys off the file extension and rejects
    unknown ones (including ``.txt``) with "Unsupported SPDX file type"
    even when the content is a valid tag-value document. We catch that
    specific case and route to the tag-value parser when the content
    starts with ``SPDXVersion`` — the unambiguous tag-value signature.
    """
    try:
        return parse_file(str(path))
    except SPDXParsingError as exc:
        if "Unsupported SPDX file type" not in str(exc):
            raise
        head = path.read_text(encoding="utf-8", errors="replace").lstrip()[:32]
        if head.startswith("SPDXVersion"):
            return parse_tag_value(str(path))
        raise


def _document_describes(doc: SpdxDocument) -> set[str]:
    return {
        rel.related_spdx_element_id
        for rel in doc.relationships
        if rel.spdx_element_id == doc.creation_info.spdx_id
        and rel.relationship_type == RelationshipType.DESCRIBES
        and isinstance(rel.related_spdx_element_id, str)
    }


def _extract_purl(pkg: SpdxPackage) -> str | None:
    for ref in pkg.external_references:
        if ref.reference_type == "purl":
            return ref.locator
    return None


def _extract_license(pkg: SpdxPackage) -> str | None:
    for value in (pkg.license_concluded, pkg.license_declared):
        if isinstance(value, LicenseExpression):
            return str(value)
    return None
