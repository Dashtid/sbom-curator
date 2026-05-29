"""Discover (manual, scan) pairs in the conventional ``artifacts/`` layout.

Folder-scan mode (``sbom-curator ingest <dir>``) finds matching files in
``<dir>/manual/`` and ``<dir>/syft/`` and runs ``ingest`` once per pair.
Naming convention (per ``docs/WORKFLOW.md``):

* Manual SBOMs: ``<dir>/manual/<name>.spdx`` (also ``.spdx.json``, ``.spdx.yaml``)
* Scan SBOMs:   ``<dir>/syft/<name>.syft.spdx.json``

Pairs are joined by ``<name>`` after normalization (lowercase, runs of
dot/space/underscore collapsed to a single dash). The manual's stem is
used as the report-friendly name (``<dir>/reports/<name>-ingest.md``).

Loose mode (the default) tolerates non-canonical scan extensions like
``.sbom.spdx.json`` and ``.spdx.json``, and normalizes filenames that
use dots instead of dashes for the version segment. Strict mode
(``strict=True``) requires the canonical ``.syft.spdx.json`` infix —
intended for CI checks that enforce the convention.
"""

import re
from dataclasses import dataclass
from pathlib import Path

_MANUAL_EXTS: tuple[str, ...] = (".spdx", ".spdx.json", ".spdx.yaml", ".spdx.yml")
_SCAN_EXT_STRICT: str = ".syft.spdx.json"
_SCAN_EXTS_LOOSE: tuple[str, ...] = (".syft.spdx.json", ".sbom.spdx.json", ".spdx.json")


@dataclass(frozen=True)
class Pair:
    """A matched manual SBOM + Syft scan, ready to ingest."""

    name: str
    manual: Path
    syft: Path


@dataclass(frozen=True)
class DiscoveryResult:
    """The result of walking ``<root>/manual/`` and ``<root>/syft/``.

    ``pairs`` is what folder-scan ingests. ``orphan_manuals`` and
    ``orphan_scans`` are files in the right directory with the right
    extension that don't have a counterpart (curator probably forgot to
    drop the other side). ``skipped`` collects files that didn't match
    any expected extension or were duplicates of an already-indexed stem.
    """

    pairs: tuple[Pair, ...]
    orphan_manuals: tuple[Path, ...]
    orphan_scans: tuple[Path, ...]
    skipped: tuple[tuple[Path, str], ...]


class DiscoveryError(Exception):
    """Raised when the directory layout is unusable for folder-scan."""


def discover(root: Path, *, strict: bool = False) -> DiscoveryResult:
    """Discover matching (manual, scan) pairs under ``root``.

    Expects ``<root>/manual/`` and ``<root>/syft/``. Pairs are matched by
    normalized stem (case-insensitive, dots/spaces/underscores treated
    as separator). The manual's original stem becomes the pair's
    ``name`` (used as the report filename).

    Raises :class:`DiscoveryError` if either expected subdirectory is
    missing.
    """
    manual_dir = root / "manual"
    syft_dir = root / "syft"
    if not manual_dir.is_dir():
        raise DiscoveryError(f"missing 'manual' subdirectory: {manual_dir}")
    if not syft_dir.is_dir():
        raise DiscoveryError(f"missing 'syft' subdirectory: {syft_dir}")

    scan_exts = (_SCAN_EXT_STRICT,) if strict else _SCAN_EXTS_LOOSE

    manuals, manual_skips = _index(manual_dir, _MANUAL_EXTS)
    scans, scan_skips = _index(syft_dir, scan_exts)

    pairs: list[Pair] = []
    matched: set[str] = set()
    for key in sorted(manuals.keys() & scans.keys()):
        m_path, m_stem = manuals[key]
        s_path, _s_stem = scans[key]
        pairs.append(Pair(name=_display_name(m_stem), manual=m_path, syft=s_path))
        matched.add(key)

    orphan_manuals = tuple(sorted(
        path for key, (path, _stem) in manuals.items() if key not in matched
    ))
    orphan_scans = tuple(sorted(
        path for key, (path, _stem) in scans.items() if key not in matched
    ))
    return DiscoveryResult(
        pairs=tuple(pairs),
        orphan_manuals=orphan_manuals,
        orphan_scans=orphan_scans,
        skipped=tuple(manual_skips + scan_skips),
    )


def _index(
    directory: Path, exts: tuple[str, ...]
) -> tuple[dict[str, tuple[Path, str]], list[tuple[Path, str]]]:
    """Map normalized stem -> (path, original_stem) for files in ``directory``.

    Returns (index, skipped). Files whose extension doesn't match any of
    ``exts`` go into ``skipped`` with reason ``unrecognized extension``;
    duplicate-stem files (same normalized key, different filename) also
    go into ``skipped``.
    """
    index: dict[str, tuple[Path, str]] = {}
    skipped: list[tuple[Path, str]] = []
    for entry in sorted(directory.iterdir()):
        if not entry.is_file():
            continue
        ext = _matching_ext(entry.name, exts)
        if ext is None:
            skipped.append((entry, "unrecognized extension"))
            continue
        stem = entry.name[: -len(ext)]
        key = _normalize(stem)
        if key in index:
            skipped.append((entry, f"duplicate stem after normalization: {key}"))
            continue
        index[key] = (entry, stem)
    return index, skipped


def _matching_ext(filename: str, exts: tuple[str, ...]) -> str | None:
    """Longest matching extension from ``exts`` (case-insensitive), or None."""
    lower = filename.lower()
    matches = [ext for ext in exts if lower.endswith(ext)]
    if not matches:
        return None
    return max(matches, key=len)


def _normalize(stem: str) -> str:
    """Stem -> match key. Lowercase; collapse dot/space/underscore runs to dash."""
    s = stem.lower()
    s = re.sub(r"[.\s_]+", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    return s.strip("-")


def _display_name(stem: str) -> str:
    """Convert a manual file's stem to a report-friendly name.

    Preserves the curator's casing; replaces whitespace runs with a
    single dash; strips surrounding dashes and dots. Falls back to the
    raw stem if the result would be empty (degenerate filenames of only
    separators — won't happen with curator-chosen names, but keeps the
    contract that the Pair always has a non-empty ``name``).
    """
    cleaned = re.sub(r"\s+", "-", stem).strip("-.")
    return cleaned or stem
