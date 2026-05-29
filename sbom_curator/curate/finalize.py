"""Strip ``sbom-curator`` tool annotations from an SPDX tag-value SBOM.

The ingest/reconcile workflow has the curator drop ``sbom-curator <key>: <value>``
hints into ``PackageComment`` blocks (e.g. ``covers-prefix:`` to mark an
umbrella entry). Those lines are operational — useful to the tool, noise to a
regulator. ``sbom-curator finalize`` produces a clean copy for submission with
the annotations removed.

Text-edit only (no parse-and-serialize): preserves formatting, ordering, and
any other ``PackageComment`` content byte-for-byte. A ``PackageComment`` block
whose entire content was tool annotations is removed (including its trailing
newline). Mixed blocks (curator notes + tool lines) keep the notes and lose
the tool lines.

Tag-value SPDX only. Other serializations would need their own pass.
"""

import re
from pathlib import Path

from sbom_curator.curate.discover import DiscoveryError

_BLOCK_RE = re.compile(
    r"^[ \t]*PackageComment:[ \t]*<text>(?P<inner>.*?)</text>[ \t]*(?:\r?\n|\Z)",
    re.MULTILINE | re.DOTALL,
)
_TOOL_LINE_RE = re.compile(r"^[ \t]*sbom-curator [\w-]+:[ \t]*\S")


def strip_tool_annotations(text: str) -> tuple[str, int]:
    """Strip ``sbom-curator <key>: <value>`` lines from ``PackageComment`` blocks.

    Returns ``(cleaned_text, n_stripped)``. Idempotent: running on already-
    clean text yields identical text with ``n_stripped == 0``.

    A block whose remaining content is empty (or whitespace only) is removed
    in full, including its trailing newline. Otherwise the block is rewritten
    with the tool lines gone, preserving line endings detected in the
    original match (CRLF vs LF).
    """
    stripped_count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal stripped_count
        line_sep = "\r\n" if "\r\n" in match.group(0) else "\n"
        kept: list[str] = []
        for line in match.group("inner").splitlines():
            if _TOOL_LINE_RE.match(line):
                stripped_count += 1
            else:
                kept.append(line)
        if not any(line.strip() for line in kept):
            return ""
        return f"PackageComment: <text>{line_sep.join(kept)}</text>{line_sep}"

    return _BLOCK_RE.sub(replace, text), stripped_count


def discover_manuals(root: Path) -> list[Path]:
    """Walk ``<root>/manual/`` for tag-value SBOMs (``.spdx``).

    Folder mode for ``sbom-curator finalize`` does not need a paired scan —
    it operates only on the manual side. Raises :class:`DiscoveryError`
    when the subdirectory is missing.
    """
    manual_dir = root / "manual"
    if not manual_dir.is_dir():
        raise DiscoveryError(f"missing 'manual' subdirectory: {manual_dir}")
    return sorted(
        entry for entry in manual_dir.iterdir()
        if entry.is_file() and entry.suffix.lower() == ".spdx"
    )
