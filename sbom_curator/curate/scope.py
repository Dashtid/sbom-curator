"""Scope filters applied to a scan SBOM before reconciliation.

Two kinds of cleanup, both narrowing what a directory scan dumps into the
change report down to real third-party dependencies:

* ``drop_by_name_prefix`` — drop the product's own assemblies by name
  prefix (a .NET app whose DLLs are all ``Hermes.Module.*`` becomes a few
  hundred phantom "adds" otherwise). The DESCRIBES-based filter in
  ``parsers.spdx`` already drops the product when the scan names it
  explicitly; this is the curator-supplied fallback for directory scans,
  where the DESCRIBES target is a synthetic ``...Directory-<path>`` node
  that shares no name with the assemblies.
* ``dedupe_scan`` — collapse a package the scan lists more than once:
  exact duplicates (Syft emits one row per referencing project), and
  "same package at different precision" pairs (a NuGet semver ``9.0.0``
  alongside its .NET assembly version ``9.0.24.52809``; a version with a
  ``+build`` local segment alongside the same version without). Genuine
  multi-version installs (``foo 1.x`` *and* ``foo 2.x``) are kept.
"""

import logging
from collections.abc import Iterable

from packaging.version import InvalidVersion, Version

from sbom_curator.parsers.model import Component

_log = logging.getLogger(__name__)


def drop_by_name_prefix(
    components: Iterable[Component], prefixes: Iterable[str]
) -> tuple[list[Component], list[Component]]:
    """Split ``components`` into ``(kept, dropped)`` by name prefix.

    A component is dropped if its name starts with any of ``prefixes``,
    compared case-insensitively. Empty or falsy prefixes are ignored; with
    no usable prefixes nothing is dropped. Order is preserved within each
    list.
    """
    lowered = tuple(p.lower() for p in prefixes if p)
    kept: list[Component] = []
    dropped: list[Component] = []
    for component in components:
        if component.name.lower().startswith(lowered):
            dropped.append(component)
        else:
            kept.append(component)
    return kept, dropped


def dedupe_scan(components: list[Component]) -> tuple[list[Component], list[Component]]:
    """Collapse scan entries that name the same package more than once.

    Returns ``(kept, dropped)``. Within each lowercased-name group:

    * exact duplicates (same version) collapse to the first occurrence;
    * if the remaining distinct versions denote the same package at
      different precision (see ``_canonical_variant``), all collapse to the
      canonical one;
    * otherwise every distinct version is kept — a real multi-version
      install is not a duplicate.

    ``kept`` is returned sorted by ``(name.lower(), version)`` for
    determinism, matching :func:`sbom_curator.parsers.spdx.load`.
    """
    by_name: dict[str, list[Component]] = {}
    for component in components:
        by_name.setdefault(component.name.lower(), []).append(component)

    kept: list[Component] = []
    dropped: list[Component] = []
    for group in by_name.values():
        first_by_version: dict[str, Component] = {}
        for component in group:
            if component.version in first_by_version:
                dropped.append(component)
            else:
                first_by_version[component.version] = component
        distinct = list(first_by_version.values())
        if len(distinct) == 1:
            kept.append(distinct[0])
            continue
        canonical = _canonical_variant([c.version for c in distinct])
        if canonical is None:
            kept.extend(distinct)
            continue
        for component in distinct:
            if component.version == canonical:
                kept.append(component)
            else:
                dropped.append(component)
        _log.debug(
            "collapsed scan duplicates of %r: kept %s, dropped %s",
            group[0].name,
            canonical,
            sorted(c.version for c in distinct if c.version != canonical),
        )
    kept.sort(key=lambda c: (c.name.lower(), c.version))
    return kept, dropped


def _canonical_variant(versions: list[str]) -> str | None:
    """Pick the version to keep when several denote one package, else None.

    Returns a version string if the inputs are the same package at
    different precision:

    * all PEP 440-equal, or all sharing one numeric release (differing only
      in pre/post/dev/local segments) -> the shortest string;
    * exactly two, where one's numeric release is a prefix of the other's
      (``8.2.2`` vs ``8.2.2.1+abc``) -> the shorter;
    * exactly two with three- and four-component releases sharing
      major.minor (a NuGet semver ``9.0.0`` and its .NET assembly version
      ``9.0.24.52809``) -> the three-component one.

    Returns None for anything else — distinct releases, or versions that
    don't parse as PEP 440 — so the caller keeps every entry.
    """
    try:
        parsed = {v: Version(v) for v in versions}
    except InvalidVersion:
        return None
    uniq = list(parsed)
    if len({parsed[v] for v in uniq}) == 1 or len({parsed[v].release for v in uniq}) == 1:
        return min(uniq, key=lambda s: (len(s), s))
    if len(uniq) != 2:
        return None
    short, long_ = sorted(uniq, key=lambda s: len(parsed[s].release))
    rs, rl = parsed[short].release, parsed[long_].release
    if len(rs) < len(rl) and rl[: len(rs)] == rs:
        return short
    if (len(rs), len(rl)) == (3, 4) and rs[:2] == rl[:2]:
        return short
    return None
