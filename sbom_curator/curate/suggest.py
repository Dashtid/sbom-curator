"""Propose ``covers-prefix:`` annotations for tight scan-name clusters.

After matching, the *added* bucket can contain a cluster of scan packages
that share a dotted name prefix (``Microsoft.Extensions.*``,
``Vortice.*``) that no manual entry has declared coverage for. The
matcher has the data to point that out, so the curator doesn't have to
read the full *added* list and notice the pattern themselves.

A suggestion is a (prefix, packages) pair. We propose:

* the *most specific* prefix that captures a given set of packages —
  if ``Microsoft.`` and ``Microsoft.Extensions.`` would both capture
  exactly the same five packages, only ``Microsoft.Extensions.`` is
  proposed;
* with at least ``threshold`` packages in the cluster (3 by default);
* skipping any prefix that's already declared as a ``covers-prefix`` on
  some manual entry — we'd just be telling the curator what they already
  wrote.

Ordering is cluster size descending, then prefix alphabetical, capped at
``max_suggestions``.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from sbom_curator.parsers.model import Component


@dataclass(frozen=True)
class CoversPrefixSuggestion:
    prefix: str
    packages: tuple[str, ...]


def suggest_covers_prefixes(
    added: Iterable[Component],
    existing_prefixes: Iterable[str],
    *,
    threshold: int = 3,
    max_suggestions: int = 5,
) -> list[CoversPrefixSuggestion]:
    """Propose ``covers-prefix:`` annotations; see module docstring."""
    by_prefix: dict[str, set[str]] = {}
    for component in added:
        parts = component.name.split(".")
        for i in range(1, len(parts)):
            prefix = ".".join(parts[:i]) + "."
            by_prefix.setdefault(prefix, set()).add(component.name)

    existing_lower = {p.lower() for p in existing_prefixes if p}

    qualifying = [
        (prefix, packages)
        for prefix, packages in by_prefix.items()
        if len(packages) >= threshold and prefix.lower() not in existing_lower
    ]

    # Dedup: when two prefixes capture exactly the same set of packages,
    # keep only the most specific (longest) one. ``by_prefix`` is built
    # shortest-first (the loop above adds prefixes by increasing length),
    # so for any duplicate package set the more specific prefix is always
    # the later overwrite — last-write-wins gives the right answer.
    best_for_set: dict[frozenset[str], tuple[str, set[str]]] = {}
    for prefix, packages in qualifying:
        best_for_set[frozenset(packages)] = (prefix, packages)

    deduped = list(best_for_set.values())
    deduped.sort(key=lambda pp: (-len(pp[1]), pp[0].lower()))
    return [
        CoversPrefixSuggestion(prefix=prefix, packages=tuple(sorted(packages)))
        for prefix, packages in deduped[:max_suggestions]
    ]
