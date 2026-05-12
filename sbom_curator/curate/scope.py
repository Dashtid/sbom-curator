"""Scope filters applied to a scan SBOM before reconciliation.

A directory scan of a build tree lists the product's own assemblies as
packages — e.g. a .NET app whose assemblies share the ``Hermes.`` prefix
shows up as a few hundred ``Hermes.Module.*`` "packages". Those aren't
dependencies; they're the thing being shipped. ``drop_by_name_prefix``
removes them so the change report surfaces real third-party components
instead of the product decomposed into DLLs.

The DESCRIBES-based filter in ``parsers.spdx`` already drops the product
when the scan names it explicitly; this is the fallback for directory
scans, where the DESCRIBES target is a synthetic ``...Directory-<path>``
node that shares no name with the assemblies.
"""

from collections.abc import Iterable

from sbom_curator.parsers.model import Component


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
