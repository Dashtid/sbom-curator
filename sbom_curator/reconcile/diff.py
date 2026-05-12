"""Reconcile a manual SBOM against a Syft-generated SBOM."""

from dataclasses import dataclass
from urllib.parse import unquote

from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.equivalence import licenses_equal, versions_equal


@dataclass(frozen=True)
class Reconciliation:
    """Result of comparing a manual SBOM against a Syft SBOM.

    Attributes:
        only_in_manual: Components present only in the authoritative manual
            SBOM. Usually fine (vendored binaries, statically linked libs
            Syft cannot see).
        only_in_syft: Components present only in the Syft scan. Likely
            missing from the manual SBOM and worth a human review.
        in_both: Components matched across both inputs as
            ``(manual, syft)`` pairs. The pair may agree, differ on
            version, differ on license, or differ on both. Reporters
            inspect the pairs to surface disagreements.
    """

    only_in_manual: list[Component]
    only_in_syft: list[Component]
    in_both: list[tuple[Component, Component]]

    @property
    def version_mismatches(self) -> list[tuple[Component, Component]]:
        """In-both pairs whose versions disagree under PEP 440 equivalence.

        ``1.0`` and ``1.0.0`` agree; ``1.0.0`` and ``1.0.0+local`` disagree.
        Unparseable versions fall back to strict string equality.
        """
        return [(m, s) for m, s in self.in_both if not versions_equal(m.version, s.version)]

    @property
    def license_mismatches(self) -> list[tuple[Component, Component]]:
        """In-both pairs whose license expressions disagree.

        ``Apache-2.0 OR MIT`` and ``MIT OR Apache-2.0`` agree (OR/AND is
        commutative). Both ``None`` agrees; one ``None`` and one set
        license disagrees. Unparseable expressions fall back to strict
        string equality.
        """
        return [(m, s) for m, s in self.in_both if not licenses_equal(m.license, s.license)]


def reconcile(manual: list[Component], syft: list[Component]) -> Reconciliation:
    """Compare two component lists and bucket them.

    Matching happens in two passes. First by **PURL identity**: a manual
    and a scan component match if their package URLs denote the same
    package — same PURL after lowercasing, URL-decoding, and dropping the
    ``@version``, ``?qualifiers``, and ``#subpath`` (see
    :func:`_normalize_purl`). This catches the case where the curator
    recorded the canonical name (``CommunityToolkit`` with PURL
    ``pkg:nuget/CommunityToolkit.Mvvm@8.2.2``) and the scan used a
    different one (``CommunityToolkit.Mvvm``). The version is deliberately
    dropped from the PURL key, so a PURL match with differing versions
    still lands in ``in_both`` — that surfaces it as a version
    disagreement, which is what we want.

    Whatever is still unmatched is then matched by **lowercased name**.

    Where multiple components share a key within a single side (rare —
    e.g. a manual SBOM listing two builds of one library), each is matched
    against any same-key component on the other side, pairs produced in
    input order, and extras spill into the only-in-X buckets. A component
    is consumed by at most one match across both passes.

    Output ordering inside each bucket is deterministic
    ``(name.lower(), version)`` so the eventual triage report diffs
    cleanly run-to-run.
    """
    manual_by_purl: dict[str, list[int]] = {}
    manual_by_name: dict[str, list[int]] = {}
    for i, c in enumerate(manual):
        manual_by_name.setdefault(c.name.lower(), []).append(i)
        key = _normalize_purl(c.purl)
        if key is not None:
            manual_by_purl.setdefault(key, []).append(i)

    consumed: set[int] = set()
    in_both: list[tuple[Component, Component]] = []
    unmatched: list[Component] = []
    for s in syft:
        key = _normalize_purl(s.purl)
        idx = _take(manual_by_purl.get(key, []), consumed) if key is not None else None
        if idx is None:
            unmatched.append(s)
        else:
            in_both.append((manual[idx], s))

    only_in_syft: list[Component] = []
    for s in unmatched:
        idx = _take(manual_by_name.get(s.name.lower(), []), consumed)
        if idx is None:
            only_in_syft.append(s)
        else:
            in_both.append((manual[idx], s))

    only_in_manual: list[Component] = [c for i, c in enumerate(manual) if i not in consumed]

    only_in_manual.sort(key=_sort_key)
    only_in_syft.sort(key=_sort_key)
    in_both.sort(key=lambda pair: _sort_key(pair[0]))

    return Reconciliation(
        only_in_manual=only_in_manual,
        only_in_syft=only_in_syft,
        in_both=in_both,
    )


def _take(indices: list[int], consumed: set[int]) -> int | None:
    """Return the first index not yet in ``consumed``, marking it consumed."""
    for i in indices:
        if i not in consumed:
            consumed.add(i)
            return i
    return None


def _normalize_purl(purl: str | None) -> str | None:
    """Reduce a package URL to a version-free identity key, or None.

    Lowercases, URL-decodes, and strips the ``#subpath``, ``?qualifiers``,
    and ``@version`` so ``pkg:nuget/CommunityToolkit.Mvvm@8.2.2`` and
    ``pkg:nuget/CommunityToolkit.Mvvm@8.2.2.1%2Babc`` both become
    ``pkg:nuget/communitytoolkit.mvvm``. Returns None for a missing value
    or anything that isn't a ``pkg:`` URL — we don't match on junk.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    head = purl.split("#", 1)[0].split("?", 1)[0].rsplit("@", 1)[0]
    return unquote(head).lower()


def _sort_key(c: Component) -> tuple[str, str]:
    return (c.name.lower(), c.version)
