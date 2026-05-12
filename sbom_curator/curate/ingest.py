"""Turn a reconciliation into a per-scan change report.

`reconcile` answers "how do these two SBOMs differ?". `ingest` answers
the curator's question — "what changed in the latest scan, relative to
the SBOM I maintain?" — by relabelling the reconciler's buckets:

- **ADDED**  — the scan lists it; your SBOM doesn't. Consider adding it.
- **BUMPED** — both list it, at different versions. Consider updating.
- **REVIEW** — your SBOM lists it; the scan doesn't list anything by
  that name. Could be (a) something the scanner can't see (vendored or
  statically linked — fine, leave it), (b) the scan listing it under a
  different name (a known gap — see the .NET notes in BACKLOG.md), or
  (c) something genuinely gone (then remove it).
- **KEEP**   — both list it at the same version. No change — unless the
  *license* changed, which is carried as an annotation.

No new matching logic lives here: `plan()` calls `reconcile()` and
partitions its `in_both` bucket on PEP 440 version equivalence, so the
two commands share one source of truth.

`plan()` does not rewrite the manual SBOM. The curator reads the report
and edits by hand; an `--apply` mode, if it ever lands, stays opt-in.
"""

from dataclasses import dataclass

from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import reconcile
from sbom_curator.reconcile.equivalence import licenses_equal, versions_equal


def _license_changed(a: Component, b: Component) -> bool:
    """True only when *both* records carry a license and they differ.

    "You say MIT, the scan says nothing" is not a change — the scanner
    just has no opinion — so a missing license on either side is not a
    finding. "You say MIT, the scan says Apache-2.0" is.
    """
    return a.license is not None and b.license is not None and not licenses_equal(
        a.license, b.license
    )


@dataclass(frozen=True)
class BumpAction:
    """Both SBOMs list this component, at different versions."""

    manual: Component
    syft: Component

    @property
    def license_changed(self) -> bool:
        return _license_changed(self.manual, self.syft)


@dataclass(frozen=True)
class AddAction:
    """The scan lists this component; the manual SBOM does not."""

    syft: Component


@dataclass(frozen=True)
class KeepAction:
    """Both SBOMs list this component at the same version."""

    manual: Component
    syft: Component

    @property
    def license_changed(self) -> bool:
        return _license_changed(self.manual, self.syft)


@dataclass(frozen=True)
class ReviewAction:
    """The manual SBOM lists this component; the scan lists nothing by that name."""

    manual: Component


@dataclass(frozen=True)
class EditPlan:
    """The per-scan change report, derived from a reconciliation.

    Ordering inside each list is the reconciler's deterministic
    ``(name.lower(), version)`` so the rendered report diffs cleanly
    run-to-run.
    """

    added: list[AddAction]
    bumped: list[BumpAction]
    reviews: list[ReviewAction]
    keeps: list[KeepAction]

    @property
    def keeps_with_license_change(self) -> list[KeepAction]:
        return [k for k in self.keeps if k.license_changed]


def plan(manual: list[Component], syft: list[Component]) -> EditPlan:
    """Build a change report by relabelling a reconciliation's buckets.

    ``in_both`` pairs split on :func:`versions_equal`: equal versions
    become :class:`KeepAction`, unequal become :class:`BumpAction`.
    ``only_in_syft`` becomes :class:`AddAction`; ``only_in_manual``
    becomes :class:`ReviewAction`.
    """
    r = reconcile(manual, syft)
    bumped = [BumpAction(manual=m, syft=s) for m, s in r.in_both
              if not versions_equal(m.version, s.version)]
    keeps = [KeepAction(manual=m, syft=s) for m, s in r.in_both
             if versions_equal(m.version, s.version)]
    added = [AddAction(syft=c) for c in r.only_in_syft]
    reviews = [ReviewAction(manual=c) for c in r.only_in_manual]
    return EditPlan(added=added, bumped=bumped, reviews=reviews, keeps=keeps)
