"""Turn a reconciliation into a curator-actionable edit plan.

`reconcile` answers "how do these two SBOMs differ?". `ingest` answers
the next question — "what should I change in the manual SBOM?" — by
relabelling the reconciler's four buckets as verbs:

- **PRESERVE** — manual lists it, Syft can't see it. Vendored or
  statically linked; leave it alone.
- **ADD** — Syft saw it, manual doesn't list it. Candidate addition.
- **BUMP** — manual has it at an older version. Update the version.
- **KEEP** — already in agreement. No action — unless the license
  drifted, which is carried as an annotation on the action.

No new matching logic lives here: `plan()` calls `reconcile()` and
partitions its `in_both` bucket on PEP 440 version equivalence, so the
two commands share one source of truth.

`plan()` does not rewrite the manual SBOM. The curator reads the plan
and edits by hand; an `--apply` mode, if it ever lands, stays opt-in.
"""

from dataclasses import dataclass

from sbom_curator.parsers.model import Component
from sbom_curator.reconcile.diff import reconcile
from sbom_curator.reconcile.equivalence import licenses_equal, versions_equal


@dataclass(frozen=True)
class BumpAction:
    """Manual lists this component at a version Syft superseded."""

    manual: Component
    syft: Component

    @property
    def license_drift(self) -> bool:
        return not licenses_equal(self.manual.license, self.syft.license)


@dataclass(frozen=True)
class AddAction:
    """Syft saw this component; the manual SBOM does not list it."""

    syft: Component


@dataclass(frozen=True)
class KeepAction:
    """Manual and Syft agree on version. No action — unless license drifted."""

    manual: Component
    syft: Component

    @property
    def license_drift(self) -> bool:
        return not licenses_equal(self.manual.license, self.syft.license)


@dataclass(frozen=True)
class PreserveAction:
    """Manual lists this component; Syft cannot see it (vendored/static)."""

    manual: Component


@dataclass(frozen=True)
class EditPlan:
    """The curator's TODO list, derived from a reconciliation.

    Ordering inside each list is the reconciler's deterministic
    ``(name.lower(), version)`` so the rendered plan diffs cleanly
    run-to-run.
    """

    bumps: list[BumpAction]
    adds: list[AddAction]
    keeps: list[KeepAction]
    preserves: list[PreserveAction]

    @property
    def keeps_with_license_drift(self) -> list[KeepAction]:
        return [k for k in self.keeps if k.license_drift]


def plan(manual: list[Component], syft: list[Component]) -> EditPlan:
    """Build an edit plan by relabelling a reconciliation's buckets.

    ``in_both`` pairs split on :func:`versions_equal`: equal versions
    become :class:`KeepAction`, unequal become :class:`BumpAction`.
    ``only_in_syft`` becomes :class:`AddAction`; ``only_in_manual``
    becomes :class:`PreserveAction`.
    """
    r = reconcile(manual, syft)
    bumps = [BumpAction(manual=m, syft=s) for m, s in r.in_both
             if not versions_equal(m.version, s.version)]
    keeps = [KeepAction(manual=m, syft=s) for m, s in r.in_both
             if versions_equal(m.version, s.version)]
    adds = [AddAction(syft=c) for c in r.only_in_syft]
    preserves = [PreserveAction(manual=c) for c in r.only_in_manual]
    return EditPlan(bumps=bumps, adds=adds, keeps=keeps, preserves=preserves)
