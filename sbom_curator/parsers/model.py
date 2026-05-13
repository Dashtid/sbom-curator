from dataclasses import dataclass
from typing import Literal

Source = Literal["manual", "syft"]


@dataclass(frozen=True)
class Component:
    """Normalized component record used by the reconcile stage.

    name and version are required; everything else is best-effort. The source
    field tracks which input the component came from so the reconciler can
    group findings.
    """

    name: str
    version: str
    source: Source
    purl: str | None = None
    license: str | None = None
    covers_prefixes: tuple[str, ...] = ()
    """Name prefixes this manual entry declares it covers. Populated from a
    ``sbom-curator covers-prefix: <PREFIX>`` line in the package's
    ``PackageComment``; only set for ``source == "manual"`` components, and
    used by the reconciler's prefix-coverage pass."""
