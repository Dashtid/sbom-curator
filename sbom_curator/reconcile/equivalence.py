"""Loose equivalence checks for version and license strings.

Strict string equality is the cheap path everywhere — when it succeeds we
skip parsing entirely. The loose paths exist to suppress false-positive
disagreements that would otherwise drown a triage report in noise.

Both helpers fall back to strict string equality on parse failure so a
malformed version or license expression cannot make a real disagreement
disappear.
"""

from license_expression import ExpressionError, get_spdx_licensing
from packaging.version import InvalidVersion, Version

_licensing = get_spdx_licensing()


def versions_equal(a: str, b: str) -> bool:
    """Return True if two version strings refer to the same release.

    PEP 440 equivalence: ``1.0 == 1.0.0``, ``1.0.0 == 1.0.0.0``, but
    ``1.0.0 != 1.0.0+local`` because PEP 440 treats local segments as
    distinguishing. This is correct for SBOM use — a build with extra
    metadata is technically a different artifact.

    Also accepts the **NuGet semver ↔ .NET assembly-version** pattern: a
    3-component release ``X.Y.Z`` paired with the 4-component assembly
    version ``X.Y.Z.<revision>`` (e.g. NuGet ``4.4.1`` and the assembly
    ``4.4.1.57983`` of the same release). Restricted to the (3, 4)
    length pair so unrelated patches don't quietly match.

    Versions that fail to parse fall back to strict string equality. So
    ``"weird-tag" == "weird-tag"`` still holds, but ``"weird-tag-a"``
    does not equal ``"weird-tag-b"``.
    """
    if a == b:
        return True
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return False
    if va == vb:
        return True
    return _dotnet_assembly_revision_match(va.release, vb.release)


def _dotnet_assembly_revision_match(
    a: tuple[int, ...], b: tuple[int, ...]
) -> bool:
    """NuGet ``X.Y.Z`` ↔ .NET assembly ``X.Y.Z.<revision>`` — same release."""
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    if (len(short), len(long_)) != (3, 4):
        return False
    return long_[:3] == short


def licenses_equal(a: str | None, b: str | None) -> bool:
    """Return True if two SPDX license expression strings are equivalent.

    Handles ``OR``/``AND`` commutativity: ``Apache-2.0 OR MIT`` equals
    ``MIT OR Apache-2.0``. Also handles redundancy and associativity via
    ``license_expression.simplify()``.

    ``None`` on both sides counts as agreement; one ``None`` and one set
    string counts as disagreement. Expressions that fail to parse fall
    back to strict string equality.
    """
    if a == b:
        return True
    if a is None or b is None:
        return False
    try:
        return bool(_licensing.parse(a).simplify() == _licensing.parse(b).simplify())
    except ExpressionError:
        return False
