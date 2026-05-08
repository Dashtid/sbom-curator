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

    Versions that fail to parse fall back to strict string equality. So
    ``"weird-tag" == "weird-tag"`` still holds, but ``"weird-tag-a"``
    does not equal ``"weird-tag-b"``.
    """
    if a == b:
        return True
    try:
        return Version(a) == Version(b)
    except InvalidVersion:
        return False


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
