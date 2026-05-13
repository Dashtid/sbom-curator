"""Preflight an SPDX SBOM before ``ingest``/``reconcile``.

The parser used by ``ingest``/``reconcile`` fails loudly on spec violations
(via spdx-tools) but the message is opaque — a real Affinity 5.0.0 run
greeted the curator with ``Token did not match specified grammar rule.
Line: 196`` for what was a ``PackageVersion: NOASSERTION`` line that SPDX
2.3 §7.3 forbids. ``lint`` re-runs the same parser and translates the few
known failure modes into actionable, line-numbered messages, plus
reports the cases the parser silently skips (``UNKNOWN``-version
packages, backslash-path names) so the curator knows what got dropped.

Errors and warnings are separate: errors block ``ingest``/``reconcile``,
warnings don't. Exit-code policy is the caller's (``cli.lint`` returns 2
on any error and 0 otherwise).
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from spdx_tools.spdx.parser.error import SPDXParsingError

from sbom_curator.parsers.spdx import parse_document

Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class LintIssue:
    severity: Severity
    message: str
    line: int | None = None


@dataclass(frozen=True)
class LintResult:
    issues: list[LintIssue]

    @property
    def errors(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == "warning"]


_LINE_NUMBER = re.compile(r"Line:\s*(\d+)")


def lint(path: Path) -> LintResult:
    """Check ``path`` for known SPDX issues; return errors and warnings."""
    try:
        doc = parse_document(path)
    except SPDXParsingError as exc:
        return LintResult(issues=[_translate_parse_error(path, str(exc))])
    except Exception as exc:  # noqa: BLE001 - spdx-tools raises a variety
        return LintResult(issues=[LintIssue("error", f"{path}: {exc}")])

    issues: list[LintIssue] = []
    for pkg in doc.packages:
        name = pkg.name
        version_obj = pkg.version
        version = "" if version_obj is None else str(version_obj).strip()
        if not version:
            issues.append(LintIssue(
                "warning",
                f"package {name!r}: missing PackageVersion — will be skipped by ingest/reconcile",
            ))
        elif version.upper() in {"UNKNOWN", "NOASSERTION"}:
            issues.append(LintIssue(
                "warning",
                f"package {name!r}: PackageVersion is {version!r} — will be skipped by "
                "ingest/reconcile (use a real version, or omit the field to mean unknown)",
            ))
        if "\\" in name:
            issues.append(LintIssue(
                "warning",
                f"package {name!r}: name looks like a filesystem path — will be skipped "
                "by ingest/reconcile (loose binaries inside vendored source trees are not "
                "packages; scan the deployed install, not the build tree)",
            ))
    return LintResult(issues=issues)


def _translate_parse_error(path: Path, message: str) -> LintIssue:
    """Turn spdx-tools' opaque grammar errors into something actionable."""
    line_match = _LINE_NUMBER.search(message)
    line = int(line_match.group(1)) if line_match else None
    offending = _read_line(path, line) if line is not None else None
    if offending is not None and re.match(
        r"^\s*PackageVersion\s*:\s*NOASSERTION\s*$", offending
    ):
        return LintIssue(
            "error",
            "PackageVersion: NOASSERTION is forbidden by SPDX 2.3 §7.3 — delete the "
            "line (the field is optional; absence means unknown)",
            line=line,
        )
    return LintIssue("error", message.strip(), line=line)


def _read_line(path: Path, line_number: int) -> str | None:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for i, candidate in enumerate(fh, start=1):
                if i == line_number:
                    return candidate.rstrip("\n")
    except OSError:
        return None
    return None
