from pathlib import Path

from click.testing import CliRunner

from sbom_curator.cli import cli
from sbom_curator.lint import LintIssue, LintResult, _read_line, lint

FIXTURES = Path(__file__).parent / "fixtures" / "spdx"


# ----- lint() -----


def test_clean_sbom_has_no_issues() -> None:
    assert lint(FIXTURES / "tagvalue_minimal.spdx").issues == []


def test_noassertion_version_produces_a_line_numbered_error() -> None:
    result = lint(FIXTURES / "noassertion_version.spdx")
    assert len(result.errors) == 1
    assert result.warnings == []
    err = result.errors[0]
    assert err.line == 18
    assert "NOASSERTION" in err.message
    assert "SPDX 2.3" in err.message


def test_unknown_version_is_a_warning() -> None:
    issues = lint(FIXTURES / "affinity_minimal.spdx.json").issues
    messages = [i.message for i in issues if i.severity == "warning"]
    assert any("unknown-version-pkg" in m and "UNKNOWN" in m for m in messages)


def test_missing_version_is_not_a_finding() -> None:
    # A package with no PackageVersion is an explicit curator choice per
    # SPDX 2.3 §7.3 ("absence means unknown"). The entry is silently
    # skipped from ingest/reconcile -- lint must not nag the curator for
    # following spec.
    issues = lint(FIXTURES / "affinity_minimal.spdx.json").issues
    messages = [i.message for i in issues]
    assert not any("no-version-pkg" in m for m in messages)


def test_backslash_name_is_a_warning() -> None:
    issues = lint(FIXTURES / "affinity_minimal.spdx.json").issues
    messages = [i.message for i in issues if i.severity == "warning"]
    assert any("filesystem path" in m for m in messages)


def test_unreadable_path_produces_an_error(tmp_path: Path) -> None:
    bad = tmp_path / "nonsense.spdx.json"
    bad.write_text("{not valid json", encoding="utf-8")
    result = lint(bad)
    assert len(result.errors) == 1
    assert result.warnings == []


def test_read_line_returns_none_when_path_is_unreadable(tmp_path: Path) -> None:
    # Defensive: if the path went away between parse and lint, surface the
    # original error message rather than crashing while trying to enrich it.
    assert _read_line(tmp_path / "vanished.spdx", 1) is None


def test_read_line_returns_none_when_line_number_is_out_of_range(tmp_path: Path) -> None:
    short = tmp_path / "short.spdx"
    short.write_text("only one line\n", encoding="utf-8")
    assert _read_line(short, 99) is None


def test_lint_result_separates_errors_and_warnings() -> None:
    result = LintResult(
        issues=[
            LintIssue("error", "boom"),
            LintIssue("warning", "tilt"),
            LintIssue("warning", "skew"),
        ]
    )
    assert [i.message for i in result.errors] == ["boom"]
    assert [i.message for i in result.warnings] == ["tilt", "skew"]


# ----- CLI -----


def test_lint_cli_exit_zero_when_clean() -> None:
    result = CliRunner().invoke(cli, ["lint", str(FIXTURES / "tagvalue_minimal.spdx")])
    assert result.exit_code == 0, result.output
    assert "[+]" in result.output
    # Rich wraps long lines; strip whitespace to be robust.
    assert "no issues" in " ".join(result.output.split())


def test_lint_cli_exit_two_on_error_with_line_number() -> None:
    result = CliRunner().invoke(
        cli, ["lint", str(FIXTURES / "noassertion_version.spdx")]
    )
    assert result.exit_code == 2
    assert "[-]" in result.output
    assert "line 18" in result.output
    assert "NOASSERTION" in result.output


def test_lint_cli_exit_zero_on_warnings_only() -> None:
    result = CliRunner().invoke(
        cli, ["lint", str(FIXTURES / "affinity_minimal.spdx.json")]
    )
    assert result.exit_code == 0, result.output
    assert "[!]" in result.output
    assert "warning(s)" in result.output


def test_lint_cli_translates_unknown_parse_error_without_line(tmp_path: Path) -> None:
    bad = tmp_path / "garbage.xyz"
    bad.write_text("not an SPDX document at all", encoding="utf-8")
    result = CliRunner().invoke(cli, ["lint", str(bad)])
    assert result.exit_code == 2
    assert "[-]" in result.output
