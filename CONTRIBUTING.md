# Contributing

## Quality bar

- `ruff check .` clean (rules E, F, I, UP, B, S, SIM)
- `mypy sbom_curator` strict, clean
- `pytest --cov=sbom_curator --cov-branch` 100% line + branch coverage
- `bandit -c pyproject.toml -r sbom_curator` clean

The bar mirrors `sbom-sentinel`. Coverage gate ratchets up; do not lower it.

## Workflow

- Branch from `main`, open a PR, let CI run.
- Merge with a merge commit (no squash, no rebase). Conventional-ish commit messages (`feat:`, `fix:`, `docs:`, ...).
- Don't add features beyond the task. Three similar lines is better than a
  premature abstraction.

## Output format

ASCII only in user-facing strings: `[+]`, `[-]`, `[!]`, `[i]`. No emojis.
