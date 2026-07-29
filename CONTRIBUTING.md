# Contributing

Thank you for improving `repo-safe`.

## Before opening an issue

- Search existing issues and discussions.
- Use synthetic examples only.
- Never paste a real token, credential, customer record, private path, or proprietary repository content.
- For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development setup

Requirements: Python 3.11 or newer, Git, and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/erkcet/repo-safe.git
cd repo-safe
uv sync --all-groups
```

## Test-driven workflow

Every behavior change must follow RED → GREEN → REFACTOR:

1. Add one focused test.
2. Run that test and confirm it fails for the expected reason.
3. Add the smallest implementation that makes it pass.
4. Run the focused test and full suite.
5. Refactor only while the suite remains green.

## Quality gate

Run before submitting:

```bash
uv run pytest --cov=repo_safe --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy src/repo_safe
uv run pip-audit
uv build --clear
uv run twine check dist/*
gitleaks dir . --redact
actionlint
```

Coverage must remain at or above 90%. Tests must not contain active credentials; use unmistakably synthetic values.

## Pull requests

- Keep changes focused and small.
- Explain the threat or user problem being addressed.
- Document safety trade-offs and failure behavior.
- Add tests for success, failure, and boundary cases.
- Update the README, security model, limitations, or changelog when behavior changes.
- Use Conventional Commit-style titles, for example `fix: reject duplicate manifest paths`.

By contributing, you agree that your contribution is licensed under the MIT License.

Maintainers should follow the [release checklist](docs/releasing.md) rather than publishing artifacts manually.
