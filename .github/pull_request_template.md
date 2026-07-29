## Problem

<!-- What user problem or safety gap does this solve? -->

## Changes

<!-- Keep this focused. -->

## Security impact

<!-- Explain input trust, redaction, path, symlink, race, and fail-closed implications. -->

## Verification

- [ ] A focused test failed before the implementation and passes now.
- [ ] `uv run pytest --cov=repo_safe --cov-report=term-missing`
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run mypy src/repo_safe`
- [ ] `uv build && uv run twine check dist/*`
- [ ] Documentation and changelog updated when behavior changed.
- [ ] Fixtures contain only synthetic values.
