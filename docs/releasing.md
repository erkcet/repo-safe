# Maintainer release checklist

`repo-safe` v0.x releases are published on GitHub only. PyPI and Homebrew are not release targets yet.

## Before tagging

1. Work from a clean `main` branch whose required GitHub checks are green.
2. Update `project.version` in `pyproject.toml`, refresh `uv.lock`, and move release notes from **Unreleased** to the dated version in `CHANGELOG.md`.
3. Run the complete local gate:

   ```bash
   uv lock --check
   uv sync --locked --all-groups
   uv run ruff check .
   uv run ruff format --check .
   uv run mypy src/repo_safe
   for py in 3.11 3.12 3.13 3.14; do uv run --python "$py" pytest -q; done
   uv run --python 3.11 pytest --cov=repo_safe --cov-branch --cov-report=term-missing -q
   uv run pip-audit
   uvx codespell README.md SECURITY.md CONTRIBUTING.md CHANGELOG.md docs src tests .github examples
   uv build --clear
   uv run twine check dist/*
   gitleaks dir . --redact
   actionlint
   ```

4. Install the wheel into a fresh environment and exercise `scan`, `sanitize`, and `verify` with synthetic data.
5. Commit and push. Wait for CI and CodeQL on that exact commit.

## Publish

Create and push an annotated tag matching the package version:

```bash
git tag -a v0.1.0 -m "repo-safe v0.1.0"
git push origin v0.1.0
```

The release workflow repeats the blocking checks, builds from the tag, smoke-tests the wheel, creates SHA-256 checksums and build provenance attestations, then publishes a GitHub release. The write-capable job receives only the artifact produced by the read-only build job.

## Verify

- Confirm every release workflow job is green.
- Download the released wheel and compare it with `SHA256SUMS`.
- Install from the GitHub tag in a fresh environment.
- Confirm the release page, changelog link, security policy, and private vulnerability reporting are available.

## Recovery

Do not silently replace artifacts attached to an existing release. If the release is defective, mark it as a pre-release, explain the issue, and publish a patch version. Delete a tag/release only when publication itself was accidental and no user could reasonably have consumed it; document that action publicly.
