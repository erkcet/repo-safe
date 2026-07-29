# Security policy

## Supported versions

The latest tagged release receives security fixes. During the `0.x` series, upgrade to the newest release before reporting a problem.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub's **Report a vulnerability** form in the repository Security tab. Include:

- the affected version;
- operating system and Python version;
- a minimal synthetic reproduction;
- the expected and actual behavior;
- whether a secret value, source file, or path escaped the documented boundary.

Never include a real credential, customer record, private repository, or production path. Replace all sensitive material with synthetic examples.

You should receive an acknowledgement within seven days. Confirmed issues will be coordinated privately until a fix and advisory are ready.

## Security boundary

`repo-safe` treats source trees and manifests as hostile. It does not execute source files, import project modules, invoke shells, or perform network calls. The supported output is a text-only snapshot.

The complete assumptions and guarantees are documented in [docs/security-model.md](docs/security-model.md). Known detection limits are documented in [docs/limitations.md](docs/limitations.md).

## Release security checklist

A release is not ready unless all of the following hold:

- [ ] Linux, macOS, and Windows tests pass on every supported Python version in CI.
- [ ] Source mutation, destination containment, overwrite refusal, and write-free dry-run tests pass.
- [ ] Symlink, junction-aware traversal, hard-link, traversal, duplicate-manifest, and untracked-file tests pass.
- [ ] Synthetic canary values never appear in reports, manifests, CLI output, or sanitized files.
- [ ] Binary, malformed, oversized, and over-count input fails closed or is explicitly skipped.
- [ ] An interrupted sanitize operation leaves no published partial destination.
- [ ] `ruff`, strict `mypy`, branch-aware coverage, `pip-audit`, wheel installation, and CodeQL pass.
- [ ] Built distributions pass `twine check` and are produced from the tagged commit.
- [ ] Release notes restate detection limits and recommend independent scanning before publication.
