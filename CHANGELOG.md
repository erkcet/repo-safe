# Changelog

All notable changes are documented in this file. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-07-29

### Added

- Value-safe scanning for sensitive assignments, URL credentials, and common token shapes.
- Complete PEM private-key block redaction with fail-closed handling of incomplete blocks.
- Atomic, text-only snapshot creation with safe default exclusions.
- Recursive JSON and XML property-list redaction.
- Fail-closed `.env*` redaction.
- Deterministic SHA-256 manifest without host or source metadata.
- Snapshot verification for complete schema, integrity, portable paths, duplicate aliases, untracked, linked, binary, special-file, and residual-secret failures.
- Per-directory, depth, entry, file-size, and total-byte resource bounds.
- Human-readable and JSON CLI output with stable exit codes and a write-free `--dry-run`.
- Race-resistant, no-follow regular-file reads with hard-link, symlink, and junction rejection.
- Cross-platform home-directory path anonymization.
- Cross-platform tests, linting, strict typing, coverage, build, and CodeQL workflows.

[Unreleased]: https://github.com/erkcet/repo-safe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/erkcet/repo-safe/releases/tag/v0.1.0
