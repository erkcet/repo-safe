# Troubleshooting

## `scan` exits with status 1

That is the documented result when findings exist, not an internal crash. Use `--json` to inspect value-safe metadata:

```bash
repo-safe scan ./project --json
```

## A file is missing from the snapshot

`repo-safe` intentionally skips content it cannot safely inspect, including:

- binary or non-UTF-8 files;
- files above `--max-file-bytes`;
- symlinks, Windows junctions, multiply linked files, and special files;
- private keys, credentials files, VCS metadata, dependencies, caches, and virtual environments;
- paths matched by `--exclude`.

The summary reports the number skipped, but the v0.1 manifest intentionally avoids recording source-only filenames for excluded sensitive files.

## The destination already exists

Sanitization never merges into or overwrites an existing destination. Choose a new path, inspect and remove the old snapshot yourself, or rename it before running again.

## The destination is inside the source

Use a sibling path. This is rejected to prevent recursive copying and accidental source mutation:

```bash
repo-safe sanitize ./project ../project-safe
```

## `verify` reports an untracked file

The snapshot changed after its manifest was created. Create a fresh snapshot rather than editing it in place.

## `verify` reports a hash mismatch

A tracked file changed or became unreadable. Treat the snapshot as unverified and recreate it from the source.

## A known secret was not detected

Do not publish the snapshot. `repo-safe` uses bounded, offline heuristics and cannot recognize every secret format. See [limitations.md](limitations.md), rotate any exposed credential, and report a synthetic reproduction through the appropriate issue or private security channel.

Run an independent scanner as a second opinion:

```bash
gitleaks dir ./safe-snapshot --no-banner
```

## CI reports that `repo-safe` cannot be audited on PyPI

The package has no runtime dependencies. Before a PyPI publication exists, `pip-audit` may state that the local `repo-safe` distribution itself cannot be found while still reporting `No known vulnerabilities found` for installed third-party dependencies.
