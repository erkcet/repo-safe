# repo-safe

[![CI](https://github.com/erkcet/repo-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/erkcet/repo-safe/actions/workflows/ci.yml)
[![CodeQL](https://github.com/erkcet/repo-safe/actions/workflows/codeql.yml/badge.svg)](https://github.com/erkcet/repo-safe/actions/workflows/codeql.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Create a text-only repository snapshot that excludes unsafe files and redacts supported secret patterns. Always review before publishing.

```console
$ repo-safe sanitize ./my-project ./my-project-safe
CREATED: 42 file(s), 7 value(s) redacted, 1,304 skipped.

$ repo-safe verify ./my-project-safe
VERIFIED: 42 file(s) verified.
```

`repo-safe` is intentionally small, dependency-free at runtime, local-only, and fail-closed around files it cannot safely inspect.

## Why

Developers frequently need a sanitized snapshot for:

- a private backup repository;
- a reproducible bug report;
- a code-review example;
- migration or disaster-recovery documentation;
- sharing a configuration layout without sharing credentials.

A `.gitignore` prevents future commits. It does not sanitize an existing directory, inspect values inside configuration files, reject symlinks, or prove that the resulting copy has not changed. `repo-safe` does those jobs without rewriting the source.

## Safety properties

- Never modifies the source tree.
- Refuses destinations inside the source tree.
- Refuses to overwrite an existing destination.
- Builds in a temporary sibling directory and publishes with one atomic rename.
- Never follows symlinks or Windows junctions; multiply linked files are rejected.
- Reads regular files through a race-resistant, no-follow file descriptor.
- Skips binary, oversized, malformed structured, private-key, credential, VCS, dependency, cache, and virtual-environment files by default.
- Redacts sensitive assignments and known GitHub, AWS, Slack, URL-credential, and complete PEM private-key shapes.
- Recursively redacts sensitive keys in JSON and XML property lists.
- Redacts every non-placeholder assignment in `.env*` files.
- Anonymizes common macOS, Linux, and Windows home-directory paths.
- Produces a deterministic manifest containing relative paths, redaction counts, and SHA-256 hashes—never secret values or absolute source paths.
- Verifies hashes, manifest paths, untracked files, symlinks, and remaining detectable secrets.
- Performs no network calls and executes no project code.

Read the complete [security model](docs/security-model.md) and [limitations](docs/limitations.md) before relying on a snapshot.

## Installation

### Isolated installation with `pipx`

Install the tagged release directly from GitHub:

```bash
pipx install 'git+https://github.com/erkcet/repo-safe.git@v0.1.0'
```

### Run without a permanent installation

```bash
uvx --from 'git+https://github.com/erkcet/repo-safe.git@v0.1.0' repo-safe --help
```

### Development installation

```bash
git clone https://github.com/erkcet/repo-safe.git
cd repo-safe
uv sync --all-groups
uv run repo-safe --help
```

## Usage

### Scan without exposing values

```bash
repo-safe scan ./my-project
repo-safe scan ./my-project --json
```

A scan reports only the relative path, finding type, and a line number for line-oriented detectors. Document-level JSON and plist findings use line `1`. It never includes the matched value.

### Create a sanitized snapshot

```bash
repo-safe sanitize ./my-project ./my-project-safe
```

Add project-specific exclusions with repeatable path globs:

```bash
repo-safe sanitize ./my-project ./safe \
  --exclude 'fixtures/private/**' \
  --exclude '*.generated.log'
```

Bound untrusted input:

```bash
repo-safe sanitize ./my-project ./safe \
  --max-files 5000 \
  --max-file-bytes 2097152 \
  --max-total-bytes 268435456
```

For `sanitize`, file-size and aggregate-byte limits apply independently to inspected input and generated output. A transformed file that expands beyond the per-file limit is skipped; aggregate output expansion aborts atomically.

Machine-readable output:

```bash
repo-safe sanitize ./my-project ./safe --json
```

Preview the same bounded work and counter summary without creating the destination or its parent:

```bash
repo-safe sanitize ./my-project ./safe --dry-run
```

### Verify a snapshot

```bash
repo-safe verify ./my-project-safe
repo-safe verify ./my-project-safe --json
```

Verification checks:

1. manifest schema and path safety;
2. duplicate or invalid entries;
3. SHA-256 integrity for every tracked file;
4. missing, untracked, linked, binary, or special files;
5. a fresh pass with the same documented built-in detectors.

The colocated hashes detect accidental corruption; they are not a signature or proof against an attacker who can replace both files and manifest.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Operation succeeded; scan is clean or snapshot verified. |
| `1` | Scan found secret-like values or verification failed. |
| `2` | Invalid input, unsafe path, limit violation, or filesystem error. |

## What is excluded by default

Directories include `.git`, `.hg`, `.svn`, `.venv`, `node_modules`, `__pycache__`, and common test/lint caches.

Files include SSH private-key names, `.netrc`, `credentials.json`, and `.key`, `.pem`, `.p12`, and `.pfx` suffixes. Built-in sensitive names, directory names, suffixes, `.env*` recognition, and custom exclusion matching use case-insensitive, Unicode-normalized portable identities for consistent behavior across supported filesystems. Binary or undecodable files and text files over 5 MiB are skipped.

Skipped files are counted but not copied. This is a security tool, so uninspectable data is excluded rather than trusted.

## Supported redaction

- `KEY=value`, `KEY: value`, `export KEY=value`, INI, TOML, and common YAML assignments;
- all populated assignments in `.env*` files;
- nested JSON keys such as `apiKey`, `client_secret`, `password`, and `token`;
- nested XML property-list keys;
- GitHub classic and fine-grained tokens, AWS access keys, Slack tokens, URL user-info credentials, and complete PEM private-key blocks embedded in text;
- `/Users/<name>`, `/home/<name>`, and `C:\\Users\\<name>` home paths.

Values that clearly look like placeholders—such as `[REDACTED]`, `${TOKEN}`, `changeme`, or `your-value-here`—are not reported.

## Manifest

Every successful snapshot contains `.repo-safe-manifest.json`:

```json
{
  "files": [
    {
      "path": "config/settings.json",
      "redactions": 2,
      "sha256": "..."
    }
  ],
  "schema_version": 1,
  "summary": {
    "files_skipped": 4,
    "files_written": 18,
    "values_redacted": 3
  }
}
```

The manifest is intentionally reproducible: it has no timestamp, hostname, username, or absolute path.

## Non-goals

`repo-safe` is not:

- a replacement for Gitleaks, TruffleHog, or GitHub secret scanning;
- a Git-history rewriting tool;
- a binary-document sanitizer;
- a guarantee that arbitrary human prose contains no sensitive information;
- a reason to publish a snapshot without reviewing it.

For high-assurance publication, run `repo-safe verify`, inspect the output, and then run an independent secret scanner.

## Development

```bash
uv sync --all-groups
uv run pytest --cov=repo_safe --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy src/repo_safe
uv build
```

The project requires at least 90% branch-aware test coverage. New behavior follows test-driven development.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow.

## Documentation

- [Security model](docs/security-model.md)
- [Limitations and safe use](docs/limitations.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Maintainer release checklist](docs/releasing.md)
- [Security reporting policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 Erkan Çetinkaya
