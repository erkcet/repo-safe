# Synthetic demonstration project

This directory contains no active credentials. It exists only to demonstrate redaction.

From a source checkout:

```bash
# Exit 1 is expected: the synthetic fixture contains one secret-like value.
uv run repo-safe scan examples/demo || test $? -eq 1

demo_root="$(mktemp -d)"
uv run repo-safe sanitize examples/demo "$demo_root/snapshot"
uv run repo-safe verify "$demo_root/snapshot"
```

The sanitized `settings.json` replaces the synthetic credential-like value with `[REDACTED]`. Inspect both the snapshot and `.repo-safe-manifest.json` before sharing any real output.
