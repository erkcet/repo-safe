# Limitations and safe use

No secret scanner can prove that arbitrary data is safe to publish. `repo-safe` reduces common accidental-disclosure risks and makes its result verifiable; it does not replace human review or an independent scanner.

## Working tree only

The tool snapshots visible files in a directory. It does not copy or sanitize `.git`, commits, tags, reflogs, submodules, or Git LFS object stores. Never push an existing Git history merely because its current working tree looks clean.

## Text only

Binary and undecodable files are skipped. This includes images, archives, SQLite databases, compiled artifacts, most office documents, and binary property lists. A skipped file is not evidence that the file is unsafe; it means `repo-safe` cannot establish that it is safe.

## Detection is intentionally finite

The built-in detector targets sensitive key names and selected high-signal token formats. It can miss:

- a credential under an unrelated key such as `value`;
- a token split across lines or assembled at runtime;
- base64, encrypted, compressed, or custom-encoded data;
- passwords in comments, prose, fixtures, or source literals without a sensitive context;
- personally identifiable or commercially confidential text that is not a credential.

It can also report synthetic test values. Prefer explicit placeholders such as `[REDACTED]`, `${TOKEN}`, or `your-value-here` in public examples.

## Structured formats

JSON and XML property lists are parsed and deterministically reserialized, so formatting and key order may change. Malformed structured files are excluded rather than copied because safe redaction boundaries cannot be established. Common YAML, TOML, INI, shell, and `.env` assignments are handled line by line. Complex multiline values, anchors, custom tags, heredocs, and unusual quoting may require manual review.

## Permissions and metadata

Snapshots contain file content and directory structure. They do not preserve ownership, ACLs, extended attributes, timestamps, executable bits, hard links, or sparse-file metadata. The output is a shareable content snapshot, not a forensic or byte-for-byte backup.

## Filenames and integrity scope

Relative filenames are preserved in findings and the manifest. They are review metadata, not secret-anonymized content; avoid sensitive names and control characters. SHA-256 values are stored beside the snapshot, so they detect accidental corruption and uncoordinated edits—not an attacker who can rewrite both content and manifest.

## Recommended publication workflow

```bash
repo-safe scan ./source
repo-safe sanitize ./source ./snapshot
repo-safe verify ./snapshot
gitleaks dir ./snapshot
```

Then:

1. review the manifest and skipped-file count;
2. inspect the snapshot as a separate tree;
3. search for organization-specific names, customer data, paths, and identifiers;
4. initialize a brand-new Git repository inside the snapshot;
5. publish only after that review.

Never add a remote or push automatically from the source repository. `repo-safe` intentionally has no `push` command.
