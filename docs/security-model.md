# Security model

`repo-safe` creates a new, text-only working-tree snapshot. It does not rewrite Git history and does not claim to prove that arbitrary text contains no confidential information.

## Assets

The tool protects:

1. the source tree from mutation;
2. detected secret values from disclosure in reports and manifests;
3. the destination boundary from traversal or symlink escape;
4. snapshot integrity after creation.

## Trust boundaries

The following are treated as untrusted:

- every source-tree path and file;
- file contents and encodings;
- symlinks and special files;
- destination manifests supplied to `verify`;
- custom exclusion globs.

The installed `repo-safe` package, Python runtime, operating system kernel, destination parent directory, and exclusive access to the source during a run are trusted. A malicious or same-user process that mutates source paths concurrently is outside the threat model. A process that can modify both a published snapshot and its colocated manifest can also replace both; the manifest detects accidental corruption and uncoordinated changes, not hostile authenticity.

## Guarantees

### Source immutability

The source is opened read-only. `repo-safe` never renames, deletes, chmods, formats, or writes a source path.

### Destination isolation

The destination must not exist and must be outside the source. Work is created in a temporary sibling directory and renamed into place only after the manifest is complete. A failed operation removes the temporary tree. This gives all-or-nothing visibility under the trusted-parent assumption; it is not a crash-durability or hostile concurrent-writer guarantee.

### File-type boundary

Only regular UTF-8 text files within the configured size and count limits are eligible. Symlinks, junctions, multiply linked files, sockets, devices, FIFOs, binary data, undecodable text, and configured sensitive files are skipped.

Files are opened with `O_NOFOLLOW` when the platform supports it. The pre-open and post-open device/inode identity and regular-file mode are compared. Reads are bounded even if a file grows after opening.

### Value-safe reporting

Findings contain only:

- relative POSIX path;
- line number;
- detector type.

Reports and manifests do not contain matched values, snippets, timestamps, or absolute source/destination paths. Relative filenames are retained as review metadata and are not anonymized; do not put credentials, personal data, or terminal control characters in filenames.

### Redaction

The sanitizer uses layered detection:

1. sensitive assignment names in line-oriented formats;
2. all populated assignments in `.env*` files;
3. recursive sensitive-key traversal for JSON;
4. recursive sensitive-key traversal for XML property lists;
5. known high-signal token, URL-credential, and complete PEM private-key shapes embedded in text.

Replacement text is `[REDACTED]`, with `[REDACTED PRIVATE KEY]` used for complete PEM blocks.

### Integrity

The manifest stores a SHA-256 digest for each output file. `verify` validates the full schema, rejects unsafe and duplicate paths, requires every tracked entry to remain bounded UTF-8 text, checks every digest, rejects missing, untracked, linked, binary, and special files, and performs a fresh pass with the built-in detector. Because the manifest is colocated with the snapshot, hashes detect accidental corruption; they are not a signature or authenticity proof.

## Deliberately fail-closed behavior

Data is skipped—not copied unchanged—when it cannot be decoded, safely opened, bounded, or structurally parsed with confidence. Malformed JSON, property lists, and incomplete private-key blocks are excluded because safe redaction boundaries cannot be established.

## Threats addressed

| Threat | Mitigation |
|---|---|
| Secret in common config assignment | Key-based redaction and verification rescan |
| Secret in nested JSON/plist | Structured recursive redaction |
| Known token embedded in prose | High-signal token-shape replacement |
| Secret in `.env` under an unusual name | Redact every populated assignment |
| Source symlink escapes repository | Skip symlinks and no-follow opens |
| Final file replaced between check and open | No-follow leaf open plus descriptor identity comparison |
| Manifest traversal, drive, alias, or unsafe component | Canonical portable relative-path validation |
| Duplicate manifest entries | Explicit duplicate rejection |
| Binary or huge-file evasion | Text-only boundary and hard size limits |
| Partial destination after failure | Temporary sibling plus atomic rename |
| Snapshot modified after creation | Hash, untracked-file, and rescan verification |
| Report leaks matched value | Findings never retain snippets or values |

## Threats not addressed

- secrets expressed as arbitrary prose;
- steganography, images, archives, databases, office documents, or other binary formats;
- encrypted or encoded values without a detectable key or token shape;
- malicious kernel/filesystem behavior;
- a privileged or same-user attacker modifying source and output during execution;
- hostile replacement of both a snapshot file and its colocated manifest;
- crash durability, power-loss persistence, or a hostile writer racing destination publication;
- secrets or personal data embedded in relative filenames;
- sensitive Git history, reflogs, submodules, or Git LFS objects;
- policy decisions about whether non-secret business information is publishable.

See [limitations.md](limitations.md) for operational guidance.
