"""Create intentionally lossy sanitized repository snapshots."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from .models import SanitizeReport
from .policy import is_excluded, is_portable_relative_path
from .safeio import collect_tree, is_link_like, read_regular_file
from .scanner import StructuredDataError, redact_json_text, redact_plist_text, redact_text

_MANIFEST_NAME = ".repo-safe-manifest.json"


def sanitize_tree(
    source: Path,
    destination: Path,
    *,
    max_files: int = 10_000,
    max_file_bytes: int = 5 * 1024 * 1024,
    max_total_bytes: int = 512 * 1024 * 1024,
    exclude: tuple[str, ...] = (),
    dry_run: bool = False,
) -> SanitizeReport:
    """Create an atomic, text-only snapshot with secret-like values redacted."""

    source = source.resolve(strict=True)
    destination = destination.resolve(strict=False)
    if not source.is_dir():
        raise ValueError("source must be a directory")
    if destination == source or source in destination.parents:
        raise ValueError("destination must be outside the source tree")
    if destination.exists():
        raise FileExistsError(f"destination already exists: {destination}")
    if max_files < 1 or max_file_bytes < 1 or max_total_bytes < 1:
        raise ValueError("safety limits must be positive")

    paths = collect_tree(
        source,
        max_entries=max_files,
        should_prune=lambda path: (
            not is_portable_relative_path(path.relative_to(source).as_posix())
            or is_excluded(path.relative_to(source), exclude)
        ),
    )

    temporary: Path | None = None
    if not dry_run:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.repo-safe-", dir=destination.parent)
        )
    report = SanitizeReport()
    manifest_files: list[dict[str, object]] = []
    total_bytes = 0
    total_output_bytes = 0
    try:
        for path in paths:
            relative = path.relative_to(source)
            if is_link_like(path):
                report.files_skipped += 1
                continue
            if not is_portable_relative_path(relative.as_posix()) or is_excluded(relative, exclude):
                report.files_skipped += 1
                continue
            if not path.is_file():
                continue
            try:
                raw = read_regular_file(path, max_bytes=max_file_bytes)
                total_bytes += len(raw)
                if total_bytes > max_total_bytes:
                    raise ValueError("total byte limit exceeded")
                if b"\x00" in raw:
                    raise UnicodeDecodeError("utf-8", raw, 0, 1, "unsafe text input")
                content = raw.decode("utf-8")
            except (UnicodeDecodeError, OSError):
                report.files_skipped += 1
                continue
            if relative.suffix.casefold() == ".json":
                try:
                    redacted, redactions = redact_json_text(content)
                except StructuredDataError:
                    report.files_skipped += 1
                    continue
            elif relative.suffix.casefold() == ".plist":
                try:
                    redacted, redactions = redact_plist_text(content)
                except StructuredDataError:
                    report.files_skipped += 1
                    continue
            else:
                try:
                    redacted, redactions = redact_text(
                        content,
                        redact_all_assignments=relative.name.casefold().startswith(".env"),
                    )
                except StructuredDataError:
                    report.files_skipped += 1
                    continue
            output_bytes = redacted.encode("utf-8")
            if len(output_bytes) > max_file_bytes:
                report.files_skipped += 1
                continue
            total_output_bytes += len(output_bytes)
            if total_output_bytes > max_total_bytes:
                raise ValueError("total output byte limit exceeded")
            if temporary is not None:
                output_path = temporary / relative
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(output_bytes)
            report.files_written += 1
            report.values_redacted += redactions
            manifest_files.append(
                {
                    "path": relative.as_posix(),
                    "redactions": redactions,
                    "sha256": hashlib.sha256(output_bytes).hexdigest(),
                }
            )
        if temporary is not None:
            manifest = {
                "schema_version": 1,
                "files": manifest_files,
                "summary": report.to_dict(),
            }
            manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            (temporary / ".repo-safe-manifest.json").write_text(manifest_text, encoding="utf-8")
            temporary.replace(destination)
    except BaseException:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    return report
