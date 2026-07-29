"""Verify the integrity and safety of sanitized snapshots."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

from .models import VerifyReport
from .policy import is_excluded, is_portable_relative_path, portable_path_key
from .safeio import collect_tree, is_link_like, read_regular_file
from .scanner import scan_text

_MANIFEST_NAME = ".repo-safe-manifest.json"
_MAX_FILES = 10_000
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_regular_file(path, max_bytes=10 * 1024 * 1024).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("manifest is missing, unreadable, or invalid JSON") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("manifest uses an unsupported schema")
    if set(value) != {"schema_version", "files", "summary"}:
        raise ValueError("manifest schema contains missing or unexpected fields")
    if not isinstance(value.get("files"), list):
        raise ValueError("manifest files must be a list")
    summary = value.get("summary")
    if not isinstance(summary, dict) or set(summary) != {
        "files_written",
        "files_skipped",
        "values_redacted",
    }:
        raise ValueError("manifest summary is invalid")
    if any(type(summary[key]) is not int or summary[key] < 0 for key in summary):
        raise ValueError("manifest summary is invalid")
    if len(value["files"]) > _MAX_FILES:
        raise ValueError(f"manifest file limit exceeded: more than {_MAX_FILES}")
    if summary["files_written"] != len(value["files"]):
        raise ValueError("manifest summary is inconsistent")
    redaction_total = 0
    redaction_summary_checkable = True
    for entry in value["files"]:
        count = entry.get("redactions") if isinstance(entry, dict) else None
        if type(count) is not int or count < 0:
            redaction_summary_checkable = False
            break
        redaction_total += count
    if redaction_summary_checkable and redaction_total != summary["values_redacted"]:
        raise ValueError("manifest redaction summary is inconsistent")
    return value


def _display_path(relative: str) -> str:
    if all(character.isprintable() and character not in "\r\n\x1b" for character in relative):
        return relative
    return json.dumps(relative, ensure_ascii=True)


def verify_tree(snapshot: Path) -> VerifyReport:
    """Verify bounded text files, manifest hashes, tree shape, and secret findings."""

    snapshot = snapshot.resolve(strict=True)
    if not snapshot.is_dir():
        raise ValueError("snapshot must be a directory")
    report = VerifyReport()
    try:
        manifest = _load_manifest(snapshot / _MANIFEST_NAME)
    except ValueError as error:
        report.errors.append(str(error))
        return report
    tracked: set[str] = set()
    canonical_tracked: set[str] = set()
    total_bytes = 0
    for raw_entry in manifest["files"]:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "path",
            "redactions",
            "sha256",
        }:
            report.errors.append("manifest contains an invalid file entry")
            continue
        relative = raw_entry.get("path")
        expected_hash = raw_entry.get("sha256")
        redactions = raw_entry.get("redactions")
        if (
            not isinstance(relative, str)
            or not isinstance(expected_hash, str)
            or type(redactions) is not int
            or redactions < 0
        ):
            report.errors.append("manifest contains an invalid file entry")
            continue
        display = _display_path(relative)
        if relative == _MANIFEST_NAME or not is_portable_relative_path(relative):
            report.errors.append(f"unsafe manifest path: {display}")
            continue
        if is_excluded(Path(relative)):
            report.errors.append(f"forbidden snapshot path: {display}")
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            report.errors.append(f"invalid manifest hash: {display}")
            continue
        canonical = portable_path_key(relative)
        if relative in tracked or canonical in canonical_tracked:
            report.errors.append(f"duplicate manifest path: {display}")
            continue
        tracked.add(relative)
        canonical_tracked.add(canonical)
        path = snapshot / relative
        try:
            file_bytes = read_regular_file(path, max_bytes=_MAX_FILE_BYTES)
        except OSError:
            report.errors.append(f"missing or unsafe file: {display}")
            continue
        if b"\x00" in file_bytes:
            report.errors.append(f"unsafe text file: {display}")
            continue
        try:
            content = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            report.errors.append(f"unsafe text file: {display}")
            continue
        total_bytes += len(file_bytes)
        if total_bytes > _MAX_TOTAL_BYTES:
            report.errors.append("snapshot total-byte limit exceeded")
            break
        findings = scan_text(content, path=relative)
        for finding in findings[:100]:
            report.errors.append(
                f"secret-like value remains: {_display_path(finding.path)}:{finding.line}"
            )
        actual_hash = hashlib.sha256(file_bytes).hexdigest()
        if actual_hash != expected_hash:
            report.errors.append(f"hash mismatch: {display}")
            continue
        if not findings:
            report.files_verified += 1

    try:
        paths = collect_tree(snapshot, max_entries=_MAX_FILES + 1)
    except ValueError as error:
        report.errors.append(str(error))
        return report
    for path in paths:
        relative = path.relative_to(snapshot).as_posix()
        display = _display_path(relative)
        if relative == _MANIFEST_NAME:
            continue
        try:
            if is_link_like(path):
                report.errors.append(f"unsafe symlink or junction: {display}")
                continue
            metadata = path.lstat()
        except OSError:
            report.errors.append(f"unsafe filesystem entry: {display}")
            continue
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            report.errors.append(f"unsafe special file: {display}")
        elif relative not in tracked:
            report.errors.append(f"untracked file: {display}")
    return report
