"""Secret-aware, value-safe repository scanner."""

from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path, PurePosixPath
from typing import Any, cast
from xml.parsers.expat import ExpatError

from .models import Finding, ScanReport
from .policy import is_excluded, is_portable_relative_path
from .safeio import collect_tree, is_link_like, read_regular_file


class StructuredDataError(ValueError):
    """Raised when a supported structured file cannot be parsed safely."""


_SENSITIVE_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(?P<value>.*?)\s*$"
)
_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|secret|password|passwd|token|private[_-]?key|database[_-]?url|connection[_-]?string)",
    re.IGNORECASE,
)
_PLACEHOLDERS = {
    "",
    "changeme",
    "example",
    "placeholder",
    "redacted",
    "replace-me",
    "todo",
    "your-value-here",
}
_TOKEN_PATTERNS = (
    (
        "github-fine-grained-token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
        "[REDACTED]",
    ),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "[REDACTED]"),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED]"),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED]"),
    (
        "url-credential",
        re.compile(r"(?P<scheme>https?://)[^/\s:@]+:[^/\s@]+@", re.IGNORECASE),
        r"\g<scheme>[REDACTED]@",
    ),
)
_PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<label>(?:[A-Z0-9 ]+ )?PRIVATE KEY)-----.*?"
    r"-----END (?P=label)-----",
    re.DOTALL,
)
_PATH_PATTERNS = (
    (
        "home-path",
        re.compile(
            r"(?P<prefix>/(?:Users|home)/)(?!(?:example|user)\b|\[USER\])"
            r"[^/\s'\"`]+",
            re.IGNORECASE,
        ),
        r"\g<prefix>[USER]",
    ),
    (
        "windows-home-path",
        re.compile(
            r"(?P<prefix>[A-Z]:\\Users\\)(?!(?:example|user)\b|\[USER\])"
            r"[^\\\s'\"`]+",
            re.IGNORECASE,
        ),
        r"\g<prefix>[USER]",
    ),
)


_PLACEHOLDER_PATTERN = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:(?::[-?])[^}]*)?\}")


def _is_real_value(raw_value: str) -> bool:
    value = raw_value.strip().strip("'\"").strip()
    normalized = value.strip("[]<>").casefold()
    return (
        bool(value)
        and normalized not in _PLACEHOLDERS
        and _PLACEHOLDER_PATTERN.fullmatch(value) is None
    )


def redact_text(content: str, *, redact_all_assignments: bool = False) -> tuple[str, int]:
    """Replace supported secret values while preserving surrounding text."""

    content, redactions = _PRIVATE_KEY_BLOCK.subn("[REDACTED PRIVATE KEY]", content)
    if _PRIVATE_KEY_MARKER.search(content):
        raise StructuredDataError("unsafe or malformed private key block")

    output: list[str] = []
    for line in content.splitlines(keepends=True):
        if line.endswith("\r\n"):
            line_ending = "\r\n"
        elif line.endswith(("\n", "\r")):
            line_ending = line[-1]
        else:
            line_ending = ""
        body = line[: -len(line_ending)] if line_ending else line
        match = _SENSITIVE_ASSIGNMENT.match(body)
        if (
            match
            and (redact_all_assignments or _SENSITIVE_KEY.search(match.group("key")))
            and _is_real_value(match.group("value"))
        ):
            body = f"{body[: match.start('value')]}[REDACTED]"
            redactions += 1
        for _kind, pattern, replacement in _TOKEN_PATTERNS:
            body, count = pattern.subn(replacement, body)
            redactions += count
        for _kind, pattern, replacement in _PATH_PATTERNS:
            body, count = pattern.subn(replacement, body)
            redactions += count
        output.append(body + line_ending)
    return "".join(output), redactions


def _redact_value(item: object) -> tuple[object, int]:
    if isinstance(item, dict):
        output: dict[str, object] = {}
        count = 0
        for key, child in item.items():
            if _SENSITIVE_KEY.search(str(key)):
                if child is None or (isinstance(child, str) and not _is_real_value(child)):
                    output[str(key)] = child
                else:
                    output[str(key)] = "[REDACTED]"
                    count += 1
                continue
            output[str(key)], child_count = _redact_value(child)
            count += child_count
        return output, count
    if isinstance(item, list):
        output_list: list[object] = []
        count = 0
        for child in item:
            sanitized, child_count = _redact_value(child)
            output_list.append(sanitized)
            count += child_count
        return output_list, count
    if isinstance(item, str):
        return redact_text(item)
    return item, 0


def redact_json_text(content: str) -> tuple[str, int]:
    """Redact sensitive keys recursively in a JSON document."""

    try:
        redacted, redactions = _redact_value(json.loads(content))
        output = json.dumps(redacted, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as error:
        raise StructuredDataError("unsafe or malformed JSON") from error
    return output, redactions


def redact_plist_text(content: str) -> tuple[str, int]:
    """Redact sensitive keys recursively in an XML property list."""

    try:
        value = plistlib.loads(content.encode("utf-8"))
        redacted, redactions = _redact_value(value)
        output = plistlib.dumps(cast(Any, redacted), fmt=plistlib.FMT_XML, sort_keys=True)
    except (
        ExpatError,
        plistlib.InvalidFileException,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        raise StructuredDataError("unsafe or malformed property list") from error
    return output.decode("utf-8"), redactions


def scan_text(content: str, *, path: str) -> list[Finding]:
    """Scan one already-bounded UTF-8 document without retaining values."""

    findings: list[Finding] = []
    document_path = PurePosixPath(path)
    suffix = document_path.suffix.casefold()
    redact_all_assignments = document_path.name.casefold().startswith(".env")
    if suffix == ".json":
        try:
            _redacted, structured_redactions = redact_json_text(content)
        except StructuredDataError:
            return [Finding(path=path, kind="malformed-json", line=1)]
        structured_kind = "sensitive-json-key"
    elif suffix == ".plist":
        try:
            _redacted, structured_redactions = redact_plist_text(content)
        except StructuredDataError:
            return [Finding(path=path, kind="malformed-plist", line=1)]
        structured_kind = "sensitive-plist-key"
    else:
        structured_redactions = 0
        structured_kind = ""
    findings.extend(
        Finding(path=path, kind=structured_kind, line=1) for _ in range(structured_redactions)
    )
    for marker in _PRIVATE_KEY_MARKER.finditer(content):
        findings.append(
            Finding(
                path=path,
                kind="private-key",
                line=content.count("\n", 0, marker.start()) + 1,
            )
        )
    for line_number, line in enumerate(content.splitlines(), start=1):
        for kind, pattern, _replacement in _TOKEN_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(path=path, kind=kind, line=line_number))
        for kind, pattern, _replacement in _PATH_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(path=path, kind=kind, line=line_number))
        match = _SENSITIVE_ASSIGNMENT.match(line)
        if (
            match
            and (redact_all_assignments or _SENSITIVE_KEY.search(match.group("key")))
            and _is_real_value(match.group("value"))
        ):
            findings.append(Finding(path=path, kind="sensitive-assignment", line=line_number))
        if len(findings) >= 10_000:
            break
    return findings


def scan_tree(
    source: Path,
    *,
    max_files: int = 10_000,
    max_file_bytes: int = 5 * 1024 * 1024,
    max_total_bytes: int = 512 * 1024 * 1024,
    exclude: tuple[str, ...] = (),
) -> ScanReport:
    """Scan bounded regular UTF-8 files without retaining secret values."""

    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("source must be a directory")
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

    report = ScanReport()
    total_bytes = 0
    for path in paths:
        relative_path = path.relative_to(source)
        if is_link_like(path):
            report.files_skipped += 1
            continue
        if not is_portable_relative_path(relative_path.as_posix()) or is_excluded(
            relative_path, exclude
        ):
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
        report.files_scanned += 1
        relative = path.relative_to(source).as_posix()
        remaining = 10_000 - len(report.findings)
        if remaining > 0:
            report.findings.extend(scan_text(content, path=relative)[:remaining])
    return report
