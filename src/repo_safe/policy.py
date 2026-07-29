"""Default snapshot inclusion policy."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath, PureWindowsPath

EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
}
SENSITIVE_FILENAMES = {
    ".netrc",
    ".repo-safe-manifest.json",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
SENSITIVE_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


def is_portable_relative_path(value: str) -> bool:
    """Return whether a canonical POSIX path is safe on supported platforms."""

    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        not value
        or value != posix_path.as_posix()
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or "\\" in value
        or any(part in {"", ".", ".."} for part in posix_path.parts)
        or _CONTROL_CHARACTERS.search(value)
    ):
        return False
    for part in posix_path.parts:
        if ":" in part or part.endswith((".", " ")):
            return False
        stem = part.split(".", 1)[0].casefold()
        if stem in _WINDOWS_RESERVED_NAMES:
            return False
    return True


def _matches_pattern(relative: Path, pattern: str) -> bool:
    path = PurePosixPath(relative.as_posix().casefold())
    pattern = pattern.casefold()
    if pattern.endswith("/**"):
        root_pattern = pattern[:-3].rstrip("/")
        candidates = [path, *path.parents]
        return any(candidate.match(root_pattern) for candidate in candidates)
    return path.match(pattern)


def is_excluded(relative: Path, extra_patterns: tuple[str, ...] = ()) -> bool:
    """Return whether a relative path should be pruned or skipped."""

    folded_parts = {part.casefold() for part in relative.parts}
    return (
        bool(EXCLUDED_DIRECTORIES.intersection(folded_parts))
        or relative.name.casefold() in SENSITIVE_FILENAMES
        or relative.suffix.casefold() in SENSITIVE_SUFFIXES
        or any(_matches_pattern(relative, pattern) for pattern in extra_patterns)
    )
