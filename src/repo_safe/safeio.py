"""Race-resistant reads of untrusted repository files."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path


class UnsafeFileError(OSError):
    """Raised when a path is not a stable regular file within safety limits."""


def is_link_like(path: Path) -> bool:
    """Return whether a path is a symlink or Windows reparse point."""

    metadata = path.lstat()
    file_attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(file_attributes & 0x400)


def walk_tree(
    root: Path,
    *,
    should_prune: Callable[[Path], bool] | None = None,
    max_entries_per_directory: int = 10_000,
    max_depth: int = 64,
    _depth: int = 0,
) -> Iterator[Path]:
    """Yield entries deterministically without descending into unsafe paths."""

    if _depth > max_depth:
        raise ValueError(f"directory depth limit exceeded: more than {max_depth}")
    entries: list[os.DirEntry[str]] = []
    with os.scandir(root) as directory:
        for entry in directory:
            if len(entries) >= max_entries_per_directory:
                raise ValueError(
                    f"directory entry limit exceeded: more than {max_entries_per_directory}"
                )
            entries.append(entry)
    entries.sort(key=lambda entry: entry.name)
    for entry in entries:
        path = Path(entry.path)
        if is_link_like(path):
            yield path
        elif entry.is_dir(follow_symlinks=False):
            yield path
            if should_prune is None or not should_prune(path):
                yield from walk_tree(
                    path,
                    should_prune=should_prune,
                    max_entries_per_directory=max_entries_per_directory,
                    max_depth=max_depth,
                    _depth=_depth + 1,
                )
        else:
            yield path


def collect_tree(
    root: Path,
    *,
    max_entries: int,
    should_prune: Callable[[Path], bool] | None = None,
) -> list[Path]:
    """Collect a bounded tree without allowing entry-count memory exhaustion."""

    paths: list[Path] = []
    for path in walk_tree(root, should_prune=should_prune):
        if len(paths) >= max_entries:
            raise ValueError(f"file limit exceeded: more than {max_entries}")
        paths.append(path)
    return paths


def read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    """Read a regular file without following symlinks and with a hard size cap."""

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise UnsafeFileError("path is not a regular file")
    if before.st_nlink != 1:
        raise UnsafeFileError("path has multiple hard links")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise UnsafeFileError("opened path is not a regular file")
        if after.st_nlink != 1:
            raise UnsafeFileError("opened file has multiple hard links")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise UnsafeFileError("file changed while opening")
        if after.st_size > max_bytes:
            raise UnsafeFileError("file exceeds the configured size limit")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise UnsafeFileError("file grew beyond the configured size limit")
        return data
    finally:
        os.close(descriptor)
