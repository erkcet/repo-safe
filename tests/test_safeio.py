from __future__ import annotations

import os
from pathlib import Path

import pytest

from repo_safe.safeio import UnsafeFileError, read_regular_file, walk_tree


def test_read_regular_file_reads_within_limit(tmp_path: Path) -> None:
    path = tmp_path / "note.txt"
    path.write_bytes(b"hello")

    assert read_regular_file(path, max_bytes=5) == b"hello"


def test_read_regular_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_bytes(b"hello")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(UnsafeFileError, match="not a regular file"):
        read_regular_file(link, max_bytes=100)


def test_read_regular_file_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "large.txt"
    path.write_bytes(b"123456")

    with pytest.raises(UnsafeFileError, match="size limit"):
        read_regular_file(path, max_bytes=5)


def test_read_regular_file_rejects_hard_links(tmp_path: Path) -> None:
    original = tmp_path / "original.txt"
    linked = tmp_path / "linked.txt"
    original.write_bytes(b"private")
    os.link(original, linked)

    with pytest.raises(UnsafeFileError, match="multiple hard links"):
        read_regular_file(linked, max_bytes=100)


def test_walk_tree_does_not_descend_into_symlinked_directory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    outside = tmp_path / "outside"
    source.mkdir()
    outside.mkdir()
    (outside / "private.txt").write_text("private", encoding="utf-8")
    (source / "linked").symlink_to(outside, target_is_directory=True)

    relative_paths = [path.relative_to(source).as_posix() for path in walk_tree(source)]

    assert relative_paths == ["linked"]


def test_walk_tree_bounds_directory_fanout(tmp_path: Path) -> None:
    (tmp_path / "one").write_text("1", encoding="utf-8")
    (tmp_path / "two").write_text("2", encoding="utf-8")

    with pytest.raises(ValueError, match="directory entry limit"):
        list(walk_tree(tmp_path, max_entries_per_directory=1))


def test_walk_tree_bounds_depth(tmp_path: Path) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)

    with pytest.raises(ValueError, match="directory depth limit"):
        list(walk_tree(tmp_path, max_depth=0))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
def test_read_regular_file_rejects_special_file(tmp_path: Path) -> None:
    path = tmp_path / "pipe"
    os.mkfifo(path)

    with pytest.raises(UnsafeFileError, match="not a regular file"):
        read_regular_file(path, max_bytes=100)
