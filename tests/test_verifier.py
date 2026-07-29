from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from repo_safe.sanitizer import sanitize_tree
from repo_safe.verifier import verify_tree


def test_verify_accepts_untampered_sanitized_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "config.txt").write_text("password=secret-value\n", encoding="utf-8")
    sanitize_tree(source, destination)

    report = verify_tree(destination)

    assert report.ok is True
    assert report.files_verified == 1
    assert report.errors == []


def test_verify_rejects_tampering_and_untracked_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "config.txt").write_text("public=true\n", encoding="utf-8")
    sanitize_tree(source, destination)
    (destination / "config.txt").write_text("token=untracked-secret-value\n", encoding="utf-8")
    (destination / "extra.txt").write_text("unexpected\n", encoding="utf-8")

    report = verify_tree(destination)

    assert report.ok is False
    assert "hash mismatch: config.txt" in report.errors
    assert "untracked file: extra.txt" in report.errors
    assert "secret-like value remains: config.txt:1" in report.errors


def test_verify_rejects_manifest_path_traversal(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("public\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "files": [{"path": "../outside.txt", "sha256": "0" * 64, "redactions": 0}],
        "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert report.ok is False
    assert "unsafe manifest path: ../outside.txt" in report.errors


def test_verify_reports_missing_and_invalid_manifest(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()

    missing = verify_tree(snapshot)
    assert missing.ok is False
    assert missing.errors == ["manifest is missing, unreadable, or invalid JSON"]

    (snapshot / ".repo-safe-manifest.json").write_text("[]", encoding="utf-8")
    unsupported = verify_tree(snapshot)
    assert unsupported.errors == ["manifest uses an unsupported schema"]


def test_verify_rejects_untracked_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    snapshot = tmp_path / "safe"
    source.mkdir()
    (source / "note.txt").write_text("safe\n", encoding="utf-8")
    sanitize_tree(source, snapshot)
    (snapshot / "link.txt").symlink_to(snapshot / "note.txt")

    report = verify_tree(snapshot)

    assert report.ok is False
    assert "unsafe symlink or junction: link.txt" in report.errors


def test_verify_accepts_sanitized_structured_placeholders(tmp_path: Path) -> None:
    source = tmp_path / "source"
    snapshot = tmp_path / "safe"
    source.mkdir()
    (source / "settings.json").write_text(
        json.dumps({"service": {"api_key": "synthetic-private-value"}}), encoding="utf-8"
    )
    sanitize_tree(source, snapshot)

    report = verify_tree(snapshot)

    assert report.ok is True
    assert report.errors == []


def test_verify_rejects_invalid_duplicate_and_missing_manifest_entries(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    note = b"safe\n"
    (snapshot / "note.txt").write_bytes(note)
    digest = hashlib.sha256(note).hexdigest()
    manifest = {
        "schema_version": 1,
        "files": [
            42,
            {"path": "bad.txt", "sha256": "invalid", "redactions": 0},
            {"path": "note.txt", "sha256": digest, "redactions": 0},
            {"path": "note.txt", "sha256": digest, "redactions": 0},
            {"path": "missing.txt", "sha256": "0" * 64, "redactions": 0},
        ],
        "summary": {"files_written": 5, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert "manifest contains an invalid file entry" in report.errors
    assert "invalid manifest hash: bad.txt" in report.errors
    assert "duplicate manifest path: note.txt" in report.errors
    assert "missing or unsafe file: missing.txt" in report.errors


def test_verify_rejects_manifest_paths_forbidden_by_snapshot_policy(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    (snapshot / ".git").mkdir(parents=True)
    data = b"token=synthetic-secret\n"
    (snapshot / ".git" / "config").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "files": [
            {
                "path": ".git/config",
                "sha256": hashlib.sha256(data).hexdigest(),
                "redactions": 0,
            }
        ],
        "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert report.ok is False
    assert "forbidden snapshot path: .git/config" in report.errors


def test_verify_rejects_binary_tracked_files(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    data = b"\x00SYNTHETIC_BINARY_SECRET\xff"
    (snapshot / "payload.bin").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "files": [
            {
                "path": "payload.bin",
                "sha256": hashlib.sha256(data).hexdigest(),
                "redactions": 0,
            }
        ],
        "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert report.ok is False
    assert "unsafe text file: payload.bin" in report.errors


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
def test_verify_rejects_untracked_special_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    snapshot = tmp_path / "safe"
    source.mkdir()
    sanitize_tree(source, snapshot)
    os.mkfifo(snapshot / "pipe")

    report = verify_tree(snapshot)

    assert report.ok is False
    assert "unsafe special file: pipe" in report.errors


@pytest.mark.parametrize("relative", ["C:/outside.txt", "a//b.txt", "a/./b.txt", "bad\nname.txt"])
def test_verify_rejects_noncanonical_or_drive_manifest_paths(tmp_path: Path, relative: str) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    manifest = {
        "schema_version": 1,
        "files": [{"path": relative, "sha256": "0" * 64, "redactions": 0}],
        "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert report.ok is False
    displayed = json.dumps(relative) if "\n" in relative else relative
    assert f"unsafe manifest path: {displayed}" in report.errors


def test_verify_rejects_invalid_utf8_tracked_file(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    data = b"\xff\xfe"
    (snapshot / "bad.txt").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "files": [
            {
                "path": "bad.txt",
                "sha256": hashlib.sha256(data).hexdigest(),
                "redactions": 0,
            }
        ],
        "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert "unsafe text file: bad.txt" in report.errors


def test_verify_rejects_casefolded_duplicate_paths(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    manifest = {
        "schema_version": 1,
        "files": [
            {"path": "A.txt", "sha256": "0" * 64, "redactions": 0},
            {"path": "a.txt", "sha256": "0" * 64, "redactions": 0},
        ],
        "summary": {"files_written": 2, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert "duplicate manifest path: a.txt" in report.errors


@pytest.mark.parametrize(
    "manifest,error",
    [
        (
            {"schema_version": 1, "files": [], "summary": {}, "extra": True},
            "manifest schema contains missing or unexpected fields",
        ),
        (
            {"schema_version": 1, "files": [], "summary": {}},
            "manifest summary is invalid",
        ),
        (
            {
                "schema_version": 1,
                "files": [],
                "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
            },
            "manifest summary is inconsistent",
        ),
    ],
)
def test_verify_validates_complete_manifest_schema(
    tmp_path: Path, manifest: dict[str, object], error: str
) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert report.errors == [error]


def test_verify_rejects_inconsistent_redaction_summary(tmp_path: Path) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    data = b"safe\n"
    (snapshot / "note.txt").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "files": [
            {
                "path": "note.txt",
                "sha256": hashlib.sha256(data).hexdigest(),
                "redactions": 1,
            }
        ],
        "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert "manifest redaction summary is inconsistent" in report.errors


def test_verify_rejects_populated_dotenv_assignment_case_insensitively(
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    data = b"REGION=abc\n"
    relative = ".ENV.LOCAL"
    (snapshot / relative).write_bytes(data)
    manifest = {
        "schema_version": 1,
        "files": [
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "redactions": 0,
            }
        ],
        "summary": {"files_written": 1, "files_skipped": 0, "values_redacted": 0},
    }
    (snapshot / ".repo-safe-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_tree(snapshot)

    assert report.ok is False
    assert f"secret-like value remains: {relative}:1" in report.errors


def test_verify_rejects_excessively_nested_manifest_without_crashing(
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "safe"
    snapshot.mkdir()
    nested = "[" * 5_000 + "0" + "]" * 5_000
    (snapshot / ".repo-safe-manifest.json").write_text(nested, encoding="utf-8")

    report = verify_tree(snapshot)

    assert report.ok is False
    assert report.errors in (
        ["manifest is missing, unreadable, or invalid JSON"],
        ["manifest uses an unsupported schema"],
    )
