from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from repo_safe.scanner import scan_tree


def test_scan_reports_assignment_secret_without_exposing_value(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "settings.ini").write_text(
        "theme=dark\napi_token=very-secret-token-value\n",
        encoding="utf-8",
    )

    report = scan_tree(source)

    assert report.files_scanned == 1
    assert len(report.findings) == 1
    assert report.findings[0].path == "settings.ini"
    assert report.findings[0].kind == "sensitive-assignment"
    assert report.findings[0].line == 2
    assert "very-secret-token-value" not in json.dumps(report.to_dict())


def test_scan_never_follows_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside.env"
    outside.write_text("API_TOKEN=outside-secret-value\n", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    (source / "linked.env").symlink_to(outside)

    report = scan_tree(source)

    assert report.files_scanned == 0
    assert report.files_skipped == 1
    assert report.findings == []


def test_scan_detects_known_token_without_retaining_it(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fake_token = "ghp_" + ("A" * 36)
    (source / "notes.txt").write_text(f"accidentally pasted {fake_token}\n", encoding="utf-8")

    report = scan_tree(source)

    assert [finding.kind for finding in report.findings] == ["github-token"]
    assert fake_token not in json.dumps(report.to_dict())


def test_scan_detects_nested_json_secret_keys(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    secret = "json-secret-value"
    (source / "settings.json").write_text(
        json.dumps({"service": {"client_secret": secret}}), encoding="utf-8"
    )

    report = scan_tree(source)

    assert [finding.kind for finding in report.findings] == ["sensitive-json-key"]
    assert secret not in json.dumps(report.to_dict())


def test_scan_skips_binary_and_placeholder_values(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "binary.dat").write_bytes(b"\x00secret")
    (source / "example.env").write_text(
        "TOKEN=[REDACTED]\npath=`/Users/[USER]`\n", encoding="utf-8"
    )

    report = scan_tree(source)

    assert report.files_scanned == 1
    assert report.files_skipped == 1
    assert report.findings == []


def test_scan_enforces_file_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.txt").write_text("one", encoding="utf-8")
    (source / "two.txt").write_text("two", encoding="utf-8")

    with pytest.raises(ValueError, match="file limit"):
        scan_tree(source, max_files=1)


def test_scan_requires_directory_source(tmp_path: Path) -> None:
    source = tmp_path / "file.txt"
    source.write_text("text", encoding="utf-8")

    with pytest.raises(ValueError, match="source must be a directory"):
        scan_tree(source)


def test_scan_detects_nested_plist_secret_keys(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    secret = "plist-private-value"
    (source / "service.plist").write_bytes(
        plistlib.dumps({"Label": "demo", "Credentials": {"Password": secret}})
    )

    report = scan_tree(source)

    assert [finding.kind for finding in report.findings] == ["sensitive-plist-key"]
    assert secret not in json.dumps(report.to_dict())


def test_scan_prunes_default_dependency_and_vcs_directories(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".git").mkdir()
    (source / "node_modules").mkdir()
    (source / "safe.txt").write_text("hello\n", encoding="utf-8")
    (source / ".git" / "config").write_text("token=hidden-value\n", encoding="utf-8")
    (source / "node_modules" / "package.txt").write_text(
        "password=hidden-value\n", encoding="utf-8"
    )

    report = scan_tree(source)

    assert report.files_scanned == 1
    assert report.files_skipped == 2
    assert report.findings == []


def test_scan_detects_current_token_and_url_credential_shapes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    fine_grained = "github_pat_" + ("A" * 82)
    (source / "notes.txt").write_text(
        f"found {fine_grained}\nendpoint=https://alice:synthetic-password@example.test/api\n",
        encoding="utf-8",
    )

    report = scan_tree(source)

    assert {finding.kind for finding in report.findings} == {
        "github-fine-grained-token",
        "url-credential",
    }
    assert fine_grained not in json.dumps(report.to_dict())


def test_scan_reports_malformed_structured_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "broken.json").write_text("{", encoding="utf-8")
    (source / "broken.plist").write_text("<plist>", encoding="utf-8")

    report = scan_tree(source)

    assert {finding.kind for finding in report.findings} == {
        "malformed-json",
        "malformed-plist",
    }


def test_scan_enforces_total_byte_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.txt").write_text("1234", encoding="utf-8")

    with pytest.raises(ValueError, match="total byte limit"):
        scan_tree(source, max_total_bytes=3)
