from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from repo_safe.sanitizer import sanitize_tree
from repo_safe.verifier import verify_tree


def test_sanitize_copies_text_and_redacts_sensitive_assignments(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    original = "theme=dark\napi_token=very-secret-token-value\n"
    (source / "settings.ini").write_text(original, encoding="utf-8")

    report = sanitize_tree(source, destination)

    assert (source / "settings.ini").read_text(encoding="utf-8") == original
    assert (destination / "settings.ini").read_text(encoding="utf-8") == (
        "theme=dark\napi_token=[REDACTED]\n"
    )
    assert report.files_written == 1
    assert report.values_redacted == 1
    assert "very-secret-token-value" not in json.dumps(report.to_dict())


def test_sanitize_skips_default_exclusions_binary_files_and_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "safe.txt").write_text("hello\n", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("token=secret-value\n", encoding="utf-8")
    (source / "node_modules").mkdir()
    (source / "node_modules" / "package.js").write_text("code\n", encoding="utf-8")
    (source / "id_rsa").write_text("private key material\n", encoding="utf-8")
    (source / "image.bin").write_bytes(b"\x00\x01\x02secret")
    (source / "linked.txt").symlink_to(source / "safe.txt")

    report = sanitize_tree(source, destination)

    assert sorted(path.name for path in destination.iterdir()) == [
        ".repo-safe-manifest.json",
        "safe.txt",
    ]
    assert report.files_written == 1
    assert report.files_skipped == 5


def test_sanitize_writes_deterministic_value_safe_manifest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    secret = "ghp_" + ("Z" * 36)
    (source / "b.txt").write_text(f"token={secret}\n", encoding="utf-8")
    (source / "a.txt").write_text("public\n", encoding="utf-8")

    sanitize_tree(source, destination)

    manifest_path = destination / ".repo-safe-manifest.json"
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    assert manifest["schema_version"] == 1
    assert [entry["path"] for entry in manifest["files"]] == ["a.txt", "b.txt"]
    assert manifest["files"][1]["redactions"] == 1
    assert len(manifest["files"][0]["sha256"]) == 64
    assert secret not in manifest_text
    assert str(source) not in manifest_text
    assert str(destination) not in manifest_text


def test_sanitize_is_atomic_when_safety_limit_is_exceeded(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "one.txt").write_text("one\n", encoding="utf-8")
    (source / "two.txt").write_text("two\n", encoding="utf-8")

    with pytest.raises(ValueError, match="file limit"):
        sanitize_tree(source, destination, max_files=1)

    assert not destination.exists()


def test_sanitize_redacts_every_value_in_dotenv_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / ".env.production").write_text(
        "REGION=eu-west-1\nUNUSUAL_CREDENTIAL=hidden-value\nEMPTY=\n",
        encoding="utf-8",
    )

    sanitize_tree(source, destination)

    assert (destination / ".env.production").read_text(encoding="utf-8") == (
        "REGION=[REDACTED]\nUNUSUAL_CREDENTIAL=[REDACTED]\nEMPTY=\n"
    )


def test_sanitize_redacts_nested_json_values(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    secret = "nested-secret-value"
    (source / "settings.json").write_text(
        json.dumps({"name": "demo", "service": {"apiKey": secret, "enabled": True}}),
        encoding="utf-8",
    )

    report = sanitize_tree(source, destination)

    sanitized = json.loads((destination / "settings.json").read_text(encoding="utf-8"))
    assert sanitized == {
        "name": "demo",
        "service": {"apiKey": "[REDACTED]", "enabled": True},
    }
    assert report.values_redacted == 1
    assert secret not in json.dumps(report.to_dict())


def test_sanitize_redacts_nested_plist_values(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "service.plist").write_bytes(
        plistlib.dumps({"Label": "demo", "Credentials": {"Password": "hidden-value"}})
    )

    report = sanitize_tree(source, destination)

    sanitized = plistlib.loads((destination / "service.plist").read_bytes())
    assert sanitized == {
        "Credentials": {"Password": "[REDACTED]"},
        "Label": "demo",
    }
    assert report.values_redacted == 1


def test_sanitize_applies_custom_exclude_patterns(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "keep.txt").write_text("keep\n", encoding="utf-8")
    (source / "debug.log").write_text("debug\n", encoding="utf-8")
    private = source / "private"
    private.mkdir()
    (private / "notes.txt").write_text("private\n", encoding="utf-8")

    report = sanitize_tree(source, destination, exclude=("*.log", "private/**"))

    assert (destination / "keep.txt").exists()
    assert not (destination / "debug.log").exists()
    assert not (destination / "private" / "notes.txt").exists()
    assert report.files_skipped == 2


def test_sanitize_rejects_unsafe_destinations(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    with pytest.raises(ValueError, match="outside the source"):
        sanitize_tree(source, source / "output")

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FileExistsError, match="already exists"):
        sanitize_tree(source, existing)


def test_sanitize_skips_files_above_size_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "large.txt").write_text("too large", encoding="utf-8")

    report = sanitize_tree(source, destination, max_file_bytes=3)

    assert report.files_written == 0
    assert report.files_skipped == 1


def test_sanitize_dry_run_writes_nothing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "missing-parent" / "safe"
    source.mkdir()
    (source / "config.env").write_text("API_TOKEN=private-value\n", encoding="utf-8")

    report = sanitize_tree(source, destination, dry_run=True)

    assert report.files_written == 1
    assert report.values_redacted == 1
    assert not destination.exists()
    assert not destination.parent.exists()


def test_sanitize_anonymizes_common_home_directory_paths(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    original = (
        "mac=/Users/alice/projects/demo\n"
        "linux=/home/bob/projects/demo\n"
        "windows=C:\\Users\\carol\\projects\\demo\n"
    )
    (source / "paths.txt").write_text(original, encoding="utf-8")

    report = sanitize_tree(source, destination)

    sanitized = (destination / "paths.txt").read_text(encoding="utf-8")
    assert "/Users/[USER]/projects/demo" in sanitized
    assert "/home/[USER]/projects/demo" in sanitized
    assert "C:\\Users\\[USER]\\projects\\demo" in sanitized
    assert (source / "paths.txt").read_text(encoding="utf-8") == original
    assert report.values_redacted == 3


def test_sanitize_cleans_temporary_tree_after_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "note.txt").write_text("safe\n", encoding="utf-8")
    original_write_bytes = Path.write_bytes

    def fail_snapshot_write(path: Path, data: bytes) -> int:
        if ".safe.repo-safe-" in path.as_posix():
            raise OSError("synthetic write failure")
        return original_write_bytes(path, data)

    monkeypatch.setattr(Path, "write_bytes", fail_snapshot_write)

    with pytest.raises(OSError, match="synthetic write failure"):
        sanitize_tree(source, destination)

    assert not destination.exists()
    assert list(tmp_path.glob(".safe.repo-safe-*")) == []


def test_sanitize_skips_malformed_structured_files_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "broken.json").write_text('{"api_key":"synthetic-secret"', encoding="utf-8")
    (source / "broken.plist").write_text(
        "<plist><dict><key>Password</key><string>synthetic-secret</dict>",
        encoding="utf-8",
    )

    report = sanitize_tree(source, destination)

    assert not (destination / "broken.json").exists()
    assert not (destination / "broken.plist").exists()
    assert report.files_written == 0
    assert report.files_skipped == 2


def test_sanitize_redacts_short_and_underscore_prefixed_dotenv_values(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / ".env").write_text(
        "PIN=123\n_SECRET=abc\nREFERENCE=${TOKEN}\nEMPTY=\n", encoding="utf-8"
    )

    report = sanitize_tree(source, destination)

    assert (destination / ".env").read_text(encoding="utf-8") == (
        "PIN=[REDACTED]\n_SECRET=[REDACTED]\nREFERENCE=${TOKEN}\nEMPTY=\n"
    )
    assert report.values_redacted == 2


def test_sanitize_redacts_complete_private_key_blocks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    body = "SYNTHETIC_PRIVATE_KEY_BODY_123456"
    (source / "notes.txt").write_text(
        f"before\r\n{begin}\r\n{body}\r\n{end}\r\nafter\r\n",
        encoding="utf-8",
    )

    report = sanitize_tree(source, destination)
    output = (destination / "notes.txt").read_text(encoding="utf-8")

    assert output == "before\n[REDACTED PRIVATE KEY]\nafter\n"
    assert body not in output
    assert "END PRIVATE KEY" not in output
    assert report.values_redacted == 1


def test_sanitize_preserves_crlf_for_line_redactions(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "config.ini").write_bytes(b"theme=dark\r\npassword=hidden-value\r\nnext=yes\r\n")

    sanitize_tree(source, destination)

    assert (destination / "config.ini").read_bytes() == (
        b"theme=dark\r\npassword=[REDACTED]\r\nnext=yes\r\n"
    )


def test_sanitize_reserves_manifest_name(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / ".repo-safe-manifest.json").write_text("{}", encoding="utf-8")

    report = sanitize_tree(source, destination)

    manifest = json.loads((destination / ".repo-safe-manifest.json").read_text(encoding="utf-8"))
    assert manifest["files"] == []
    assert report.files_written == 0
    assert report.files_skipped == 1


def test_sanitize_recursive_glob_excludes_all_descendants(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    deep = source / "fixtures" / "private" / "deep"
    deep.mkdir(parents=True)
    (source / "fixtures" / "private" / "one.txt").write_text("one", encoding="utf-8")
    (deep / "two.txt").write_text("two", encoding="utf-8")

    report = sanitize_tree(source, destination, exclude=("fixtures/private/**",))

    assert not (destination / "fixtures").exists()
    assert report.files_skipped == 1


def test_sanitize_total_byte_limit_is_atomic(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "one.txt").write_text("1234", encoding="utf-8")

    with pytest.raises(ValueError, match="total byte limit"):
        sanitize_tree(source, destination, max_total_bytes=3)

    assert not destination.exists()


def test_sanitize_skips_incomplete_private_key_block(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    marker = "-----BEGIN " + "PRIVATE KEY-----\nsynthetic-body\n"
    (source / "broken.txt").write_text(marker, encoding="utf-8")

    report = sanitize_tree(source, destination)

    assert not (destination / "broken.txt").exists()
    assert report.files_skipped == 1


def test_sanitize_skips_nonportable_control_character_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "bad\nname.txt").write_text("safe", encoding="utf-8")

    report = sanitize_tree(source, destination)

    assert report.files_skipped == 1
    assert not (destination / "bad\nname.txt").exists()
    assert verify_tree(destination).ok is True


def test_sanitize_redacts_modern_token_and_url_credential_shapes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    token = "github" + "_pat_" + "A" * 24
    credential_url = "https://" + "alice:synthetic-password@example.test/api"
    (source / "notes.txt").write_text(
        f"found {token}\nendpoint {credential_url}\n", encoding="utf-8"
    )

    report = sanitize_tree(source, destination)
    output = (destination / "notes.txt").read_text(encoding="utf-8")

    assert token not in output
    assert credential_url not in output
    assert "https://[REDACTED]@example.test/api" in output
    assert report.values_redacted == 2
    assert verify_tree(destination).ok is True


def test_sanitize_treats_sensitive_names_and_dotenv_case_insensitively(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / ".NETRC").write_text("synthetic credential", encoding="utf-8")
    (source / "CREDENTIALS.JSON").write_text('{"theme": "safe"}', encoding="utf-8")
    (source / ".ENV.PRODUCTION").write_text("REGION=abc\n", encoding="utf-8")

    report = sanitize_tree(source, destination)

    assert not (destination / ".NETRC").exists()
    assert not (destination / "CREDENTIALS.JSON").exists()
    assert (destination / ".ENV.PRODUCTION").read_text(encoding="utf-8") == ("REGION=[REDACTED]\n")
    assert report.files_skipped == 2
    assert verify_tree(destination).ok is True


def test_sanitize_skips_excessively_nested_json(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    nested = "[" * 5_000 + "0" + "]" * 5_000
    (source / "deep.json").write_text(nested, encoding="utf-8")

    report = sanitize_tree(source, destination)

    assert report.files_skipped == 1
    assert not (destination / "deep.json").exists()
    assert verify_tree(destination).ok is True


def test_sanitize_skips_structured_output_larger_than_file_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    compact = json.dumps([0] * 100, separators=(",", ":"))
    (source / "expanded.json").write_text(compact, encoding="utf-8")

    report = sanitize_tree(source, destination, max_file_bytes=len(compact.encode("utf-8")))

    assert report.files_written == 0
    assert report.files_skipped == 1
    assert not (destination / "expanded.json").exists()
    assert verify_tree(destination).ok is True


def test_sanitize_rejects_aggregate_output_expansion_atomically(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    compact = json.dumps([0] * 100, separators=(",", ":"))
    for name in ("one.json", "two.json"):
        (source / name).write_text(compact, encoding="utf-8")
    input_total = 2 * len(compact.encode("utf-8"))

    with pytest.raises(ValueError, match="total output byte limit exceeded"):
        sanitize_tree(
            source,
            destination,
            max_file_bytes=1_000,
            max_total_bytes=input_total,
        )

    assert not destination.exists()
