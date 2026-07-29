from __future__ import annotations

import json
from pathlib import Path

from repo_safe.cli import main


def test_scan_command_returns_findings_as_value_safe_json(tmp_path: Path, capsys: object) -> None:
    source = tmp_path / "source"
    source.mkdir()
    secret = "ghp_" + ("Q" * 36)
    (source / "leak.txt").write_text(f"{secret}\n", encoding="utf-8")

    exit_code = main(["scan", str(source), "--json"])

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    payload = json.loads(captured.out)
    assert exit_code == 1
    assert payload["findings"][0]["kind"] == "github-token"
    assert secret not in captured.out


def test_sanitize_command_creates_verified_snapshot_with_json_output(
    tmp_path: Path, capsys: object
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "config.env").write_text("API_TOKEN=hidden-value\n", encoding="utf-8")
    (source / "debug.log").write_text("ignore\n", encoding="utf-8")

    exit_code = main(
        [
            "sanitize",
            str(source),
            str(destination),
            "--exclude",
            "*.log",
            "--json",
        ]
    )

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload == {"files_skipped": 1, "files_written": 1, "values_redacted": 1}
    assert (destination / ".repo-safe-manifest.json").exists()


def test_verify_command_returns_nonzero_for_tampered_snapshot(
    tmp_path: Path, capsys: object
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "README.md").write_text("safe\n", encoding="utf-8")
    assert main(["sanitize", str(source), str(destination)]) == 0
    capsys.readouterr()  # type: ignore[attr-defined]
    (destination / "README.md").write_text("changed\n", encoding="utf-8")

    exit_code = main(["verify", str(destination), "--json"])

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    payload = json.loads(captured.out)
    assert exit_code == 1
    assert payload["ok"] is False
    assert "hash mismatch: README.md" in payload["errors"]


def test_human_output_covers_clean_scan_and_successful_verification(
    tmp_path: Path, capsys: object
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "README.md").write_text("safe\n", encoding="utf-8")

    assert main(["scan", str(source)]) == 0
    assert "CLEAN:" in capsys.readouterr().out  # type: ignore[attr-defined]
    assert main(["sanitize", str(source), str(destination)]) == 0
    assert "CREATED:" in capsys.readouterr().out  # type: ignore[attr-defined]
    assert main(["verify", str(destination)]) == 0
    assert "VERIFIED:" in capsys.readouterr().out  # type: ignore[attr-defined]


def test_cli_returns_usage_error_without_leaking_content(tmp_path: Path, capsys: object) -> None:
    missing = tmp_path / "missing"

    exit_code = main(["scan", str(missing)])

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert exit_code == 2
    assert captured.out == ""
    assert "repo-safe:" in captured.err


def test_sanitize_command_dry_run_does_not_create_destination(
    tmp_path: Path, capsys: object
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "safe"
    source.mkdir()
    (source / "config.env").write_text("TOKEN=private-value\n", encoding="utf-8")

    exit_code = main(["sanitize", str(source), str(destination), "--dry-run", "--json"])

    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert exit_code == 0
    assert payload["files_written"] == 1
    assert payload["values_redacted"] == 1
    assert not destination.exists()


def test_scan_command_supports_custom_exclusions(tmp_path: Path, capsys: object) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "private").mkdir()
    (source / "private" / "config.txt").write_text("token=synthetic-secret\n", encoding="utf-8")

    exit_code = main(["scan", str(source), "--exclude", "private/**", "--json"])
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]

    assert exit_code == 0
    assert payload["files_skipped"] == 1
    assert payload["findings"] == []
