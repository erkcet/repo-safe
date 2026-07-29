"""Command-line interface for repo-safe."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .sanitizer import sanitize_tree
from .scanner import scan_tree
from .verifier import verify_tree


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-safe",
        description=(
            "Create text-only repository snapshots that redact supported secret patterns. "
            "Always review before sharing."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Find secret-like values without printing them.")
    scan.add_argument("source", type=Path, help="Repository or directory to scan.")
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a path glob. Repeatable.",
    )
    scan.add_argument("--max-files", type=int, default=10_000, help="Maximum input entries.")
    scan.add_argument(
        "--max-file-bytes", type=int, default=5 * 1024 * 1024, help="Maximum text file size."
    )
    scan.add_argument(
        "--max-total-bytes",
        type=int,
        default=512 * 1024 * 1024,
        help="Maximum total input bytes.",
    )
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    sanitize = commands.add_parser("sanitize", help="Create an atomic sanitized snapshot.")
    sanitize.add_argument("source", type=Path, help="Repository or directory to sanitize.")
    sanitize.add_argument("destination", type=Path, help="New directory to create.")
    sanitize.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a path glob. Repeatable.",
    )
    sanitize.add_argument("--max-files", type=int, default=10_000, help="Maximum input entries.")
    sanitize.add_argument(
        "--max-file-bytes", type=int, default=5 * 1024 * 1024, help="Maximum text file size."
    )
    sanitize.add_argument(
        "--max-total-bytes",
        type=int,
        default=512 * 1024 * 1024,
        help="Maximum total input bytes.",
    )
    sanitize.add_argument(
        "--dry-run", action="store_true", help="Report the plan without writing any files."
    )
    sanitize.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    verify = commands.add_parser("verify", help="Verify hashes and rescan a snapshot.")
    verify.add_argument("snapshot", type=Path, help="Sanitized snapshot to verify.")
    verify.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run repo-safe and return a stable process exit code."""

    args = _build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            scan_report = scan_tree(
                args.source,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                exclude=tuple(args.exclude),
            )
            if args.json:
                print(json.dumps(scan_report.to_dict(), indent=2, sort_keys=True))
            else:
                status = "CLEAN" if not scan_report.findings else "FINDINGS"
                print(
                    f"{status}: {len(scan_report.findings)} finding(s), "
                    f"{scan_report.files_scanned} file(s) scanned, "
                    f"{scan_report.files_skipped} skipped."
                )
                for finding in scan_report.findings:
                    print(f"- {finding.path}:{finding.line} [{finding.kind}]")
            return 1 if scan_report.findings else 0
        if args.command == "sanitize":
            sanitize_report = sanitize_tree(
                args.source,
                args.destination,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                exclude=tuple(args.exclude),
                dry_run=args.dry_run,
            )
            if args.json:
                print(json.dumps(sanitize_report.to_dict(), indent=2, sort_keys=True))
            else:
                label = "DRY RUN" if args.dry_run else "CREATED"
                print(
                    f"{label}: {sanitize_report.files_written} file(s), "
                    f"{sanitize_report.values_redacted} value(s) redacted, "
                    f"{sanitize_report.files_skipped} skipped."
                )
            return 0
        if args.command == "verify":
            verify_report = verify_tree(args.snapshot)
            if args.json:
                print(json.dumps(verify_report.to_dict(), indent=2, sort_keys=True))
            else:
                status = "VERIFIED" if verify_report.ok else "FAILED"
                print(f"{status}: {verify_report.files_verified} file(s) verified.")
                for error in verify_report.errors:
                    print(f"- {error}")
            return 0 if verify_report.ok else 1
    except (OSError, ValueError) as error:
        print(f"repo-safe: {error}", file=sys.stderr)
        return 2
    return 2
