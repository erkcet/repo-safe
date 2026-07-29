"""Data models used by repository scanning and sanitization."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Finding:
    """A secret-like value found at a location, without retaining the value."""

    path: str
    kind: str
    line: int


@dataclass(slots=True)
class VerifyReport:
    """Integrity and secret-scan result for a sanitized snapshot."""

    files_verified: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Return true when every integrity and safety check passed."""

        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible verification result."""

        return {"ok": self.ok, "files_verified": self.files_verified, "errors": self.errors}


@dataclass(slots=True)
class SanitizeReport:
    """Safe-to-serialize result of creating a sanitized snapshot."""

    files_written: int = 0
    files_skipped: int = 0
    values_redacted: int = 0

    def to_dict(self) -> dict[str, int]:
        """Return report counters without source content."""

        return {
            "files_written": self.files_written,
            "files_skipped": self.files_skipped,
            "values_redacted": self.values_redacted,
        }


@dataclass(slots=True)
class ScanReport:
    """Safe-to-serialize result of scanning a repository tree."""

    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible report that never contains secret values."""

        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "findings": [asdict(finding) for finding in self.findings],
        }
