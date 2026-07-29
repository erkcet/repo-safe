"""repo-safe public package."""

from importlib.metadata import version

from .models import Finding, ScanReport

__all__ = ["Finding", "ScanReport"]
__version__ = version("repo-safe")
