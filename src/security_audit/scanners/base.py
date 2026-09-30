"""Common scanner protocol and scan context."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import platform
from typing import Protocol

from security_audit.model import Finding


@dataclass(frozen=True)
class Context:
    home: Path
    repository: Path
    full: bool = False
    system: str = field(default_factory=platform.system)


class Scanner(Protocol):
    category: str

    def detect(self, context: Context) -> bool: ...

    def scan(self, context: Context) -> list[Finding]: ...

    def recommendations(self) -> tuple[str, ...]: ...
