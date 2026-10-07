"""Versioned findings with separate risk, check state and evidence."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

REPORT_SCHEMA_VERSION = 2


class Risk(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    OBSERVED = "observed"
    NEEDS_REVIEW = "needs_review"
    PASS = "pass"
    ISSUE = "issue"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class Evidence(str, Enum):
    METADATA = "stored_metadata"
    MANIFEST = "manifest_declaration"
    POLICY = "configured_policy"
    LOCAL_COMMAND = "local_command"
    PERMISSIONS = "file_permissions"
    MANUAL = "manual_review"
    USER_UI = "user_reported_ui"
    UNAVAILABLE = "unavailable"


CATEGORIES = {"OS": "os", "BR": "browser", "API": "api", "GIT": "git",
              "SSH": "ssh", "CL": "cloud", "DEV": "dev", "NET": "network", "AI": "ai"}


@dataclass(frozen=True)
class Finding:
    code: str
    risk: Risk
    title: str
    location: str
    recommendation: str
    auto_fixable: bool = False
    status: Status = Status.NEEDS_REVIEW
    evidence_source: Evidence = Evidence.MANUAL
    limitations: tuple[str, ...] = ("A finding is limited to the stated check, not a safety verdict.",)
    category: str = ""
    checked_on: str | None = None

    def __post_init__(self) -> None:
        if not self.category:
            object.__setattr__(self, "category", CATEGORIES.get(self.code.split("-")[0], "audit"))

    @property
    def id(self) -> str:
        # Titles, counts, severity and status may change without changing identity.
        identity = json.dumps([self.category, self.code, self.location], ensure_ascii=True)
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {"id": self.id, "code": self.code, "category": self.category,
                "risk": self.risk.value, "title": self.title,
                "location": self.location, "recommendation": self.recommendation,
                "auto_fixable": self.auto_fixable, "status": self.status.value,
                "evidence_source": self.evidence_source.value,
                "limitations": list(self.limitations), "checked_on": self.checked_on}


ORDER = {risk: index for index, risk in enumerate(Risk)}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (ORDER[item.risk], item.code, item.location))
