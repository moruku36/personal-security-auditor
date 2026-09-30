"""Strict, fixed-vocabulary report model."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Risk(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    code: str
    risk: Risk
    title: str
    location: str
    recommendation: str
    auto_fixable: bool = False

    def as_dict(self) -> dict[str, str | bool]:
        return {"code": self.code, "risk": self.risk.value, "title": self.title,
                "location": self.location, "recommendation": self.recommendation,
                "auto_fixable": self.auto_fixable}


ORDER = {risk: index for index, risk in enumerate(Risk)}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (ORDER[item.risk], item.code, item.location))
