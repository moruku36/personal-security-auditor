"""Fixed implementation/fixture matrix; no host discovery or safety claims."""
from __future__ import annotations

import json

from security_audit.model import REPORT_SCHEMA_VERSION

LEGACY_MAC = "Legacy 2026-10-06 one Mac (macOS 27.2); new features not device-validated"
LEGACY_WINDOWS = "Legacy 2026-10-06 one PC (Windows version unrecorded); new features not device-validated"
NOT_VALIDATED = "No documented physical-device validation"
NOTICE = (
    "Fixture coverage describes tests present in the repository, not a passing test run. "
    "CI is separate from physical-device validation. Historical runs do not validate new code. "
    "Check docs/coverage.md for scope, versions and unavailable reasons."
)


def rows() -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for system, legacy in (("Darwin", LEGACY_MAC), ("Windows", LEGACY_WINDOWS)):
        result.append({"os": system, "browser": "-", "implemented": "selected OS/network checks",
                       "fixtures": "synthetic OS states; network parser fixtures",
                       "physical_validation": legacy})
        browsers = ("Chrome", "Brave", "Edge", "Firefox", "Safari") if system == "Darwin" else (
            "Chrome", "Brave", "Edge", "Firefox")
        for browser in browsers:
            implemented = (
                "presence + bounded manifest declarations"
                + (" + selected registry policies" if system == "Windows" else "")
                if browser == "Chrome" else
                "presence + extension directory counts" if browser in ("Brave", "Edge") else
                "data-directory presence only")
            fixtures = ("synthetic manifests/policies and scope" if browser == "Chrome"
                        else "synthetic directory/scope fixtures")
            result.append({
                "os": system, "browser": browser, "implemented": implemented,
                "fixtures": fixtures,
                "physical_validation": ("Legacy scan/UI context only; browser version/scope unrecorded; "
                                        "new features not device-validated")
                if browser == "Chrome" else NOT_VALIDATED,
            })
    result.append({"os": "Windows", "browser": "Safari",
                   "implemented": "discovery unavailable; independent manual guidance only",
                   "fixtures": "aggregate manual record fixtures; no discovery adapter",
                   "physical_validation": NOT_VALIDATED})
    result.append({"os": "Linux/other", "browser": "all",
                   "implemented": "OS/network/browser adapters unavailable",
                   "fixtures": "unsupported adapter fixtures", "physical_validation": NOT_VALIDATED})
    return result


def as_coverage(format_name: str) -> str:
    if format_name == "json":
        return json.dumps({"schema_version": REPORT_SCHEMA_VERSION,
                           "notice": NOTICE, "coverage": rows()}, indent=2) + "\n"
    lines = ["Coverage (implementation / fixtures / physical validation)", "", NOTICE, "",
             "| OS | Browser | Implemented | Fixtures | Physical validation |",
             "| --- | --- | --- | --- | --- |"]
    lines.extend("| " + " | ".join(row.values()) + " |" for row in rows())
    return "\n".join(lines) + "\n"
