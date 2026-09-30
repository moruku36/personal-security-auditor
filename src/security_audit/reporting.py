from __future__ import annotations

import json
import os
import platform
import tempfile
from collections import Counter
from pathlib import Path

from security_audit.model import Finding, Risk
from security_audit.windows import restrict_windows_acl


def overall(findings: list[Finding]) -> Risk:
    return next((risk for risk in Risk if any(item.risk == risk for item in findings)), Risk.INFO)


def as_json(findings: list[Finding]) -> str:
    return json.dumps({"overall_risk": overall(findings).value,
                       "findings": [item.as_dict() for item in findings]}, indent=2) + "\n"


def as_markdown(findings: list[Finding]) -> str:
    counts = Counter(item.risk for item in findings)
    lines = ["# Personal Security Audit", "", f"Overall risk: **{overall(findings).value}**", "",
             "| Risk | Count |", "| --- | ---: |"]
    lines.extend(f"| {risk.value} | {counts[risk]} |" for risk in Risk)
    for finding in findings:
        lines.extend(["", f"## {finding.risk.value}: {finding.code}", "",
                      finding.title, "", f"Location: `{finding.location}`", "",
                      f"Recommendation: {finding.recommendation}"])
    return "\n".join(lines) + "\n"


def as_terminal(findings: list[Finding]) -> str:
    counts = Counter(item.risk for item in findings)
    lines = ["Personal Security Audit", "", f"Overall Risk: {overall(findings).value}", ""]
    lines.extend(f"{risk.value:<8} {counts[risk]}" for risk in Risk)
    for item in findings:
        lines.extend(["", f"{item.risk.value} [{item.code}] {item.title}",
                      f"Location: {item.location}", f"Recommendation: {item.recommendation}"])
    return "\n".join(lines) + "\n"


def write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Report target is a symlink")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".security-audit-", delete=False) as handle:
            temporary = Path(handle.name)
            if platform.system() == "Windows" and not restrict_windows_acl(temporary):
                raise OSError("Could not restrict report ACL")
            temporary.chmod(0o600)
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
