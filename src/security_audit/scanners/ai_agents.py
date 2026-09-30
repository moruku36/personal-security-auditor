from __future__ import annotations

from security_audit.model import Finding, Risk
from security_audit.permissions import broad_access
from security_audit.scanners.base import Context


class AIAgentScanner:
    category = "ai"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Review agent filesystem, shell, network and MCP permissions in each tool UI.",)

    def scan(self, context: Context) -> list[Finding]:
        findings: list[Finding] = []
        for name in (".codex", ".claude", ".cursor"):
            path = context.home / name
            if not path.is_dir():
                continue
            findings.append(Finding("AI-001", Risk.INFO, f"{name[1:]} agent directory found",
                                    "~/" + name, "Review agent permissions and MCP servers manually."))
            exposure = broad_access(path, context.system)
            if exposure:
                findings.append(Finding("AI-002", Risk.MEDIUM,
                    "Agent configuration directory permissions are broad", "~/" + name,
                    "Restrict directory access after reviewing shared workflows.",
                    context.system != "Windows"))
            elif exposure is None:
                findings.append(Finding("AI-098", Risk.INFO,
                    "Agent directory permissions unavailable", "~/" + name,
                    "Review directory permissions manually."))
        return findings
