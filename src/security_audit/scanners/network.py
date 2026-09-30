from __future__ import annotations

import platform
import re

from security_audit.model import Finding, Risk
from security_audit.safety import run
from security_audit.scanners.base import Context


class NetworkScanner:
    category = "network"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Verify non-loopback listeners are protected by a firewall.",)

    def scan(self, context: Context) -> list[Finding]:
        if platform.system() != "Darwin":
            return [Finding("NET-000", Risk.INFO, "Network adapter is pending", "network",
                            "Inspect local listening services manually.")]
        status, output = run(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], 8)
        if status != 0:
            return [Finding("NET-000", Risk.INFO, "Listener inspection unavailable", "network",
                            "Review listening services manually.")]
        findings: list[Finding] = []
        endpoints: set[tuple[str, str, str]] = set()
        for line in output.splitlines()[1:]:
            match = re.search(r"TCP\s+(\S+):(\d+)\s+\(LISTEN\)", line)
            if match:
                host, port = match.groups()
                if host not in ("127.0.0.1", "[::1]", "localhost"):
                    process = line.split()[0]
                    kind = "macOS sharing service" if process in ("rapportd", "ControlCe") else "other service"
                    endpoints.add((host, port, kind))
        for host, port, kind in sorted(endpoints)[:50]:
            safe_host = host if host in ("*", "0.0.0.0", "[::]") else "non-loopback address"
            risk = Risk.MEDIUM if kind == "macOS sharing service" else Risk.HIGH
            findings.append(Finding("NET-001", risk,
                f"TCP port {port} listens beyond loopback ({kind})", f"{safe_host}:{port}",
                "Verify network exposure and bind to loopback if remote access is unnecessary."))
        return findings
