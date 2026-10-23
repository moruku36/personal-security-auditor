from __future__ import annotations

import re

from security_audit import linux
from security_audit.model import Evidence, Finding, Risk, Status
from security_audit.safety import run
from security_audit.scanners.base import Context
from security_audit.windows import powershell_json

WINDOWS_LISTEN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
  $address = $_.LocalAddress
  if ($address -notin @('127.0.0.1', '::1', '::ffff:127.0.0.1')) {
    [pscustomobject]@{
      port = [int]$_.LocalPort
      bind = if ($address -in @('0.0.0.0', '::')) { '*' } else { 'network' }
    }
  }
} | Select-Object -First 100)
@{ listeners = $listeners } | ConvertTo-Json -Compress -Depth 3
"""


INCOMPLETE_TABLE = ("The TCP table was malformed, partly unreadable, or larger than the "
                    "reporting bound.")


class NetworkScanner:
    category = "network"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Verify non-loopback listeners are protected by a firewall.",)

    def scan(self, context: Context) -> list[Finding]:
        if context.system == "Windows":
            return self._scan_windows()
        if context.system == "Linux":
            return self._scan_linux(context)
        if context.system != "Darwin":
            return [Finding("NET-000", Risk.INFO, "Network adapter is unavailable", "network",
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

    def _scan_windows(self) -> list[Finding]:
        result = powershell_json(WINDOWS_LISTEN_SCRIPT)
        if not isinstance(result, dict) or not isinstance(result.get("listeners"), list):
            return [Finding("NET-000", Risk.INFO, "Windows listener inspection unavailable",
                            "network", "Review listening TCP ports manually.")]
        endpoints: set[tuple[int, str]] = set()
        for item in result["listeners"]:
            if not isinstance(item, dict):
                continue
            port, bind = item.get("port"), item.get("bind")
            if isinstance(port, int) and 1 <= port <= 65535 and bind in ("*", "network"):
                endpoints.add((port, bind))
        findings: list[Finding] = []
        for port, bind in sorted(endpoints)[:50]:
            location = f"{bind if bind == '*' else 'non-loopback address'}:{port}"
            findings.append(Finding("NET-001", Risk.HIGH,
                f"TCP port {port} listens beyond loopback", location,
                "Check its owner, firewall rule and whether remote access is needed."))
        return findings

    def _scan_linux(self, context: Context) -> list[Finding]:
        """Read the kernel TCP tables; no command, address or process name is emitted."""
        result = linux.tcp_listeners(context.linux)
        if result is None:
            return [Finding("NET-000", Risk.INFO, "Linux listener inspection unavailable",
                            "network", "Review listening TCP ports manually.",
                            status=Status.UNAVAILABLE, evidence_source=Evidence.UNAVAILABLE,
                            limitations=("The kernel TCP table could not be read.",))]
        endpoints, complete = result
        limitations = ("Listening beyond loopback does not establish Internet exposure.",
                       "Only this process's network namespace is visible; owners are not inspected.")
        findings: list[Finding] = []
        for port, bind in endpoints:
            location = f"{bind if bind == '*' else 'non-loopback address'}:{port}"
            findings.append(Finding("NET-001", Risk.HIGH,
                f"TCP port {port} listens beyond loopback", location,
                "Check its owner, firewall rule and whether remote access is needed.",
                status=Status.NEEDS_REVIEW, evidence_source=Evidence.LOCAL_COMMAND,
                limitations=limitations))
        if not complete:
            findings.append(Finding("NET-000", Risk.INFO, "Linux listener inspection was incomplete",
                                    "network", "Review listening TCP ports manually.",
                                    status=Status.UNAVAILABLE, evidence_source=Evidence.UNAVAILABLE,
                                    limitations=(INCOMPLETE_TABLE,)))
        return findings
