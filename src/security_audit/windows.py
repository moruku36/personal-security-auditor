"""Read-only Windows probes. PowerShell emits only bounded status facts."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


def powershell(script: str, *, target: Path | None = None, timeout: float = 12) -> str | None:
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    executable = root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not executable.is_file():
        return None
    env = {name: value for name, value in os.environ.items()
           if name.upper() in {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATH", "PATHEXT", "TEMP"}}
    env["SystemRoot"] = str(root)
    if target is not None:
        env["SECURITY_AUDIT_TARGET"] = str(target)
    try:
        result = subprocess.run(
            [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout, check=False, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout[:8192] if result.returncode == 0 else None


def powershell_json(script: str, *, timeout: float = 12) -> dict[str, Any] | list[Any] | None:
    output = powershell(script, timeout=timeout)
    if output is None:
        return None
    try:
        parsed = json.loads(output)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
  $acl = Get-Acl -LiteralPath $env:SECURITY_AUDIT_TARGET
  $broad = $false
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne 'Allow') { continue }
    $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($sid -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')) {
      $rights = [int]$rule.FileSystemRights
      if (($rights -band 1) -ne 0 -or ($rights -band 2) -ne 0) { $broad = $true }
    }
  }
  if ($broad) { 'BROAD' } else { 'PRIVATE' }
} catch { 'UNKNOWN' }
"""


def broad_windows_acl(path: Path) -> bool | None:
    """Flag broad read/write grants; unknown ACLs are never treated as safe."""
    if path.is_symlink() or not path.exists():
        return None
    output = powershell(ACL_SCRIPT, target=path)
    if output is None:
        return None
    result = output.strip()
    return True if result == "BROAD" else False if result == "PRIVATE" else None


PRIVATE_ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
  $path = $env:SECURITY_AUDIT_TARGET
  $acl = Get-Acl -LiteralPath $path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { $acl.PurgeAccessRules($rule.IdentityReference) }
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow')
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $path -AclObject $acl
  'OK'
} catch { 'FAILED' }
"""


def restrict_windows_acl(path: Path) -> bool:
    output = powershell(PRIVATE_ACL_SCRIPT, target=path)
    return output is not None and output.strip() == "OK"
