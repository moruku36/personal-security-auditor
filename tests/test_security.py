from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from security_audit import engine
from security_audit.cli import main
from security_audit.engine import scan
from security_audit.model import Finding
from security_audit.remediation import target
from security_audit.reporting import as_json, as_markdown, as_terminal, write_private
from security_audit.scanners.base import Context
from security_audit.scanners.browser import (
    BrowserScanner,
    _bounded_directories,
    _metadata_is_reparse_point,
    _safe_browsing_policy_status,
)
from security_audit.scanners.development import DevelopmentScanner
from security_audit.scanners.network import NetworkScanner
from security_audit.scanners.os_security import OSScanner
from security_audit.scanners.secrets import SecretScanner


class SecurityTests(unittest.TestCase):
    def test_secret_scanner_never_opens_configuration_file(self) -> None:
        fake = "FAKE_ONLY_DO_NOT_USE_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = home / ".zshrc"
            profile.write_text("OPENAI_API_KEY=" + fake + "\n", encoding="utf-8")
            context = Context(home, home)
            with patch.object(Path, "open", side_effect=AssertionError("file content read")):
                findings = SecretScanner().scan(context)
            for report in (as_terminal(findings), as_json(findings), as_markdown(findings)):
                self.assertNotIn(fake, report)
            self.assertEqual(json.loads(as_json(findings))["findings"][0]["code"], "API-001")

    def test_secret_scanner_only_reports_candidate_file_presence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            env_file = home / ".env"
            env_file.write_text("FAKE_ONLY_DO_NOT_USE", encoding="utf-8")
            env_file.chmod(0o644)
            findings = SecretScanner().scan(Context(home, home, system="Darwin"))
            finding = next(item for item in findings if item.code == "API-001")
            self.assertIn("contents were not read", finding.title)
            self.assertEqual(finding.location, "local configuration metadata")
            permission_finding = next(item for item in findings if item.code == "API-002")
            self.assertFalse(permission_finding.auto_fixable)

    def test_developer_store_permission_check_avoids_content(self) -> None:
        fake = "FAKE_ONLY_DO_NOT_USE_registry_token"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / ".docker" / "config.json"
            config.parent.mkdir()
            config.write_text(fake, encoding="utf-8")
            config.chmod(0o644)
            findings = DevelopmentScanner().scan(Context(home, home, system="Darwin"))
            self.assertTrue(any(item.code == "DEV-003" for item in findings))
            self.assertNotIn(fake, as_json(findings))

    def test_macos_firewall_disabled_is_high_risk(self) -> None:
        def fake_run(argv: list[str], timeout: float = 4.0) -> tuple[int, str]:
            if "socketfilterfw" in argv[0]:
                return 0, "Firewall is disabled. (State = 0)"
            return -1, ""

        with (tempfile.TemporaryDirectory() as directory,
              patch("security_audit.scanners.os_security.run", side_effect=fake_run),
              patch.dict(os.environ, {}, clear=True)):
            findings = OSScanner().scan(Context(Path(directory), Path(directory), system="Darwin"))
        self.assertTrue(any(item.code == "OS-002" and item.risk.value == "HIGH"
                            for item in findings))

    def test_sandbox_does_not_claim_firewall_is_disabled(self) -> None:
        with (tempfile.TemporaryDirectory() as directory,
              patch("security_audit.scanners.os_security.run",
                    return_value=(0, "Firewall is disabled")),
              patch.dict(os.environ, {"CODEX_SANDBOX": "seatbelt"})):
            findings = OSScanner().scan(Context(Path(directory), Path(directory), system="Darwin"))
        self.assertFalse(any(item.code == "OS-002" for item in findings))

    def test_windows_os_status_and_missing_checks(self) -> None:
        status = {"encryption": "off", "firewall": "on", "antivirus": "passive",
                  "uac": "on", "secure_boot": "unknown"}
        with (tempfile.TemporaryDirectory() as directory,
              patch("security_audit.scanners.os_security.powershell_json", return_value=status)):
            context = Context(Path(directory), Path(directory), system="Windows")
            findings = OSScanner().scan(context)
        self.assertTrue(any(item.code == "OS-W01" and item.risk.value == "HIGH"
                            for item in findings))
        self.assertTrue(any(item.title == "Microsoft Defender is passive" for item in findings))
        self.assertTrue(any(item.title == "Secure Boot status unavailable" for item in findings))
        self.assertFalse(any(item.code == "OS-W02" for item in findings))

    def test_windows_listener_output_rejects_addresses_and_invalid_ports(self) -> None:
        payload = {"listeners": [{"port": 8080, "bind": "network"},
                                 {"port": 8080, "bind": "network"},
                                 {"port": 70000, "bind": "*"},
                                 {"port": 1234, "bind": "FAKE_SECRET_IP"}]}
        with (tempfile.TemporaryDirectory() as directory,
              patch("security_audit.scanners.network.powershell_json", return_value=payload)):
            findings = NetworkScanner().scan(Context(Path(directory), Path(directory),
                                                      system="Windows"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].location, "non-loopback address:8080")
        self.assertNotIn("FAKE_SECRET_IP", as_json(findings))

    def test_windows_browser_paths_and_shell_profile_presence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            root = home / "AppData/Local/Google/Chrome/User Data/Default/Extensions"
            root.mkdir(parents=True)
            (root / "fake-extension").mkdir()
            with patch("security_audit.scanners.browser._extension_policy_status",
                       return_value="not-configured"):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            self.assertTrue(any(item.code == "BR-002" for item in findings))
            profile = home / "Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
            profile.parent.mkdir(parents=True)
            profile.write_text('$env:OPENAI_API_KEY="FAKE_ONLY_DO_NOT_USE"\n', encoding="utf-8")
            findings = SecretScanner().scan(Context(home, home, system="Windows"))
            self.assertTrue(any(item.code == "API-001" for item in findings))

    def test_chrome_safe_browsing_registry_policy_is_bounded_and_unknown_safe(self) -> None:
        class FakeWinreg:
            HKEY_CURRENT_USER = "user"
            HKEY_LOCAL_MACHINE = "machine"
            KEY_READ = 1
            REG_DWORD = 4

            def __init__(self, entries: dict[str, tuple[object, int]]):
                self.entries = entries

            def OpenKey(self, hive: str, _path: str, _reserved: int, _access: int) -> str:
                if hive not in self.entries:
                    raise FileNotFoundError
                return hive

            def QueryValueEx(self, hive: str, _name: str) -> tuple[object, int]:
                if hive not in self.entries:
                    raise FileNotFoundError
                return self.entries[hive]

            def CloseKey(self, _key: str) -> None:
                return None

        scenarios = (
            ({"user": (0, 4)}, "disabled"),
            ({"machine": (2, 4)}, "enhanced"),
            ({"user": (1, 4), "machine": (2, 4)}, "conflicting"),
            ({"user": (False, 4)}, "unknown"),
            ({"user": ("0", 1)}, "unknown"),
            ({}, "not-configured"),
        )
        for entries, expected in scenarios:
            with self.subTest(expected=expected):
                fake = FakeWinreg(entries)
                with patch.dict(sys.modules, {"winreg": fake}):
                    self.assertEqual(_safe_browsing_policy_status("Windows"), expected)

    def test_chrome_disabled_safe_browsing_policy_is_high_risk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "AppData/Local/Google/Chrome/User Data/Default").mkdir(parents=True)
            with (patch("security_audit.scanners.browser._extension_policy_status",
                        return_value="not-configured"),
                  patch("security_audit.scanners.browser._safe_browsing_policy_status",
                        return_value="disabled")):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            finding = next(item for item in findings if item.code == "BR-010")
            self.assertEqual(finding.risk.value, "HIGH")
            self.assertNotIn("SafeBrowsingProtectionLevel", as_json([finding]))

    def test_chrome_conflicting_safe_browsing_policy_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "AppData/Local/Google/Chrome/User Data/Default").mkdir(parents=True)
            with (patch("security_audit.scanners.browser._extension_policy_status",
                        return_value="not-configured"),
                  patch("security_audit.scanners.browser._safe_browsing_policy_status",
                        return_value="conflicting")):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            finding = next(item for item in findings if item.code == "BR-010")
            self.assertEqual(finding.risk.value, "INFO")
            self.assertIn("conflict", finding.title)

    def test_chrome_manifest_findings_are_aggregated_and_sanitized(self) -> None:
        fake_id = "FAKE_EXTENSION_ID_DO_NOT_REPORT"
        fake_name = "FAKE_EXTENSION_NAME_DO_NOT_REPORT"
        fake_url = "https://private.example.invalid/update?token=FAKE_SECRET_DO_NOT_REPORT"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            manifest = (home / "AppData/Local/Google/Chrome/User Data/Default/Extensions"
                        / fake_id / "1.0" / "manifest.json")
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "name": fake_name,
                "version": "1.0",
                "permissions": ["nativeMessaging"],
                "host_permissions": ["<all_urls>"],
                "update_url": fake_url,
            }), encoding="utf-8")
            with patch("security_audit.scanners.browser._extension_policy_status",
                       return_value="configured"):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            report = as_json(findings)
            codes = {item.code for item in findings}
            self.assertTrue({"BR-004", "BR-005", "BR-006", "BR-009"}.issubset(codes))
            private_values = (fake_id, fake_name, "private.example.invalid",
                              "FAKE_SECRET_DO_NOT_REPORT")
            for private_value in private_values:
                self.assertNotIn(private_value, report)

    def test_chrome_manifest_unknown_update_source_is_not_called_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            manifest = (home / "AppData/Local/Google/Chrome/User Data/Default/Extensions"
                        / "fake-extension-id" / "1.0" / "manifest.json")
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"manifest_version": 3}', encoding="utf-8")
            with patch("security_audit.scanners.browser._extension_policy_status",
                       return_value="unknown"):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            self.assertTrue(any(item.code == "BR-007" for item in findings))
            self.assertTrue(any(item.code == "BR-009" and "unavailable" in item.title
                                for item in findings))
            self.assertFalse(any(item.code == "BR-006" for item in findings))

    def test_chrome_scan_never_opens_browser_secret_databases(self) -> None:
        forbidden_names = {"Login Data", "Cookies", "History", "Local State", "Secure Preferences"}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = home / "AppData/Local/Google/Chrome/User Data/Default"
            extensions = profile / "Extensions" / "fake-extension-id" / "1.0"
            extensions.mkdir(parents=True)
            (extensions / "manifest.json").write_text(
                '{"manifest_version":3,"permissions":[]}', encoding="utf-8")
            for name in forbidden_names:
                (profile / name).write_text("SYNTHETIC_SENTINEL_DO_NOT_READ", encoding="utf-8")

            original_open = Path.open

            def guard_open(path: Path, *args: object, **kwargs: object):
                if path.name in forbidden_names:
                    raise AssertionError("Chrome secret database was opened")
                return original_open(path, *args, **kwargs)

            with (patch.object(Path, "open", autospec=True, side_effect=guard_open),
                  patch("security_audit.scanners.browser._extension_policy_status",
                        return_value="not-configured")):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            report = as_json(findings)
            self.assertNotIn("SYNTHETIC_SENTINEL_DO_NOT_READ", report)

    def test_chrome_scan_skips_oversized_manifest_without_opening_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            manifest = (home / "AppData/Local/Google/Chrome/User Data/Default/Extensions"
                        / "fake-extension-id" / "1.0" / "manifest.json")
            manifest.parent.mkdir(parents=True)
            manifest.write_text("SYNTHETIC_OVERSIZED_MANIFEST_DO_NOT_READ" * 10_000,
                                encoding="utf-8")
            original_open = Path.open

            def guard_open(path: Path, *args: object, **kwargs: object):
                if path == manifest:
                    raise AssertionError("oversized manifest was opened")
                return original_open(path, *args, **kwargs)

            with (patch.object(Path, "open", autospec=True, side_effect=guard_open),
                  patch("security_audit.scanners.browser._extension_policy_status",
                        return_value="not-configured")):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            report = as_json(findings)
            self.assertTrue(any(item.code == "BR-008" for item in findings))
            self.assertNotIn("SYNTHETIC_OVERSIZED_MANIFEST_DO_NOT_READ", report)

    def test_browser_scanner_rejects_windows_reparse_points(self) -> None:
        metadata = SimpleNamespace(st_mode=0, st_file_attributes=0x400)
        self.assertTrue(_metadata_is_reparse_point(metadata))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("security_audit.scanners.browser._is_reparse_point", return_value=True):
                children, capped, failed = _bounded_directories(root, 10)
            self.assertEqual(children, [])
            self.assertFalse(capped)
            self.assertTrue(failed)

    def test_report_rejects_reparse_point_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_path = Path(directory) / "redirected" / "report.json"
            with (patch("security_audit.reporting.platform.system", return_value="Windows"),
                  patch("security_audit.reporting._has_reparse_ancestor", return_value=True),
                  self.assertRaisesRegex(ValueError, "reparse point")):
                write_private(target_path, "synthetic")
            self.assertFalse(target_path.parent.exists())

    def test_windows_never_previews_chmod(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            finding = Finding("SSH-002", engine.Risk.HIGH, "broad", "~/.ssh/id_test", "fix", True)
            self.assertIsNone(target(Context(home, home, system="Windows"), finding))

    def test_windows_report_refuses_unsecured_acl(self) -> None:
        with (tempfile.TemporaryDirectory() as directory,
              patch("security_audit.reporting.platform.system", return_value="Windows"),
              patch("security_audit.reporting._has_reparse_ancestor", return_value=False),
              patch("security_audit.reporting.restrict_windows_acl", return_value=False)):
            destination = Path(directory) / "report.json"
            with self.assertRaises(OSError):
                write_private(destination, "FAKE_ONLY_DO_NOT_USE")
            self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "nt", "native Windows only")
    def test_windows_private_acl_can_be_applied(self) -> None:
        from security_audit.windows import PRIVATE_ACL_SCRIPT, powershell

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty-report.txt"
            path.write_text("", encoding="utf-8")
            status = powershell(PRIVATE_ACL_SCRIPT, target=path)
            self.assertEqual(status.strip() if status else "NO_OUTPUT", "OK")

    @unittest.skipUnless(os.name == "nt", "native Windows only")
    def test_windows_security_probes_return_structured_status(self) -> None:
        from security_audit.scanners.network import WINDOWS_LISTEN_SCRIPT
        from security_audit.scanners.os_security import WINDOWS_STATUS_SCRIPT
        from security_audit.windows import powershell_json

        status = powershell_json(WINDOWS_STATUS_SCRIPT)
        listeners = powershell_json(WINDOWS_LISTEN_SCRIPT)
        self.assertIsInstance(status, dict)
        self.assertEqual(set(status or {}),
                         {"encryption", "firewall", "antivirus", "uac", "secure_boot"})
        self.assertIsInstance(listeners, dict)
        self.assertIsInstance((listeners or {}).get("listeners"), list)

    def test_stdout_stderr_and_exception_are_redacted(self) -> None:
        fake = "FAKE_ONLY_DO_NOT_USE_abcdefgh"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".env").write_text("SERVICE_TOKEN=" + fake + "\n", encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            log_output = io.StringIO()
            handler = logging.StreamHandler(log_output)
            logger = logging.getLogger("security_audit")
            logger.addHandler(handler)
            with (patch("pathlib.Path.home", return_value=home),
                  patch.dict(os.environ, {}, clear=True),
                  contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
                self.assertEqual(main(["scan", "api", "--repository", directory]), 0)
            logger.removeHandler(handler)
            self.assertNotIn(fake, stdout.getvalue() + stderr.getvalue() + log_output.getvalue())

    def test_report_file_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            with (patch("pathlib.Path.home", return_value=home),
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertEqual(main(["report", "api", "--format", "json", "--output",
                                       str(home / "reports" / "latest.json")]), 0)
            path = home / "reports" / "latest.json"
            if os.name == "nt":
                from security_audit.windows import broad_windows_acl
                self.assertFalse(broad_windows_acl(path))
            else:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_report_refuses_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim.txt"
            victim.write_text("keep", encoding="utf-8")
            link = root / "latest.json"
            link.symlink_to(victim)
            with self.assertRaises(ValueError):
                write_private(link, "replacement")
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    def test_exception_text_is_not_reported(self) -> None:
        fake = "FAKE_ONLY_DO_NOT_USE_exception_value"

        class FailingScanner:
            category = "api"

            def detect(self, context: Context) -> bool:
                return True

            def scan(self, context: Context) -> list[Finding]:
                raise ValueError(fake)

            def recommendations(self) -> tuple[str, ...]:
                return ()

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(engine, "SCANNERS", (FailingScanner(),)):
                report = as_json(scan(Context(Path(directory), Path(directory)), "api"))
            self.assertNotIn(fake, report)


if __name__ == "__main__":
    unittest.main()
