from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_audit import engine
from security_audit.cli import main
from security_audit.engine import scan
from security_audit.model import Finding
from security_audit.remediation import target
from security_audit.reporting import as_json, as_markdown, as_terminal, write_private
from security_audit.scanners.base import Context
from security_audit.scanners.browser import BrowserScanner
from security_audit.scanners.development import DevelopmentScanner
from security_audit.scanners.network import NetworkScanner
from security_audit.scanners.os_security import OSScanner
from security_audit.scanners.secrets import assignment_names


class SecurityTests(unittest.TestCase):
    def test_secret_values_never_leave_scanner(self) -> None:
        fake = "FAKE_ONLY_DO_NOT_USE_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".zshrc").write_text("OPENAI_API_KEY=" + fake + "\n", encoding="utf-8")
            context = Context(home, home)
            self.assertEqual(assignment_names(home / ".zshrc"), {b"OPENAI_API_KEY"})
            findings = scan(context, "api")
            for report in (as_terminal(findings), as_json(findings), as_markdown(findings)):
                self.assertNotIn(fake, report)
            self.assertEqual(json.loads(as_json(findings))["findings"][0]["code"], "API-001")

    def test_export_assignment_name_is_detected_without_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".zshrc"
            path.write_text("export OPENAI_API_KEY=FAKE_ONLY_DO_NOT_USE\n", encoding="utf-8")
            self.assertEqual(assignment_names(path), {b"OPENAI_API_KEY"})

    def test_developer_store_permission_check_avoids_content(self) -> None:
        fake = "FAKE_ONLY_DO_NOT_USE_registry_token"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / ".docker" / "config.json"
            config.parent.mkdir()
            config.write_text(fake, encoding="utf-8")
            config.chmod(0o644)
            findings = DevelopmentScanner().scan(Context(home, home))
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
              patch("security_audit.scanners.os_security.run", return_value=(0, "Firewall is disabled")),
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

    def test_windows_browser_paths_and_powershell_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            root = home / "AppData/Local/Google/Chrome/User Data/Default/Extensions"
            root.mkdir(parents=True)
            (root / "fake-extension").mkdir()
            findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            self.assertTrue(any(item.code == "BR-002" for item in findings))
            profile = home / "Microsoft.PowerShell_profile.ps1"
            profile.write_text('$env:OPENAI_API_KEY="FAKE_ONLY_DO_NOT_USE"\n', encoding="utf-8")
            self.assertEqual(assignment_names(profile), {b"OPENAI_API_KEY"})

    def test_windows_never_previews_chmod(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            finding = Finding("SSH-002", engine.Risk.HIGH, "broad", "~/.ssh/id_test", "fix", True)
            self.assertIsNone(target(Context(home, home, system="Windows"), finding))

    def test_windows_report_refuses_unsecured_acl(self) -> None:
        with (tempfile.TemporaryDirectory() as directory,
              patch("security_audit.reporting.platform.system", return_value="Windows"),
              patch("security_audit.reporting.restrict_windows_acl", return_value=False)):
            destination = Path(directory) / "report.json"
            with self.assertRaises(OSError):
                write_private(destination, "FAKE_ONLY_DO_NOT_USE")
            self.assertFalse(destination.exists())

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
