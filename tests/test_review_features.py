from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from security_audit.cli import main
from security_audit.comparison import compare, read_snapshot, save_snapshot, snapshot
from security_audit.coverage import rows
from security_audit.engine import scan
from security_audit.manual import (
    MAX_RECORD_BYTES,
    manual_finding,
    read_record,
    record_path,
    save_record,
)
from security_audit.model import Evidence, Finding, Risk, Status
from security_audit.reporting import as_json, as_markdown, as_terminal
from security_audit.scanners.base import Context
from security_audit.scanners.browser import BrowserScanner
from security_audit.scanners.network import NetworkScanner
from security_audit.scanners.os_security import OSScanner


class RecordPermissionTests(unittest.TestCase):
    def test_manual_check_stores_only_result_and_date_and_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            path = record_path(home, "password")
            save_record(path, "clear", "2020-01-02")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")),
                             {"result": "clear", "checked_on": "2020-01-02"})
            self.assertEqual(read_record(path), (Status.PASS, "2020-01-02"))
            if os.name == "nt":
                from security_audit.windows import broad_windows_acl
                self.assertFalse(broad_windows_acl(path))
            else:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            finding = manual_finding(Context(home, home), "password")
            self.assertEqual(finding.evidence_source, Evidence.USER_UI)
            self.assertIn("User-reported", finding.limitations[0])
            self.assertEqual(finding.checked_on, "2020-01-02")


class ReviewFeaturesTests(unittest.TestCase):
    def setUp(self) -> None:
        # These tests exercise synthetic result/schema fixtures. Real ACL creation
        # is verified separately by RecordPermissionTests and existing report tests.
        acl = patch("security_audit.reporting.restrict_windows_acl", return_value=True)
        acl.start()
        self.addCleanup(acl.stop)

    def test_unchecked_and_missing_are_unknown_and_have_no_date(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = record_path(Path(directory).resolve(), "password")
            self.assertEqual(read_record(path), (Status.UNKNOWN, None))
            save_record(path, "unchecked")
            self.assertEqual(read_record(path), (Status.UNKNOWN, None))
            self.assertIsNone(json.loads(path.read_text(encoding="utf-8"))["checked_on"])

    def test_issues_are_not_unchecked_or_clear(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            save_record(record_path(home, "password"), "issues")
            finding = manual_finding(Context(home, home), "password")
            self.assertEqual(finding.status, Status.ISSUE)
            self.assertEqual(finding.checked_on, datetime.now(UTC).astimezone().date().isoformat())
            self.assertEqual(finding.risk, Risk.MEDIUM)

    def test_invalid_manual_data_is_unavailable_and_never_reported(self) -> None:
        fake = "SYNTHETIC_PRIVATE_SITE_ACCOUNT_PASSWORD"
        invalid = (
            {"result": "clear", "checked_on": "2020-01-01", "account": fake},
            {"result": fake, "checked_on": None},
            {"result": "clear", "checked_on": fake},
            {"result": "clear", "checked_on": "2020-02-30"},
            {"result": "clear", "checked_on": (datetime.now(UTC).astimezone().date() + timedelta(days=1)).isoformat()},
            {"result": "unchecked", "checked_on": "2020-01-01"},
            [fake],
        )
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            path = record_path(home, "password")
            path.parent.mkdir()
            for value in invalid:
                with self.subTest(value_type=type(value).__name__):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    finding = manual_finding(Context(home, home), "password")
                    self.assertEqual(finding.status, Status.UNAVAILABLE)
                    self.assertNotIn(fake, as_json([finding]))
            path.write_text("{", encoding="utf-8")
            self.assertEqual(read_record(path), (Status.UNAVAILABLE, None))

    def test_oversized_record_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = record_path(Path(directory).resolve(), "password")
            path.parent.mkdir()
            path.write_text("x" * (MAX_RECORD_BYTES + 1), encoding="utf-8")
            with patch.object(Path, "open", side_effect=AssertionError("oversized file read")):
                self.assertEqual(read_record(path), (Status.UNAVAILABLE, None))

    def test_inaccessible_record_is_unavailable(self) -> None:
        with patch("security_audit.manual.read_bounded_json", side_effect=PermissionError):
            self.assertEqual(read_record(Path("synthetic.json")), (Status.UNAVAILABLE, None))

    def test_record_reparse_path_is_rejected_without_reading(self) -> None:
        with (patch("security_audit.manual._has_reparse_ancestor", return_value=True),
              patch.object(Path, "open", side_effect=AssertionError("redirected file read"))):
            self.assertEqual(read_record(Path("synthetic.json")), (Status.UNAVAILABLE, None))
            with self.assertRaises(ValueError):
                save_record(Path("synthetic.json"), "clear")

    def test_manual_acl_failure_leaves_existing_record_intact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            path = record_path(home, "password")
            save_record(path, "issues", "2020-01-01")
            before = path.read_bytes()
            with (patch("security_audit.reporting.platform.system", return_value="Windows"),
                  patch("security_audit.reporting._has_reparse_ancestor", return_value=False),
                  patch("security_audit.reporting.restrict_windows_acl", return_value=False),
                  self.assertRaises(OSError)):
                save_record(path, "clear")
            self.assertEqual(path.read_bytes(), before)

    def test_manual_invalid_dates_and_results_do_not_create_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = record_path(Path(directory).resolve(), "password")
            for result, day in (("clear", "invalid"), ("clear", ""), ("unchecked", "2020-01-01"),
                                ("password-value", None)):
                with self.assertRaises(ValueError):
                    save_record(path, result, day)
            self.assertFalse(path.exists())

    def test_manual_cli_guides_records_and_forgets_without_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            output = io.StringIO()
            with (patch("pathlib.Path.home", return_value=home),
                  patch("security_audit.cli.scan", side_effect=AssertionError("unexpected scan")),
                  contextlib.redirect_stdout(output)):
                self.assertEqual(main(["password-checkup"]), 0)
                self.assertFalse(record_path(home, "password").exists())
                self.assertEqual(main(["password-checkup", "--result", "clear",
                                       "--date", "2020-01-01"]), 0)
                self.assertEqual(main(["browser-review", "Chrome", "--result", "issues"]), 0)
                self.assertEqual(main(["password-checkup", "--forget"]), 0)
            self.assertIn("Google Password Manager > Checkup", output.getvalue())
            self.assertFalse(record_path(home, "password").exists())
            self.assertEqual(read_record(record_path(home, "extensions")), (
                Status.ISSUE, datetime.now(UTC).astimezone().date().isoformat()))

    def test_stable_id_does_not_depend_on_state_risk_or_counts(self) -> None:
        finding = Finding("BR-011", Risk.INFO, "before", "Google Password Checkup", "review")
        changed = replace(finding, risk=Risk.MEDIUM, title="after", status=Status.ISSUE)
        self.assertEqual(finding.id, changed.id)
        self.assertNotEqual(finding.id, replace(finding, location="other").id)
        self.assertNotEqual(finding.id, replace(finding, category="other").id)

    def test_report_keeps_legacy_keys_and_adds_explicit_schema_and_states(self) -> None:
        finding = Finding("BR-011", Risk.INFO, "not checked", "Chrome", "review",
                          status=Status.UNKNOWN)
        data = json.loads(as_json([finding]))
        self.assertEqual(data["schema_version"], 2)
        self.assertIn("overall_risk", data)
        self.assertEqual(data["status_counts"]["unknown"], 1)
        self.assertEqual(data["status_counts"]["pass"], 0)
        item = data["findings"][0]
        self.assertTrue({"code", "risk", "title", "location", "recommendation", "auto_fixable",
                         "id", "category", "status", "evidence_source", "limitations",
                         "checked_on"}.issubset(item))
        for render in (as_terminal, as_markdown):
            self.assertIn("unknown", render([finding]))
            self.assertIn("not passes", render([finding]))
            self.assertIn("does not prove safety", render([]))

    def test_browser_matrix_has_distinct_coverage_and_manual_results(self) -> None:
        for system, roots in (("Darwin", BrowserScanner.MAC_ROOTS),
                              ("Windows", BrowserScanner.WINDOWS_ROOTS)):
            for browser, relative in roots.items():
                with (self.subTest(system=system, browser=browser),
                      tempfile.TemporaryDirectory() as directory):
                    home = Path(directory).resolve()
                    root = home / relative
                    extension = root / "Default/Extensions/synthetic-id/1.0/manifest.json"
                    extension.parent.mkdir(parents=True)
                    extension.write_text('{"permissions":["cookies"]}', encoding="utf-8")
                    context = Context(home, home, system=system)
                    save_record(record_path(home, "extensions", browser), "clear", "2020-01-01")
                    with (patch("security_audit.scanners.browser._extension_policy_status",
                                return_value="not-configured"),
                          patch("security_audit.scanners.browser._safe_browsing_policy_status",
                                return_value="not-configured")):
                        findings = BrowserScanner().scan(context)
                    scope = next(item for item in findings if item.code == "BR-003")
                    effective = next(item for item in findings if item.code == "BR-012")
                    self.assertEqual(effective.evidence_source, Evidence.USER_UI)
                    self.assertEqual(effective.status, Status.PASS)
                    if browser == "Chrome":
                        declaration = next(item for item in findings if item.code == "BR-005")
                        self.assertEqual(declaration.evidence_source, Evidence.MANIFEST)
                        self.assertEqual(declaration.status, Status.NEEDS_REVIEW)
                        self.assertEqual(next(item for item in findings if item.code == "BR-011")
                                         .status, Status.UNKNOWN)
                    else:
                        self.assertFalse(any(item.code == "BR-005" for item in findings))
                        self.assertFalse(any(item.code == "BR-011" for item in findings))
                        self.assertIn("only", scope.limitations[0])

    def test_browser_incomplete_reason_has_correct_browser_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            (home / BrowserScanner.WINDOWS_ROOTS["Brave"]).mkdir(parents=True)
            with patch("security_audit.scanners.browser._bounded_directories",
                       return_value=([], True, False)):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            finding = next(item for item in findings if item.code == "BR-008")
            self.assertEqual(finding.location, "Brave extension metadata")
            self.assertEqual(finding.status, Status.UNAVAILABLE)

    def test_browser_root_reparse_point_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            with patch("security_audit.scanners.browser._is_reparse_point", return_value=True):
                findings = BrowserScanner().scan(Context(home, home, system="Windows"))
            self.assertTrue(any(item.code == "BR-008" and item.status == Status.UNAVAILABLE
                                for item in findings))
            self.assertFalse(any(item.status == Status.PASS for item in findings))

    def test_unsupported_browser_does_not_use_mac_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            (home / BrowserScanner.MAC_ROOTS["Chrome"]).mkdir(parents=True)
            finding = BrowserScanner().scan(Context(home, home, system="Linux"))[0]
            self.assertEqual(finding.code, "BR-000")
            self.assertEqual(finding.status, Status.UNAVAILABLE)
            self.assertEqual(OSScanner().scan(Context(home, home, system="Linux"))[0].status,
                             Status.UNAVAILABLE)

    def test_windows_os_unknown_off_and_on_keep_check_identity(self) -> None:
        context = Context(Path("synthetic"), Path("synthetic"), system="Windows")
        findings = []
        for state in ("unknown", "off", "on"):
            with patch("security_audit.scanners.os_security.powershell_json",
                       return_value={"encryption": state}):
                findings.append(next(item for item in OSScanner().scan(context)
                                     if item.code == "OS-W01"))
        self.assertEqual([item.status for item in findings],
                         [Status.UNAVAILABLE, Status.ISSUE, Status.PASS])
        self.assertEqual(len({item.id for item in findings}), 1)

    def test_macos_success_failure_and_nonzero_output_are_distinct(self) -> None:
        context = Context(Path("synthetic"), Path("synthetic"), system="Darwin")
        for exit_code, output, expected in (
            (0, "FileVault is on", Status.PASS), (0, "FileVault is off", Status.ISSUE),
            (0, "malformed", Status.UNAVAILABLE), (1, "FileVault is on", Status.UNAVAILABLE),
        ):
            with (patch("security_audit.scanners.os_security.run",
                        return_value=(exit_code, output)), patch.dict(os.environ, {}, clear=True)):
                finding = next(item for item in OSScanner().scan(context) if item.code == "OS-001")
                self.assertEqual(finding.status, expected)

    def test_detect_failure_is_unavailable_and_redacted(self) -> None:
        class FailedScanner:
            category = "ssh"

            def detect(self, context: Context) -> bool:
                raise PermissionError("SYNTHETIC_PRIVATE_EXCEPTION")

        with patch("security_audit.engine.SCANNERS", (FailedScanner(),)):
            findings = scan(Context(Path("synthetic"), Path("synthetic")), "ssh")
        self.assertEqual(findings[0].status, Status.UNAVAILABLE)
        self.assertEqual(findings[0].category, "ssh")
        self.assertNotIn("SYNTHETIC_PRIVATE_EXCEPTION", as_json(findings))

    def test_snapshot_only_keeps_opaque_id_state_and_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            context = Context(home, home, system="Darwin")
            finding = Finding("SSH-002", Risk.HIGH, "SYNTHETIC_PRIVATE_TITLE",
                              "SYNTHETIC_PRIVATE_LOCATION", "SYNTHETIC_PRIVATE_RECOMMENDATION",
                              status=Status.ISSUE)
            value = snapshot([finding], context, {"ssh"})
            destination = home / "snapshot.json"
            save_snapshot(destination, value)
            content = destination.read_text(encoding="utf-8")
            self.assertNotIn("SYNTHETIC_PRIVATE", content)
            self.assertNotIn(str(home), content)
            entry = json.loads(content)["findings"][0]
            self.assertEqual(set(entry), {"id", "status"})
            self.assertEqual(read_snapshot(destination, value.scope), value)

    def test_comparison_distinguishes_unknown_missing_and_new(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            context = Context(home, home)
            old = Finding("BR-011", Risk.INFO, "before", "Chrome", "review", status=Status.PASS)
            disappeared = replace(old, code="BR-002")
            new = replace(old, code="BR-012", status=Status.ISSUE)
            previous = snapshot([old, disappeared], context, {"browser"})
            current = snapshot([replace(old, status=Status.UNKNOWN), new], context, {"browser"})
            output = compare(previous, current)
            self.assertIn("pass -> unknown", output)
            self.assertIn("not observed now", output)
            self.assertIn("newly observed: issue", output)
            self.assertNotIn("resolved:", output)
            self.assertIn("not resolved", output)

    def test_snapshot_rejects_scope_schema_raw_fields_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            finding = Finding("BR-011", Risk.INFO, "check", "Chrome", "review")
            value = snapshot([finding], Context(home, home), {"browser"})
            path = home / "snapshot.json"
            base = json.loads(value.serialize())
            invalid = [
                {**base, "schema_version": 99}, {**base, "identity_version": 99},
                {**base, "schema_version": True}, {**base, "account": "synthetic"},
                {**base, "findings": base["findings"] * 2},
                {**base, "findings": [{"id": finding.id, "status": "invalid"}]},
                {**base, "findings": [{"id": finding.id, "status": "pass", "title": "private"}]},
                {**base, "findings": [{"id": "not-an-id", "status": "pass"}]},
            ]
            for data in invalid:
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_snapshot(path, value.scope)
            path.write_text(value.serialize(), encoding="utf-8")
            for context, categories in (
                (Context(home, home, full=True), {"browser"}),
                (Context(home, home, system="different"), {"browser"}),
                (Context(home, home / "other"), {"browser"}),
                (Context(home, home), {"os"}),
            ):
                with self.assertRaises(ValueError):
                    read_snapshot(path, snapshot([], context, categories).scope)

    def test_duplicate_findings_keep_least_certain_state(self) -> None:
        item = Finding("API-002", Risk.HIGH, "check", "permissions", "review", status=Status.ISSUE)
        context = Context(Path("synthetic"), Path("synthetic"))
        value = snapshot([item, replace(item, status=Status.UNAVAILABLE)], context, {"api"})
        self.assertEqual(value.states, {item.id: Status.UNAVAILABLE})

    def test_snapshot_cli_keeps_json_valid_and_requires_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            destination = home / "baseline.json"
            finding = Finding("BR-011", Risk.INFO, "check", "Chrome", "review",
                              status=Status.UNKNOWN)
            with (patch("pathlib.Path.home", return_value=home),
                  patch("security_audit.cli.scan", return_value=[finding]),
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertEqual(main(["scan", "browser", "--repository", str(home)]), 0)
                self.assertFalse(destination.exists())
                self.assertEqual(main(["scan", "browser", "--repository", str(home),
                                       "--snapshot", str(destination)]), 0)
            stdout, stderr = io.StringIO(), io.StringIO()
            with (patch("pathlib.Path.home", return_value=home),
                  patch("security_audit.cli.scan", return_value=[finding]),
                  contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
                self.assertEqual(main(["report", "browser", "--repository", str(home),
                                       "--format", "json", "--compare", str(destination)]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["schema_version"], 2)
            self.assertIn("No ID/state changes", stderr.getvalue())

    def test_bad_baseline_is_not_overwritten_and_errors_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            baseline = home / "baseline.json"
            fake = "SYNTHETIC_PRIVATE_BASELINE"
            baseline.write_text(fake, encoding="utf-8")
            stderr = io.StringIO()
            with (patch("pathlib.Path.home", return_value=home),
                  patch("security_audit.cli.scan", return_value=[]),
                  contextlib.redirect_stderr(stderr)):
                self.assertEqual(main(["scan", "--repository", str(home),
                                       "--compare", str(baseline), "--snapshot", str(baseline)]), 2)
            self.assertEqual(baseline.read_text(encoding="utf-8"), fake)
            self.assertNotIn(fake, stderr.getvalue())

    def test_mac_listener_fixture_redacts_process_and_address(self) -> None:
        context = Context(Path("synthetic"), Path("synthetic"), system="Darwin")
        output = ("COMMAND PID USER NAME\n"
                  "SYNTHETIC_PRIVATE_PROCESS 1 user TCP 192.0.2.10:8080 (LISTEN)\n"
                  "other 2 user TCP 127.0.0.1:9000 (LISTEN)\n")
        with patch("security_audit.scanners.network.run", return_value=(0, output)):
            findings = NetworkScanner().scan(context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].location, "non-loopback address:8080")
        self.assertNotIn("192.0.2.10", as_json(findings))
        self.assertNotIn("SYNTHETIC_PRIVATE_PROCESS", as_json(findings))

    def test_redirected_profile_is_not_silently_treated_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            root = home / BrowserScanner.MAC_ROOTS["Chrome"]
            (root / "Default").mkdir(parents=True)
            with patch("security_audit.scanners.browser._is_reparse_point",
                       side_effect=lambda path: path == root / "Default"):
                findings = BrowserScanner().scan(Context(home, home, system="Darwin"))
            finding = next(item for item in findings if item.code == "BR-008")
            self.assertEqual(finding.status, Status.UNAVAILABLE)

    def test_coverage_command_does_not_scan_or_claim_new_physical_validation(self) -> None:
        stdout = io.StringIO()
        with (patch("security_audit.cli.scan", side_effect=AssertionError("unexpected scan")),
              contextlib.redirect_stdout(stdout)):
            self.assertEqual(main(["coverage", "--format", "json"]), 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(len(data["coverage"]), len(rows()))
        self.assertIn("not a passing test run", data["notice"])
        brave = next(row for row in rows() if row["browser"] == "Brave")
        self.assertIn("counts", brave["implemented"])
        self.assertIn("No documented", brave["physical_validation"])


if __name__ == "__main__":
    unittest.main()
