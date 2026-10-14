"""Independent synthetic boundary checks; no real browser or account access."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_audit.cli import main
from security_audit.comparison import Snapshot, read_snapshot, scope_id
from security_audit.manual import read_record
from security_audit.model import Status
from security_audit.reporting import as_json
from security_audit.scanners.base import Context
from security_audit.scanners.browser import BrowserScanner


class IndependentAcceptanceTests(unittest.TestCase):
    def test_duplicate_manual_result_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text('{"result":"issues","result":"clear",'
                            '"checked_on":"2020-01-01"}', encoding="utf-8")
            self.assertEqual(read_record(path), (Status.UNAVAILABLE, None))

    def test_duplicate_manual_date_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text('{"result":"clear","checked_on":"SYNTHETIC_CANARY",'
                            '"checked_on":"2020-01-01"}', encoding="utf-8")
            self.assertEqual(read_record(path), (Status.UNAVAILABLE, None))

    def test_duplicate_snapshot_status_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text('{"schema_version":1,"identity_version":1,"scope":"scope",'
                            '"findings":[{"id":"' + "a" * 64 + '",'
                            '"status":"issue","status":"pass"}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                read_snapshot(path, "scope")

    def test_duplicate_snapshot_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text('{"schema_version":999,"schema_version":1,'
                            '"identity_version":1,"scope":"scope","findings":[]}',
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                read_snapshot(path, "scope")

    def test_cli_duplicate_baseline_is_redacted_and_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            path = home / "snapshot.json"
            scope = scope_id(Context(home, home), {"browser"})
            original = '{"schema_version":"SYNTHETIC_CANARY","schema_version":1,' \
                       '"identity_version":1,"scope":"' + scope + '","findings":[]}'
            path.write_text(original, encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with (patch("pathlib.Path.home", return_value=home),
                  patch("security_audit.cli.scan", return_value=[]),
                  contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
                result = main(["report", "browser", "--format", "json", "--repository",
                               str(home), "--compare", str(path), "--snapshot", str(path)])
            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("SYNTHETIC_CANARY", stderr.getvalue())
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_one_unreadable_stored_version_marks_coverage_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            extension = home / BrowserScanner.MAC_ROOTS["Chrome"] / "Default/Extensions/fake"
            for version, content in (
                ("1", '{"host_permissions":["<all_urls>"]}'),
                ("2", '{SYNTHETIC_CANARY'),
            ):
                target = extension / version / "manifest.json"
                target.parent.mkdir(parents=True)
                target.write_text(content, encoding="utf-8")
            findings = BrowserScanner().scan(Context(home, home, system="Darwin"))
            self.assertTrue(any(f.code == "BR-008" and f.status == Status.UNAVAILABLE
                                for f in findings))
            self.assertNotIn("SYNTHETIC_CANARY", as_json(findings))
            self.assertTrue(any(f.code == "BR-004" for f in findings))

    def test_legacy_host_permission_declarations_are_not_missed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            target = home / BrowserScanner.MAC_ROOTS["Chrome"] \
                / "Default/Extensions/SYNTHETIC_PRIVATE_ID/1/manifest.json"
            target.parent.mkdir(parents=True)
            for field in ("permissions", "optional_permissions"):
                with self.subTest(field=field):
                    target.write_text(json.dumps({"manifest_version": 2,
                                                  field: ["<all_urls>"]}), encoding="utf-8")
                    findings = BrowserScanner().scan(Context(home, home, system="Darwin"))
                    self.assertTrue(any(f.code == "BR-004" for f in findings))
                    self.assertNotIn("SYNTHETIC_PRIVATE_ID", as_json(findings))

    def test_redirected_browser_ancestor_blocks_manifest_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            root = home / BrowserScanner.MAC_ROOTS["Chrome"]
            target = root / "Default/Extensions/fake/1/manifest.json"
            target.parent.mkdir(parents=True)
            target.write_text('{}', encoding="utf-8")
            ancestor = root.parent
            with (patch("security_audit.reporting._is_reparse_point",
                        side_effect=lambda path: path == ancestor),
                  patch("security_audit.scanners.browser._read_manifest",
                        return_value={"permissions": ["tabs"]}) as reader):
                findings = BrowserScanner().scan(Context(home, home, system="Darwin"))
            reader.assert_not_called()
            self.assertTrue(any(f.code == "BR-008" and f.location == "Chrome"
                                and f.status == Status.UNAVAILABLE for f in findings))

    def test_valid_snapshot_still_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            value = Snapshot("scope", {"a" * 64: Status.ISSUE})
            path.write_text(value.serialize(), encoding="utf-8")
            self.assertEqual(read_snapshot(path, "scope"), value)
            self.assertEqual(set(json.loads(path.read_text(encoding="utf-8"))),
                             {"schema_version", "identity_version", "scope", "findings"})
