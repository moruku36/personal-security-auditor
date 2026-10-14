"""Independent review fixtures; never open real browser data or change ACLs."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_audit.manual import read_bounded_json, read_record
from security_audit.model import Status
from security_audit.scanners.base import Context
from security_audit.scanners.browser import BrowserScanner, _read_manifest


class ReviewerBoundaryTests(unittest.TestCase):
    def fixture(self, home: Path, value: object) -> Path:
        path = home / BrowserScanner.MAC_ROOTS["Chrome"] \
            / "Default/Extensions/fake/1/manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def scan(self, home: Path):
        return BrowserScanner().scan(Context(home, home, system="Darwin"))

    def test_nested_duplicate_json_rejected_even_inside_array(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            for content in ('{"nested":{"result":"issues","result":"clear"}}',
                            '{"nested":[{"status":"issue","status":"pass"}]}'):
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        read_bounded_json(path, 512)

    def test_record_missing_unreadable_empty_and_clean_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            self.assertEqual(read_record(path), (Status.UNKNOWN, None))
            path.write_text('', encoding="utf-8")
            self.assertEqual(read_record(path), (Status.UNAVAILABLE, None))
            path.write_text('{"result":"clear","checked_on":"2020-01-01"}',
                            encoding="utf-8")
            self.assertEqual(read_record(path), (Status.PASS, "2020-01-01"))
            with patch("pathlib.Path.open", side_effect=PermissionError("synthetic")):
                self.assertEqual(read_record(path), (Status.UNAVAILABLE, None))

    def test_extension_root_read_failure_is_unavailable_instead_of_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            manifest = self.fixture(home, {})
            extension_root = manifest.parents[2]
            second = home / BrowserScanner.MAC_ROOTS["Chrome"] \
                / "Profile 1/Extensions/second/1/manifest.json"
            second.parent.mkdir(parents=True)
            second.write_text('{"permissions":["<all_urls>"]}', encoding="utf-8")
            original = Path.is_dir

            def inaccessible(path: Path) -> bool:
                if path == extension_root:
                    raise PermissionError("synthetic directory access denied")
                return original(path)

            with patch("pathlib.Path.is_dir", inaccessible):
                findings = self.scan(home)
            self.assertTrue(any(f.code == "BR-008" and f.status == Status.UNAVAILABLE
                                for f in findings))
            self.assertTrue(any(f.code == "BR-004" for f in findings))

    def test_reparse_at_each_browser_boundary_blocks_manifest_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            manifest = self.fixture(home, {"permissions": ["tabs"]})
            for boundary in (manifest.parents[5], manifest.parents[4], manifest.parents[3],
                             manifest.parents[2], manifest.parents[1], manifest.parent):
                with self.subTest(boundary=boundary):
                    with (patch("security_audit.reporting._is_reparse_point",
                                side_effect=lambda path, boundary=boundary: path == boundary),
                          patch("security_audit.scanners.browser._is_reparse_point",
                                side_effect=lambda path, boundary=boundary: path == boundary),
                          patch("security_audit.scanners.browser._read_manifest") as reader):
                        findings = self.scan(home)
                    reader.assert_not_called()
                    self.assertTrue(any(f.code == "BR-008" for f in findings))

    def test_legacy_permissions_case_and_non_host_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            for field in ("permissions", "optional_permissions"):
                for value, broad in ((["<ALL_URLS>"], True), (["HTTPS://*/*"], True),
                                     (["tabs", "all_urls", "https://example.org/*"], False),
                                     ([], False)):
                    with self.subTest(field=field, value=value):
                        self.fixture(home, {"manifest_version": 2, field: value})
                        findings = self.scan(home)
                        self.assertEqual(any(f.code == "BR-004" for f in findings), broad)

    def test_malformed_declaration_types_mark_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            for value in ({"permissions": "<all_urls>"},
                          {"permissions": [False, {"host": "<all_urls>"}]},
                          {"host_permissions": "<all_urls>"},
                          {"content_scripts": [{"matches": "<all_urls>"}]}):
                with self.subTest(value=value):
                    self.fixture(home, value)
                    findings = self.scan(home)
                    self.assertFalse(any(f.code == "BR-004" for f in findings))
                    self.assertTrue(any(f.code == "BR-008" for f in findings))

    def test_duplicate_manifest_permissions_do_not_erase_broad_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            path = self.fixture(home, {})
            path.write_text('{"permissions":["<all_urls>"],"permissions":[]}',
                            encoding="utf-8")
            findings = self.scan(home)
            self.assertTrue(any(f.code == "BR-008" for f in findings))

    def test_valid_and_invalid_typed_declarations_keep_issue_and_missing_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            self.fixture(home, {"permissions": ["<all_urls>", False]})
            findings = self.scan(home)
            self.assertTrue(any(f.code == "BR-004" for f in findings))
            self.assertTrue(any(f.code == "BR-008" for f in findings))

    def test_terminal_manifest_reparse_is_not_opened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            path = self.fixture(home, {"permissions": ["<all_urls>"]})
            for attribute in ("symbolic-link", "junction"):
                with self.subTest(attribute=attribute):
                    metadata = type("Metadata", (), {
                        "st_mode": 0o120777 if attribute == "symbolic-link" else 0o100644,
                        "st_size": 10,
                        "st_file_attributes": 0 if attribute == "symbolic-link" else 0x400,
                    })()
                    with (patch("pathlib.Path.lstat", return_value=metadata),
                          patch("pathlib.Path.open") as opened):
                        self.assertIsNone(_read_manifest(path, path.parents[3]))
                    opened.assert_not_called()

    def test_empty_browser_tree_does_not_claim_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            (home / BrowserScanner.MAC_ROOTS["Chrome"] / "Default/Extensions").mkdir(
                parents=True)
            findings = self.scan(home)
            self.assertFalse(any(f.status == Status.PASS for f in findings))
            self.assertFalse(any(f.code == "BR-008" for f in findings))
