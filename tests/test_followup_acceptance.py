"""Follow-up acceptance using only bounded synthetic files and metadata."""
from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from security_audit.manual import read_bounded_json, read_record
from security_audit.model import Status
from security_audit.reporting import _has_reparse_ancestor
from security_audit.scanners.base import Context
from security_audit.scanners.browser import MAX_MANIFEST_BYTES, BrowserScanner, _read_manifest


class FollowupAcceptanceTests(unittest.TestCase):
    def test_growing_manifest_is_rejected_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory).resolve()
            path = profile / "manifest.json"
            path.write_text('{}', encoding="utf-8")
            original_open = Path.open

            def grow(target: Path, mode: str = "r", **kwargs):
                if target == path and mode == "r":
                    with original_open(path, "w", encoding="utf-8") as writer:
                        writer.write(" " * (MAX_MANIFEST_BYTES + 2) + '{}')
                return original_open(target, mode, **kwargs)

            with (patch("pathlib.Path.open", grow),
                  patch("security_audit.scanners.browser.json.loads") as parse):
                self.assertIsNone(_read_manifest(path, profile))
            parse.assert_not_called()

    def test_junction_attribute_on_ancestor_blocks_manifest_reader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            root = home / BrowserScanner.MAC_ROOTS["Chrome"]
            path = root / "Default/Extensions/fake/1/manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text('{}', encoding="utf-8")
            ancestor = root.parent
            original_lstat = Path.lstat

            def reparse(target: Path):
                if target == ancestor:
                    return SimpleNamespace(st_mode=stat.S_IFDIR,
                                           st_file_attributes=getattr(
                                               stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                return original_lstat(target)

            with (patch("pathlib.Path.lstat", reparse),
                  patch("security_audit.scanners.browser._read_manifest") as reader):
                findings = BrowserScanner().scan(Context(home, home, system="Darwin"))
            reader.assert_not_called()
            self.assertTrue(any(f.code == "BR-008" and f.location == "Chrome"
                                and f.status == Status.UNAVAILABLE for f in findings))

    def test_duplicate_keys_at_every_json_depth_and_escaped_spelling(self) -> None:
        fixtures = (
            '{"outer":{"status":"issue","status":"pass"}}',
            '{"outer":[{"nested":{"id":"first","id":"second"}}]}',
            '{"result":"issues","\\u0072esult":"clear","checked_on":"2020-01-01"}',
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            for content in fixtures:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        read_bounded_json(path, 512)

    def test_missing_empty_malformed_unchecked_and_clear_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            self.assertEqual(read_record(path), (Status.UNKNOWN, None))
            for content in ("", "{}", "[]", '{"result":"clear"}', "null"):
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    self.assertEqual(read_record(path), (Status.UNAVAILABLE, None))
            path.write_text(json.dumps({"result": "unchecked", "checked_on": None}),
                            encoding="utf-8")
            self.assertEqual(read_record(path), (Status.UNKNOWN, None))
            path.write_text(json.dumps({"result": "clear", "checked_on": "2020-01-01"}),
                            encoding="utf-8")
            self.assertEqual(read_record(path), (Status.PASS, "2020-01-01"))

    def test_real_temporary_symlink_boundary_if_host_allows_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root / "outside"
            outside.mkdir()
            (outside / "record.json").write_text('{}', encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("Host disallows unprivileged temporary symlink creation")
            try:
                self.assertTrue(_has_reparse_ancestor(link / "record.json"))
                self.assertEqual(read_record(link / "record.json"), (Status.UNAVAILABLE, None))
            finally:
                link.unlink()
