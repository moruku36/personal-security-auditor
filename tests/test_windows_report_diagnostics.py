"""Synthetic checks for diagnostic redaction and behavior preservation."""
from __future__ import annotations

import errno
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from windows_report_diagnostics import capture_report_diagnostics

from security_audit import cli, windows

CANARY = "SYNTHETIC_DIAGNOSTIC_CANARY"


class DiagnosticTests(unittest.TestCase):
    def test_subprocess_outcomes_are_allowlisted_and_preserve_behavior(self) -> None:
        cases = [
            (subprocess.TimeoutExpired(CANARY, 45, output=CANARY, stderr=CANARY), "TIMEOUT"),
            (OSError(CANARY), "OS_ERROR"),
            (subprocess.SubprocessError(CANARY), "SUBPROCESS_ERROR"),
            (subprocess.CompletedProcess([CANARY], 1, CANARY, CANARY), "NONZERO_EXIT"),
            (subprocess.CompletedProcess([CANARY], 0, "FAILED_save", CANARY), "ACL_SAVE_FAILED"),
            (subprocess.CompletedProcess([CANARY], 0, CANARY, CANARY), "ACL_UNEXPECTED_OUTPUT"),
            (subprocess.CompletedProcess([CANARY], 0, "OK", CANARY), "ACL_OK"),
        ]
        for outcome, expected in cases:
            with self.subTest(reason=expected):
                events: list[dict[str, str | int]] = []
                execute = Mock()
                if isinstance(outcome, BaseException):
                    execute.side_effect = outcome
                else:
                    execute.return_value = outcome
                with (patch.object(windows.subprocess, "run", execute),
                      capture_report_diagnostics(events)):
                    args = ([CANARY, windows.PRIVATE_ACL_SCRIPT],)
                    kwargs = {"timeout": 45, "env": {"FAKE": CANARY}}
                    if isinstance(outcome, BaseException):
                        with self.assertRaises(type(outcome)) as caught:
                            windows.subprocess.run(*args, **kwargs)
                        self.assertIs(caught.exception, outcome)
                    else:
                        self.assertIs(windows.subprocess.run(*args, **kwargs), outcome)
                    execute.assert_called_once_with(*args, **kwargs)
                self.assertEqual(events[0]["reason"], expected)
                self.assertEqual(events[0]["stage"], "PRIVATE_ACL")
                self.assertIsInstance(events[0]["elapsed_ms"], int)
                self.assertNotIn(CANARY, json.dumps(events))

    def test_report_error_is_redacted_and_original_exception_rethrown(self) -> None:
        for error, expected in ((OSError(errno.EACCES, CANARY), "REPORT_PERMISSION_DENIED"),
                                (OSError(CANARY), "REPORT_OS_ERROR"),
                                (ValueError(CANARY), "REPORT_VALUE_ERROR")):
            with self.subTest(reason=expected):
                events: list[dict[str, str | int]] = []
                with (patch.object(cli, "write_private", side_effect=error) as writer,
                      capture_report_diagnostics(events)):
                    with self.assertRaises(type(error)) as caught:
                        cli.write_private(Path(CANARY), CANARY)
                    self.assertIs(caught.exception, error)
                    writer.assert_called_once_with(Path(CANARY), CANARY)
                self.assertEqual(events[0]["reason"], expected)
                self.assertNotIn(CANARY, json.dumps(events))
