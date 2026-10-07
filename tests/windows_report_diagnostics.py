"""Test-only fixed-vocabulary diagnostics; never emit command or exception contents."""
from __future__ import annotations

import errno
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

from security_audit import cli, windows

ACL_RESULTS = {
    "OK": "ACL_OK",
    "FAILED_read": "ACL_READ_FAILED",
    "FAILED_protect": "ACL_PROTECT_FAILED",
    "FAILED_purge": "ACL_PURGE_FAILED",
    "FAILED_grant": "ACL_GRANT_FAILED",
    "FAILED_save": "ACL_SAVE_FAILED",
}


@contextmanager
def capture_report_diagnostics(events: list[dict[str, str | int]]) -> Iterator[None]:
    """Observe the unchanged report/subprocess calls and rethrow original exceptions."""
    execute = windows.subprocess.run
    write_report = cli.write_private

    def emit(stage: str, reason: str, started: float) -> None:
        events.append({"stage": stage, "reason": reason,
                       "elapsed_ms": int((time.monotonic() - started) * 1000)})

    def measured_run(*args: Any, **kwargs: Any) -> Any:
        command = args[0] if args else kwargs.get("args")
        script = command[-1] if isinstance(command, (list, tuple)) and command else None
        stage = ("PRIVATE_ACL" if script == windows.PRIVATE_ACL_SCRIPT else
                 "ACL_READ" if script == windows.ACL_SCRIPT else "OTHER_SUBPROCESS")
        started = time.monotonic()
        try:
            result = execute(*args, **kwargs)
        except subprocess.TimeoutExpired:
            emit(stage, "TIMEOUT", started)
            raise
        except OSError:
            emit(stage, "OS_ERROR", started)
            raise
        except subprocess.SubprocessError:
            emit(stage, "SUBPROCESS_ERROR", started)
            raise
        if result.returncode != 0:
            reason = "NONZERO_EXIT"
        elif stage == "PRIVATE_ACL":
            reason = ACL_RESULTS.get(result.stdout[:8192].strip(), "ACL_UNEXPECTED_OUTPUT")
        elif stage == "ACL_READ":
            reason = {"PRIVATE": "ACL_PRIVATE", "BROAD": "ACL_BROAD",
                      "UNKNOWN": "ACL_UNKNOWN"}.get(result.stdout[:8192].strip(),
                                                   "ACL_UNEXPECTED_OUTPUT")
        else:
            reason = "PROCESS_OK"
        emit(stage, reason, started)
        return result

    def measured_write(*args: Any, **kwargs: Any) -> None:
        started = time.monotonic()
        try:
            write_report(*args, **kwargs)
        except OSError as error:
            reason = {errno.EACCES: "REPORT_PERMISSION_DENIED",
                      errno.EPERM: "REPORT_PERMISSION_DENIED"}.get(error.errno, "REPORT_OS_ERROR")
            emit("REPORT", reason, started)
            raise
        except ValueError:
            emit("REPORT", "REPORT_VALUE_ERROR", started)
            raise
        emit("REPORT", "REPORT_OK", started)

    with (patch.object(windows.subprocess, "run", side_effect=measured_run),
          patch.object(cli, "write_private", side_effect=measured_write)):
        yield
