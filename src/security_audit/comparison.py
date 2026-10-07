"""Opt-in local snapshots containing only opaque IDs, states and scan scope."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from security_audit.manual import read_bounded_json
from security_audit.model import Finding, Status
from security_audit.reporting import _has_reparse_ancestor, write_private
from security_audit.scanners.base import Context

SNAPSHOT_SCHEMA_VERSION = 1
IDENTITY_VERSION = 1
MAX_SNAPSHOT_BYTES = 1_000_000
MAX_FINDINGS = 5000
STATE_ORDER = {state: index for index, state in enumerate((
    Status.UNAVAILABLE, Status.UNKNOWN, Status.ISSUE, Status.NEEDS_REVIEW,
    Status.OBSERVED, Status.PASS,
))}
NOTICE = ("Missing IDs mean not observed in this scan, not resolved. "
          "Unknown/unavailable states and scan limits may hide findings. "
          "Counts, risk and manual review dates are not compared.")


@dataclass(frozen=True)
class Snapshot:
    scope: str
    states: dict[str, Status]

    def serialize(self) -> str:
        return json.dumps({
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "identity_version": IDENTITY_VERSION,
            "scope": self.scope,
            "findings": [{"id": identifier, "status": status.value}
                         for identifier, status in sorted(self.states.items())],
        }, indent=2) + "\n"


def scope_id(context: Context, categories: set[str]) -> str:
    # Scope is opaque; no home/repository path is written to the snapshot.
    value = [context.system, str(context.home.absolute()), str(context.repository.absolute()),
             context.full, sorted(categories)]
    return hashlib.sha256(json.dumps(value).encode("utf-8")).hexdigest()


def snapshot(findings: list[Finding], context: Context, categories: set[str]) -> Snapshot:
    states: dict[str, Status] = {}
    for finding in findings:
        previous = states.get(finding.id)
        if previous is None or STATE_ORDER[finding.status] < STATE_ORDER[previous]:
            states[finding.id] = finding.status
    if len(states) > MAX_FINDINGS:
        raise ValueError("Too many snapshot findings")
    return Snapshot(scope_id(context, categories), states)


def save_snapshot(path: Path, value: Snapshot) -> None:
    if _has_reparse_ancestor(path.parent):
        raise ValueError("Snapshot path contains a link or reparse point")
    content = value.serialize()
    if len(content.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot exceeds limit")
    write_private(path, content)


def read_snapshot(path: Path, expected_scope: str) -> Snapshot:
    value = read_bounded_json(path, MAX_SNAPSHOT_BYTES)
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "identity_version", "scope", "findings"
    }:
        raise ValueError("Invalid snapshot schema")
    if (type(value["schema_version"]) is not int
            or value["schema_version"] != SNAPSHOT_SCHEMA_VERSION
            or type(value["identity_version"]) is not int
            or value["identity_version"] != IDENTITY_VERSION):
        raise ValueError("Incompatible snapshot version")
    if value["scope"] != expected_scope:
        raise ValueError("Different scan scope")
    entries = value["findings"]
    if not isinstance(entries, list) or len(entries) > MAX_FINDINGS:
        raise ValueError("Invalid snapshot findings")
    states: dict[str, Status] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "status"}:
            raise ValueError("Invalid snapshot finding")
        identifier = entry["id"]
        if (not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier)
                or identifier in states or not isinstance(entry["status"], str)):
            raise ValueError("Invalid snapshot identity")
        states[identifier] = Status(entry["status"])
    return Snapshot(expected_scope, states)


def compare(previous: Snapshot, current: Snapshot) -> str:
    if previous.scope != current.scope:
        raise ValueError("Different scan scope")
    lines = ["Local finding comparison", NOTICE]
    for identifier in sorted(previous.states.keys() | current.states.keys()):
        before = previous.states.get(identifier)
        after = current.states.get(identifier)
        if before == after:
            continue
        if before is None and after is not None:
            description = "newly observed: " + after.value
        elif after is None and before is not None:
            description = "not observed now (previous: " + before.value + ")"
        else:
            assert before is not None and after is not None
            description = before.value + " -> " + after.value
        lines.append(identifier + ": " + description)
    if len(lines) == 2:
        lines.append("No ID/state changes; this does not prove safety.")
    return "\n".join(lines) + "\n"
