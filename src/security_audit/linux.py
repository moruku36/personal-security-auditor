"""Read-only Linux probes reduced to fixed vocabulary tokens.

Every probe reads a small, bounded kernel or configuration fact that an
unprivileged user can normally read (``/proc``, ``/sys``, ``/etc``) or runs one
fixed, absolute-path status command. Nothing here needs root, changes a
setting, opens a credential file or returns raw file/command content. A probe
that cannot decide returns ``unknown``; an environment outside what this adapter
handles returns ``not_supported``.
"""
from __future__ import annotations

import ipaddress
import itertools
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from security_audit.safety import run

Runner = Callable[[list[str]], tuple[int, str]]
DeviceResolver = Callable[[str], tuple[int, int] | None]

MAX_TEXT_BYTES = 4096
MAX_MOUNTINFO_BYTES = 2_000_000
MAX_PROC_NET_BYTES = 2_000_000
MAX_PROC_NET_LINES = 20_000
MAX_BLOCK_NODES = 32
MAX_SLAVES = 16
MAX_ENDPOINTS = 50
# cryptsetup UUID prefixes that denote encryption. CRYPT-VERITY-/CRYPT-INTEGRITY- are
# integrity layers, not encryption, and must not count.
ENCRYPTION_UUID_PREFIXES = ("CRYPT-LUKS1-", "CRYPT-LUKS2-", "CRYPT-PLAIN-", "CRYPT-TCRYPT-",
                            "CRYPT-BITLK-", "CRYPT-FVAULT2-")
SECURE_BOOT_VARIABLE = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
SSH_UNITS = ("ssh.service", "sshd.service", "ssh.socket", "sshd.socket")
ACTIVE_STATES = frozenset({"active", "activating", "reloading"})


def _resolve_block_device(path: str) -> tuple[int, int] | None:
    """Return major/minor of an existing /dev block node without opening it."""
    if sys.platform == "win32":
        return None
    if not path.startswith("/dev/"):
        return None
    try:
        metadata = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISBLK(metadata.st_mode):
        return None
    return os.major(metadata.st_rdev), os.minor(metadata.st_rdev)


@dataclass(frozen=True)
class LinuxSources:
    """Where probes read from. Tests inject synthetic trees; production uses the host."""

    proc: Path = Path("/proc")
    sys: Path = Path("/sys")
    etc: Path = Path("/etc")
    runtime: Path = Path("/run")
    systemctl: tuple[str, ...] = ("/usr/bin/systemctl", "/bin/systemctl")
    firewall_cmd: tuple[str, ...] = ("/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd")
    runner: Runner = run
    resolve_device: DeviceResolver = _resolve_block_device


def read_bytes(path: Path, limit: int, *, prefix: bool = False) -> bytes:
    """Read a regular file without following a final symlink.

    Raises FileNotFoundError/OSError when unreadable and ValueError when the file is
    not regular or larger than ``limit`` (unless only a prefix was requested).
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Not a regular file")
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            # seq_file backed /proc entries return short reads; loop until EOF.
            chunk = os.read(descriptor, limit + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > limit:
        if prefix:
            return data[:limit]
        raise ValueError("File exceeds limit")
    return data


def read_text(path: Path, limit: int = MAX_TEXT_BYTES, *, prefix: bool = False) -> str:
    return read_bytes(path, limit, prefix=prefix).decode("utf-8", errors="replace")


def first_existing(candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        try:
            if Path(candidate).is_file():
                return candidate
        except OSError:
            continue
    return None


def is_wsl(source: LinuxSources) -> bool:
    """Heuristic only: the WSL kernel release string names Microsoft/WSL."""
    try:
        release = read_text(source.proc / "sys" / "kernel" / "osrelease", 256).lower()
    except (OSError, ValueError):
        return False
    return "microsoft" in release or "wsl" in release


# --- disk encryption -------------------------------------------------------

def _root_mount_source(mountinfo: str) -> str | None:
    """Source of the last mount whose mount point is "/" (the visible root)."""
    source: str | None = None
    for line in mountinfo.splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        if not separator or len(fields) < 5 or fields[4] != "/":
            continue
        tail = right.split()
        if len(tail) >= 2:
            source = tail[1]
    return source


def _parse_device_numbers(text: str) -> tuple[int, int] | None:
    major, separator, minor = text.strip().partition(":")
    if not separator or not major.isdecimal() or not minor.isdecimal():
        return None
    return int(major), int(minor)


def _crypt_layer_below(sys_root: Path, start: tuple[int, int]) -> str:
    """Walk block-device slaves from the root device looking for a dm-crypt target."""
    pending = [start]
    seen: set[tuple[int, int]] = set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        if len(seen) >= MAX_BLOCK_NODES:
            return "unknown"
        seen.add(node)
        base = sys_root / "dev" / "block" / f"{node[0]}:{node[1]}"
        try:
            if not base.is_dir():
                return "unknown"
            try:
                uuid = read_text(base / "dm" / "uuid", 16, prefix=True)
            except FileNotFoundError:
                uuid = ""
            if uuid.startswith(ENCRYPTION_UUID_PREFIXES):
                return "on"
            try:
                names = sorted(entry.name for entry in
                               itertools.islice((base / "slaves").iterdir(), MAX_SLAVES + 1))
            except FileNotFoundError:
                names = []
            if len(names) > MAX_SLAVES:
                return "unknown"
            for name in names:
                parsed = _parse_device_numbers(
                    read_text(base / "slaves" / name / "dev", 32))
                if parsed is None:
                    return "unknown"
                pending.append(parsed)
        except (OSError, ValueError):
            return "unknown"
    return "not_detected"


def disk_encryption(source: LinuxSources) -> str:
    """on | not_detected | unknown | not_supported (dm-crypt under the root filesystem only)."""
    try:
        mountinfo = read_text(source.proc / "self" / "mountinfo", MAX_MOUNTINFO_BYTES)
    except FileNotFoundError:
        return "not_supported"
    except (OSError, ValueError):
        return "unknown"
    root_source = _root_mount_source(mountinfo)
    if root_source is None:
        return "unknown"
    device = source.resolve_device(root_source)
    if device is None:
        # overlay/tmpfs/network/ZFS roots or a node that cannot be resolved here.
        return "not_supported"
    return _crypt_layer_below(source.sys, device)


# --- firewall ---------------------------------------------------------------

def firewall_state(source: LinuxSources) -> str:
    """ufw_enabled | firewalld_running | manager_disabled | not_detected | unknown."""
    states: set[str] = set()
    configuration: str | None = None
    try:
        configuration = read_text(source.etc / "ufw" / "ufw.conf")
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        states.add("unknown")
    if configuration is not None:
        value = ""
        for line in configuration.splitlines():
            key, separator, rest = line.partition("=")
            if separator and key.strip() == "ENABLED":
                value = rest.strip().strip("\"'").lower()
        states.add({"yes": "ufw_enabled", "no": "manager_disabled"}.get(value, "unknown"))
    command = first_existing(source.firewall_cmd)
    if command is not None:
        code, output = source.runner([command, "--state"])
        answer = output.strip().lower()
        if code == 0 and answer == "running":
            states.add("firewalld_running")
        elif answer == "not running":
            states.add("manager_disabled")
        else:
            states.add("unknown")
    for state in ("ufw_enabled", "firewalld_running", "unknown", "manager_disabled"):
        if state in states:
            return state
    return "not_detected"


# --- mandatory access control ----------------------------------------------

def _active_security_modules(source: LinuxSources) -> set[str] | None:
    """Active LSM names, or None when the kernel does not expose them to this user."""
    try:
        listing = read_text(source.sys / "kernel" / "security" / "lsm", 512)
        return {name for name in listing.strip().lower().split(",") if name}
    except (OSError, ValueError):
        pass
    # securityfs is not exposed: fall back to the per-LSM interfaces.
    modules: set[str] = set()
    try:
        if read_text(source.sys / "fs" / "selinux" / "enforce", 8).strip() in ("0", "1"):
            modules.add("selinux")
    except (OSError, ValueError):
        pass
    try:
        enabled = read_text(source.sys / "module" / "apparmor" / "parameters" / "enabled", 8)
        if enabled.strip().upper() == "Y":
            modules.add("apparmor")
    except (OSError, ValueError):
        pass
    return modules or None


def mandatory_access_control(source: LinuxSources) -> str:
    """selinux_enforcing | selinux_permissive | selinux_unknown | apparmor | none | unknown."""
    modules = _active_security_modules(source)
    if modules is None:
        return "unknown"
    if "selinux" in modules:
        try:
            value = read_text(source.sys / "fs" / "selinux" / "enforce", 8).strip()
        except (OSError, ValueError):
            return "selinux_unknown"
        return {"1": "selinux_enforcing", "0": "selinux_permissive"}.get(value, "selinux_unknown")
    if "apparmor" in modules:
        return "apparmor"
    return "none"


# --- Secure Boot ------------------------------------------------------------

def secure_boot(source: LinuxSources) -> str:
    """on | off | unknown | not_supported (non-UEFI or firmware interface not visible)."""
    efi = source.sys / "firmware" / "efi"
    try:
        if not efi.is_dir():
            return "not_supported"
        data = read_bytes(efi / "efivars" / SECURE_BOOT_VARIABLE, 16)
    except (OSError, ValueError):
        return "unknown"
    # efivarfs prepends four attribute bytes to the one-byte boolean value.
    if len(data) == 5 and data[4] in (0, 1):
        return "on" if data[4] == 1 else "off"
    return "unknown"


# --- SSH server (systemd only) ---------------------------------------------

def _properties(block: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in block.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key] = value
    return result


def ssh_server_state(source: LinuxSources) -> str:
    """active | inactive | not_installed | not_supported | unknown."""
    try:
        if not (source.runtime / "systemd" / "system").is_dir():
            return "not_supported"
    except OSError:
        return "unknown"
    command = first_existing(source.systemctl)
    if command is None:
        return "unknown"
    code, output = source.runner(
        [command, "show", "-p", "LoadState", "-p", "ActiveState", *SSH_UNITS])
    if code != 0:
        return "unknown"
    blocks = [_properties(block) for block in output.strip().split("\n\n") if block.strip()]
    if len(blocks) != len(SSH_UNITS):
        return "unknown"
    loaded = False
    missing = 0
    for properties in blocks:
        load, active = properties.get("LoadState", ""), properties.get("ActiveState", "")
        if not load or not active:
            return "unknown"
        if load == "loaded" and active in ACTIVE_STATES:
            return "active"
        loaded = loaded or load in ("loaded", "masked")
        missing += load == "not-found"
    if loaded:
        return "inactive"
    return "not_installed" if missing == len(blocks) else "unknown"


# --- TCP listeners ----------------------------------------------------------

def _decode_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    if len(raw) == 4:
        return ipaddress.IPv4Address(raw[::-1])
    if len(raw) == 16:
        # Four 32-bit words, each stored in host (little-endian) byte order.
        return ipaddress.IPv6Address(b"".join(raw[index:index + 4][::-1]
                                              for index in range(0, 16, 4)))
    return None


def _bind_class(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """"*" for wildcard, "network" for a specific non-loopback address, None for loopback."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback:
        return None
    return "*" if address.is_unspecified else "network"


def _listeners_from(text: str, endpoints: set[tuple[int, str]]) -> bool:
    """Collect LISTEN sockets; returns False if the table was malformed or too long."""
    complete = True
    for index, line in enumerate(text.splitlines()[1:]):
        if index >= MAX_PROC_NET_LINES:
            return False
        fields = line.split()
        if len(fields) < 4:
            complete = False
            continue
        if fields[3] != "0A":
            continue
        host, separator, port_text = fields[1].partition(":")
        address = _decode_address(host)
        try:
            port = int(port_text, 16)
        except ValueError:
            port = 0
        if not separator or address is None or not 1 <= port <= 65535:
            complete = False
            continue
        bind = _bind_class(address)
        if bind is not None:
            endpoints.add((port, bind))
    return complete


def tcp_listeners(source: LinuxSources) -> tuple[list[tuple[int, str]], bool] | None:
    """Non-loopback listeners from the kernel TCP tables, or None if unreadable.

    The bool is False when the result is partial. Addresses and owning processes
    are never returned; only a port and a "*"/"network" class.
    """
    endpoints: set[tuple[int, str]] = set()
    complete = True
    for index, name in enumerate(("tcp", "tcp6")):
        try:
            text = read_text(source.proc / "net" / name, MAX_PROC_NET_BYTES)
        except FileNotFoundError:
            if index == 0:
                return None
            continue  # IPv6 may be disabled; the IPv4 table is the required one.
        except (OSError, ValueError):
            if index == 0:
                return None
            complete = False
            continue
        complete = _listeners_from(text, endpoints) and complete
    ordered = sorted(endpoints)
    if len(ordered) > MAX_ENDPOINTS:
        return ordered[:MAX_ENDPOINTS], False
    return ordered, complete
