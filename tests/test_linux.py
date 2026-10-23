"""Linux adapter tests. Synthetic /proc, /sys and /etc trees only; never the host."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from collections.abc import Callable
from functools import partial
from pathlib import Path
from unittest.mock import patch

from security_audit import linux
from security_audit.cli import main
from security_audit.coverage import rows
from security_audit.engine import scan
from security_audit.linux import LinuxSources
from security_audit.model import Evidence, Finding, Risk, Status
from security_audit.remediation import target
from security_audit.reporting import as_json
from security_audit.scanners.base import Context
from security_audit.scanners.browser import BrowserScanner, _linux_policy_status
from security_audit.scanners.network import NetworkScanner
from security_audit.scanners.os_security import OSScanner

CANARY = "SYNTHETIC_CANARY_DO_NOT_REPORT"
SECURE_BOOT = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
Runner = Callable[[list[str]], tuple[int, str]]


def put(path: Path, content: str | bytes = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def no_command(argv: list[str]) -> tuple[int, str]:
    raise AssertionError("a command was run")


class Tree:
    """A synthetic host: proc/sys/etc/run directories plus injectable commands."""

    def __init__(self, base: Path, runner: Runner = no_command,
                 devices: dict[str, tuple[int, int]] | None = None) -> None:
        self.base = base
        self.devices = devices or {}
        self.calls: list[list[str]] = []
        self._runner = runner
        self.systemctl = put(base / "bin" / "systemctl")
        self.firewall_cmd = base / "bin" / "firewall-cmd"  # absent unless a test creates it

    def run(self, argv: list[str]) -> tuple[int, str]:
        self.calls.append(argv)
        return self._runner(argv)

    @property
    def sources(self) -> LinuxSources:
        return LinuxSources(
            proc=self.base / "proc", sys=self.base / "sys", etc=self.base / "etc",
            runtime=self.base / "run", systemctl=(str(self.systemctl),),
            firewall_cmd=(str(self.firewall_cmd),), runner=self.run,
            resolve_device=lambda path: self.devices.get(path))

    def context(self, home: Path) -> Context:
        return Context(home, home, system="Linux", linux=self.sources)

    def block(self, major: int, minor: int, *, uuid: str | None = None,
              slaves: tuple[tuple[str, int, int], ...] = ()) -> None:
        node = self.base / "sys" / "dev" / "block" / f"{major}:{minor}"
        node.mkdir(parents=True, exist_ok=True)
        if uuid is not None:
            put(node / "dm" / "uuid", uuid + "\n")
        for name, slave_major, slave_minor in slaves:
            put(node / "slaves" / name / "dev", f"{slave_major}:{slave_minor}\n")

    def root_mount(self, source: str, fstype: str = "ext4") -> None:
        put(self.base / "proc" / "self" / "mountinfo",
            "22 1 0:21 / /sys rw - sysfs sysfs rw\n"
            f"36 35 98:0 / / rw,noatime - {fstype} {source} rw\n")


class TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.base = Path(self._directory.name).resolve()
        self.home = self.base / "home"
        self.home.mkdir()


class DiskEncryptionTests(TempCase):
    def test_dm_crypt_directly_under_root_is_on(self) -> None:
        tree = Tree(self.base, devices={"/dev/mapper/root": (253, 0)})
        tree.root_mount("/dev/mapper/root")
        tree.block(253, 0, uuid="CRYPT-LUKS2-" + CANARY + "-root")
        self.assertEqual(linux.disk_encryption(tree.sources), "on")

    def test_lvm_on_luks_is_found_through_slaves(self) -> None:
        tree = Tree(self.base, devices={"/dev/mapper/vg-root": (253, 1)})
        tree.root_mount("/dev/mapper/vg-root")
        tree.block(253, 1, uuid="LVM-abc", slaves=(("dm-0", 253, 0),))
        tree.block(253, 0, uuid="CRYPT-LUKS2-abc-luks", slaves=(("sda2", 8, 2),))
        tree.block(8, 2)
        self.assertEqual(linux.disk_encryption(tree.sources), "on")

    def test_integrity_and_verity_layers_are_not_counted_as_encryption(self) -> None:
        for prefix in ("CRYPT-VERITY-", "CRYPT-INTEGRITY-", "LVM-", "mpath-", ""):
            with self.subTest(prefix=prefix):
                tree = Tree(self.base / (prefix or "none").strip("-"),
                            devices={"/dev/mapper/root": (253, 0)})
                tree.root_mount("/dev/mapper/root")
                tree.block(253, 0, uuid=prefix + "abc", slaves=(("sda2", 8, 2),))
                tree.block(8, 2)
                self.assertEqual(linux.disk_encryption(tree.sources), "not_detected")
        for prefix in linux.ENCRYPTION_UUID_PREFIXES:
            with self.subTest(prefix=prefix):
                tree = Tree(self.base / prefix.strip("-"), devices={"/dev/mapper/root": (253, 0)})
                tree.root_mount("/dev/mapper/root")
                tree.block(253, 0, uuid=prefix + "abc")
                self.assertEqual(linux.disk_encryption(tree.sources), "on")

    def test_plain_partition_is_not_detected_rather_than_issue(self) -> None:
        tree = Tree(self.base, devices={"/dev/sda2": (8, 2)})
        tree.root_mount("/dev/sda2")
        tree.block(8, 2)
        self.assertEqual(linux.disk_encryption(tree.sources), "not_detected")
        findings = OSScanner().scan(tree.context(self.home))
        finding = next(item for item in findings if item.code == "OS-L01")
        self.assertEqual(finding.status, Status.NEEDS_REVIEW)
        self.assertNotEqual(finding.status, Status.ISSUE)
        self.assertTrue(any("not evidence" in text for text in finding.limitations))

    def test_overlay_zfs_and_missing_mountinfo_are_not_supported(self) -> None:
        tree = Tree(self.base)
        tree.root_mount("overlay", "overlay")
        self.assertEqual(linux.disk_encryption(tree.sources), "not_supported")
        self.assertEqual(linux.disk_encryption(Tree(self.base / "empty").sources),
                         "not_supported")

    def test_unreadable_or_oversized_stack_is_unknown_not_pass(self) -> None:
        tree = Tree(self.base, devices={"/dev/mapper/x": (253, 5)})
        tree.root_mount("/dev/mapper/x")
        self.assertEqual(linux.disk_encryption(tree.sources), "unknown")  # sysfs node missing
        tree.block(253, 5, uuid="LVM-x", slaves=(("dm-9", 253, 9),))  # slave node missing
        self.assertEqual(linux.disk_encryption(tree.sources), "unknown")
        many = tuple((f"s{index}", 9, index) for index in range(linux.MAX_SLAVES + 1))
        tree.block(253, 5, slaves=many)
        self.assertEqual(linux.disk_encryption(tree.sources), "unknown")

    def test_last_root_mount_wins_and_mount_source_is_never_reported(self) -> None:
        tree = Tree(self.base, devices={"/dev/mapper/final": (253, 0)})
        put(self.base / "proc" / "self" / "mountinfo",
            "1 0 0:1 / / rw - rootfs rootfs rw\n"
            f"2 1 0:2 / / rw - ext4 /dev/{CANARY} rw\n"
            "3 2 0:3 / / rw - ext4 /dev/mapper/final rw\n")
        tree.block(253, 0, uuid="CRYPT-PLAIN-final")
        self.assertEqual(linux.disk_encryption(tree.sources), "on")
        self.assertNotIn(CANARY, as_json(OSScanner().scan(tree.context(self.home))))


class FirewallTests(TempCase):
    def tree(self, runner: Runner = no_command) -> Tree:
        return Tree(self.base, runner)

    def test_ufw_configuration_values(self) -> None:
        for content, expected in (("ENABLED=yes\n", "ufw_enabled"),
                                  ('ENABLED="no"\n', "manager_disabled"),
                                  ("ENABLED=maybe\n", "unknown"), ("garbage", "unknown")):
            with self.subTest(content=content):
                tree = self.tree()
                put(self.base / "etc" / "ufw" / "ufw.conf", content)
                self.assertEqual(linux.firewall_state(tree.sources), expected)

    def test_firewalld_states_use_fixed_command(self) -> None:
        for code, output, expected in ((0, "running\n", "firewalld_running"),
                                       (252, "not running\n", "manager_disabled"),
                                       (1, "boom " + CANARY, "unknown"),
                                       (0, "unexpected", "unknown")):
            with self.subTest(output=output):
                tree = self.tree(lambda argv, c=code, o=output: (c, o))
                put(tree.firewall_cmd)
                self.assertEqual(linux.firewall_state(tree.sources), expected)
                self.assertEqual(tree.calls, [[str(tree.firewall_cmd), "--state"]])

    def test_no_manager_is_unknown_status_and_never_pass(self) -> None:
        tree = self.tree()
        self.assertEqual(linux.firewall_state(tree.sources), "not_detected")
        finding = next(item for item in OSScanner().scan(tree.context(self.home))
                       if item.code == "OS-L02")
        self.assertEqual(finding.status, Status.UNKNOWN)

    def test_disabled_ufw_is_review_with_nftables_caveat_not_high_issue(self) -> None:
        tree = self.tree()
        put(self.base / "etc" / "ufw" / "ufw.conf", "ENABLED=no\n")
        finding = next(item for item in OSScanner().scan(tree.context(self.home))
                       if item.code == "OS-L02")
        self.assertEqual((finding.status, finding.risk), (Status.NEEDS_REVIEW, Risk.MEDIUM))
        self.assertTrue(any("nftables" in text for text in finding.limitations))


class SecurityModuleTests(TempCase):
    def test_active_module_list_and_selinux_mode(self) -> None:
        tree = Tree(self.base)
        lsm = self.base / "sys" / "kernel" / "security" / "lsm"
        put(lsm, "lockdown,capability,landlock,yama,apparmor\n")
        self.assertEqual(linux.mandatory_access_control(tree.sources), "apparmor")
        put(lsm, "capability,yama\n")
        self.assertEqual(linux.mandatory_access_control(tree.sources), "none")
        put(lsm, "capability,selinux\n")
        enforce = self.base / "sys" / "fs" / "selinux" / "enforce"
        for value, expected in (("1", "selinux_enforcing"), ("0", "selinux_permissive"),
                                ("x", "selinux_unknown")):
            put(enforce, value)
            self.assertEqual(linux.mandatory_access_control(tree.sources), expected)
        enforce.unlink()
        self.assertEqual(linux.mandatory_access_control(tree.sources), "selinux_unknown")

    def test_without_securityfs_falls_back_or_stays_unknown(self) -> None:
        tree = Tree(self.base)
        self.assertEqual(linux.mandatory_access_control(tree.sources), "unknown")
        put(self.base / "sys" / "module" / "apparmor" / "parameters" / "enabled", "Y\n")
        self.assertEqual(linux.mandatory_access_control(tree.sources), "apparmor")
        put(self.base / "sys" / "fs" / "selinux" / "enforce", "1")
        self.assertEqual(linux.mandatory_access_control(tree.sources), "selinux_enforcing")

    def test_none_is_low_review_and_apparmor_does_not_claim_confinement(self) -> None:
        tree = Tree(self.base)
        put(self.base / "sys" / "kernel" / "security" / "lsm", "capability\n")
        finding = next(item for item in OSScanner().scan(tree.context(self.home))
                       if item.code == "OS-L03")
        self.assertEqual((finding.status, finding.risk), (Status.NEEDS_REVIEW, Risk.LOW))
        put(self.base / "sys" / "kernel" / "security" / "lsm", "apparmor\n")
        finding = next(item for item in OSScanner().scan(tree.context(self.home))
                       if item.code == "OS-L03")
        self.assertEqual(finding.status, Status.OBSERVED)
        self.assertTrue(any("not inspected" in text for text in finding.limitations))


class SecureBootTests(TempCase):
    def test_variable_states(self) -> None:
        tree = Tree(self.base)
        self.assertEqual(linux.secure_boot(tree.sources), "not_supported")
        variable = self.base / "sys" / "firmware" / "efi" / "efivars" / SECURE_BOOT
        (self.base / "sys" / "firmware" / "efi").mkdir(parents=True)
        self.assertEqual(linux.secure_boot(tree.sources), "unknown")  # variable not visible
        for data, expected in ((b"\x07\x00\x00\x00\x01", "on"), (b"\x07\x00\x00\x00\x00", "off"),
                               (b"\x07\x00\x00\x00\x02", "unknown"), (b"\x01", "unknown"),
                               (b"", "unknown")):
            put(variable, data)
            self.assertEqual(linux.secure_boot(tree.sources), expected)

    def test_off_matches_windows_issue_semantics_and_legacy_boot_is_not_supported(self) -> None:
        tree = Tree(self.base)
        findings = {item.code: item for item in OSScanner().scan(tree.context(self.home))}
        self.assertEqual(findings["OS-L04"].status, Status.UNAVAILABLE)
        self.assertTrue(any(text.startswith("not_supported:")
                            for text in findings["OS-L04"].limitations))
        put(self.base / "sys" / "firmware" / "efi" / "efivars" / SECURE_BOOT,
            b"\x07\x00\x00\x00\x00")
        findings = {item.code: item for item in OSScanner().scan(tree.context(self.home))}
        self.assertEqual((findings["OS-L04"].status, findings["OS-L04"].risk),
                         (Status.ISSUE, Risk.MEDIUM))


def unit_block(load: str, active: str) -> str:
    return f"LoadState={load}\nActiveState={active}\n"


class SSHServerTests(TempCase):
    def tree(self, output: str, code: int = 0) -> Tree:
        tree = Tree(self.base, lambda argv: (code, output))
        (self.base / "run" / "systemd" / "system").mkdir(parents=True, exist_ok=True)
        return tree

    def test_states_from_systemd_blocks(self) -> None:
        missing = unit_block("not-found", "inactive")
        cases = (
            ("\n".join([missing, missing, unit_block("loaded", "active"), missing]), "active"),
            ("\n".join([unit_block("loaded", "inactive"), missing, missing, missing]), "inactive"),
            ("\n".join([unit_block("masked", "inactive")] + [missing] * 3), "inactive"),
            ("\n".join([missing] * 4), "not_installed"),
            ("\n".join([missing] * 3), "unknown"),
            ("garbage", "unknown"),
            ("\n".join([unit_block("error", "inactive")] + [missing] * 3), "unknown"),
        )
        for output, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(linux.ssh_server_state(self.tree(output).sources), expected)

    def test_socket_activation_counts_and_command_is_fixed(self) -> None:
        missing = unit_block("not-found", "inactive")
        tree = self.tree("\n".join([unit_block("loaded", "inactive"), missing, missing,
                                    unit_block("loaded", "active")]))
        # Output order follows the requested units; the last is sshd.socket.
        self.assertEqual(linux.ssh_server_state(tree.sources), "active")
        self.assertEqual(tree.calls, [[str(tree.systemctl), "show", "-p", "LoadState",
                                       "-p", "ActiveState", *linux.SSH_UNITS]])

    def test_failure_and_non_systemd_are_distinct(self) -> None:
        self.assertEqual(linux.ssh_server_state(self.tree("x", code=1).sources), "unknown")
        other = Tree(self.base / "openrc")
        self.assertEqual(linux.ssh_server_state(other.sources), "not_supported")
        self.assertEqual(other.calls, [])
        finding = next(item for item in OSScanner().scan(other.context(self.home))
                       if item.code == "OS-L05")
        self.assertEqual(finding.status, Status.UNAVAILABLE)

    def test_missing_systemctl_binary_is_unknown(self) -> None:
        tree = self.tree("")
        tree.systemctl.unlink()
        self.assertEqual(linux.ssh_server_state(tree.sources), "unknown")


def tcp_table(*rows_: tuple[str, str]) -> str:
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n"
    return header + "".join(
        f"   {index}: {address} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000\n"
        for index, (address, state) in enumerate(rows_))


class ListenerTests(TempCase):
    def test_wildcard_specific_and_loopback_classification(self) -> None:
        tree = Tree(self.base)
        put(self.base / "proc" / "net" / "tcp", tcp_table(
            ("00000000:1F90", "0A"),      # 0.0.0.0:8080 -> "*"
            ("0100007F:0050", "0A"),      # 127.0.0.1 -> loopback, skipped
            ("0200007F:0051", "0A"),      # 127.0.0.2 -> loopback range, skipped
            ("0A02A8C0:0016", "0A"),      # specific private address -> "network"
            ("00000000:0BB8", "01"),      # ESTABLISHED, ignored
        ))
        put(self.base / "proc" / "net" / "tcp6", tcp_table(
            ("00000000000000000000000000000000:0016", "0A"),            # [::]:22 -> "*"
            ("00000000000000000000000001000000:0277", "0A"),            # ::1 skipped
            ("0000000000000000FFFF00000100007F:0278", "0A"),            # ::ffff:127.0.0.1
            ("000080FE000000000000000000000001:0050", "0A"),            # link-local-ish
        ))
        result = linux.tcp_listeners(tree.sources)
        assert result is not None
        endpoints, complete = result
        self.assertTrue(complete)
        self.assertEqual(endpoints, [(22, "*"), (22, "network"), (80, "network"),
                                     (8080, "*")])

    def test_findings_redact_addresses_and_use_existing_location_shape(self) -> None:
        tree = Tree(self.base)
        put(self.base / "proc" / "net" / "tcp", tcp_table(("0A02A8C0:0016", "0A"),
                                                          ("00000000:1F90", "0A")))
        findings = NetworkScanner().scan(tree.context(self.home))
        self.assertEqual({item.location for item in findings},
                         {"non-loopback address:22", "*:8080"})
        report = as_json(scan(tree.context(self.home), "network"))
        for text in ("192.168", "10.168", "C0A8020A", "0A02A8C0"):
            self.assertNotIn(text, report)
        for item in findings:
            self.assertEqual((item.code, item.risk, item.status),
                             ("NET-001", Risk.HIGH, Status.NEEDS_REVIEW))
            self.assertTrue(any("namespace" in text for text in item.limitations))

    def test_missing_table_is_unavailable_and_partial_table_is_flagged(self) -> None:
        tree = Tree(self.base)
        findings = NetworkScanner().scan(tree.context(self.home))
        self.assertEqual([(item.code, item.status) for item in findings],
                         [("NET-000", Status.UNAVAILABLE)])
        put(self.base / "proc" / "net" / "tcp", tcp_table(("00000000:1F90", "0A"))
            + "short line\n   9: ZZZZ:0050 00000000:0000 0A x\n")
        codes = [(item.code, item.status) for item in NetworkScanner().scan(tree.context(self.home))]
        self.assertEqual(codes, [("NET-001", Status.NEEDS_REVIEW), ("NET-000", Status.UNAVAILABLE)])

    def test_missing_ipv6_table_is_fine_but_unreadable_one_is_incomplete(self) -> None:
        tree = Tree(self.base)
        put(self.base / "proc" / "net" / "tcp", tcp_table(("00000000:1F90", "0A")))
        result = linux.tcp_listeners(tree.sources)
        assert result is not None
        self.assertTrue(result[1])
        (self.base / "proc" / "net" / "tcp6").mkdir()  # a directory cannot be read as a table
        result = linux.tcp_listeners(tree.sources)
        assert result is not None
        self.assertFalse(result[1])

    def test_endpoint_cap_is_reported_as_incomplete(self) -> None:
        tree = Tree(self.base)
        put(self.base / "proc" / "net" / "tcp", tcp_table(
            *((f"00000000:{port:04X}", "0A") for port in range(1000, 1000 + linux.MAX_ENDPOINTS + 5))))
        result = linux.tcp_listeners(tree.sources)
        assert result is not None
        self.assertEqual((len(result[0]), result[1]), (linux.MAX_ENDPOINTS, False))

    def test_short_reads_are_followed_to_end_of_file(self) -> None:
        tree = Tree(self.base)
        put(self.base / "proc" / "net" / "tcp", tcp_table(("00000000:1F90", "0A")))
        original = os.read
        with patch("security_audit.linux.os.read",
                   side_effect=lambda fd, count: original(fd, min(count, 16))):
            result = linux.tcp_listeners(tree.sources)
        self.assertEqual(result, ([(8080, "*")], True))


class UnknownEnvironmentTests(TempCase):
    def test_empty_host_yields_only_unknown_or_unavailable(self) -> None:
        tree = Tree(self.base / "nothing")
        findings = scan(tree.context(self.home))
        self.assertEqual(tree.calls, [])
        for item in findings:
            if item.category in ("os", "network", "browser"):
                self.assertIn(item.status, (Status.UNKNOWN, Status.UNAVAILABLE), item.code)
        self.assertEqual({item.code for item in findings if item.category == "os"},
                         {"OS-L01", "OS-L02", "OS-L03", "OS-L04", "OS-L05"})
        self.assertFalse(any(item.status == Status.PASS for item in findings
                             if item.category in ("os", "network", "browser")))

    def test_wsl_is_not_assessed_and_nothing_else_is_read(self) -> None:
        tree = Tree(self.base)
        put(self.base / "proc" / "sys" / "kernel" / "osrelease", "5.15.1-microsoft-standard-WSL2\n")
        put(self.base / "sys" / "kernel" / "security" / "lsm", "apparmor\n")
        findings = OSScanner().scan(tree.context(self.home))
        self.assertEqual(len(findings), 5)
        for item in findings:
            self.assertEqual(item.status, Status.UNAVAILABLE)
            self.assertTrue(any(text.startswith("not_supported:") for text in item.limitations))
        self.assertEqual(tree.calls, [])

    def test_unsupported_unix_keeps_explicit_unavailable_adapters(self) -> None:
        tree = Tree(self.base)
        context = Context(self.home, self.home, system="FreeBSD", linux=tree.sources)
        self.assertEqual(OSScanner().scan(context)[0].code, "OS-000")
        self.assertEqual(NetworkScanner().scan(context)[0].code, "NET-000")
        self.assertEqual(BrowserScanner().scan(context)[0].code, "BR-000")

    def test_ids_are_stable_across_states_and_distinct_per_check(self) -> None:
        tree = Tree(self.base)
        seen: list[set[str]] = []
        for lsm in ("selinux", "apparmor", "capability"):
            put(self.base / "sys" / "kernel" / "security" / "lsm", lsm)
            put(self.base / "sys" / "fs" / "selinux" / "enforce", "1")
            seen.append({item.id for item in OSScanner().scan(tree.context(self.home))})
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[1], seen[2])
        self.assertEqual(len(seen[0]), 5)


class BrowserLinuxTests(TempCase):
    def manifest(self, root: str, name: str, content: dict[str, object]) -> None:
        put(self.home / root / "Default" / "Extensions" / name / "1.0" / "manifest.json",
            json.dumps(content))

    def scan(self, tree: Tree | None = None) -> list[Finding]:
        return BrowserScanner().scan((tree or Tree(self.base)).context(self.home))

    def test_chrome_native_manifests_are_aggregated_and_sanitized(self) -> None:
        root = BrowserScanner.LINUX_ROOTS["Chrome"][0]
        self.manifest(root, "a", {"name": CANARY, "permissions": ["cookies", "<all_urls>"],
                                  "update_url": "https://" + CANARY + ".invalid/update"})
        self.manifest(root, "b", {"host_permissions": ["https://*/*"]})
        findings = self.scan()
        codes = {item.code for item in findings}
        self.assertTrue({"BR-001", "BR-002", "BR-004", "BR-005", "BR-006", "BR-007"} <= codes)
        broad = next(item for item in findings if item.code == "BR-004")
        self.assertIn("2 stored extension package(s)", broad.title)
        self.assertEqual(broad.evidence_source, Evidence.MANIFEST)
        self.assertNotIn(CANARY, as_json(findings))
        scope = next(item for item in findings if item.code == "BR-003")
        self.assertIn("managed policy files", scope.limitations[0])

    def test_flatpak_root_is_used_when_native_is_absent_and_snap_firefox_is_presence_only(self) -> None:
        flatpak = BrowserScanner.LINUX_ROOTS["Chrome"][1]
        self.manifest(flatpak, "a", {"permissions": ["tabs"]})
        (self.home / BrowserScanner.LINUX_ROOTS["Firefox"][2]).mkdir(parents=True)
        findings = self.scan()
        self.assertTrue(any(item.code == "BR-005" for item in findings))
        firefox = [item for item in findings if item.location.startswith("Firefox")]
        self.assertEqual({item.code for item in firefox}, {"BR-001", "BR-003", "BR-012"})
        self.assertIn("presence only", next(item for item in firefox
                                            if item.code == "BR-003").limitations[0])

    def test_multiple_distribution_roots_are_reported_not_silently_skipped(self) -> None:
        native, flatpak = BrowserScanner.LINUX_ROOTS["Chrome"]
        self.manifest(native, "a", {"permissions": []})
        self.manifest(flatpak, "b", {"permissions": ["cookies"]})
        findings = self.scan()
        extra = next(item for item in findings if item.code == "BR-014")
        self.assertEqual((extra.status, extra.evidence_source),
                         (Status.UNAVAILABLE, Evidence.UNAVAILABLE))
        self.assertFalse(any(item.code == "BR-005" for item in findings))  # only native read

    def test_other_platform_roots_are_never_used_on_linux(self) -> None:
        for relative in (*BrowserScanner.MAC_ROOTS.values(), *BrowserScanner.WINDOWS_ROOTS.values()):
            (self.home / relative).mkdir(parents=True, exist_ok=True)
        findings = self.scan()
        self.assertEqual([item.code for item in findings if item.code != "BR-013"], [])

    def test_password_checkup_is_manual_only_and_never_reports_pass(self) -> None:
        (self.home / BrowserScanner.LINUX_ROOTS["Chrome"][0]).mkdir(parents=True)
        password = next(item for item in self.scan() if item.code == "BR-011")
        self.assertEqual((password.status, password.evidence_source),
                         (Status.UNKNOWN, Evidence.MANUAL))
        self.assertIn("not checked", password.title)

    def policy(self, name: str, content: str | bytes) -> Path:
        return put(self.base / "etc" / "opt" / "chrome" / "policies" / "managed" / name, content)

    def test_policy_states_mirror_windows_vocabulary(self) -> None:
        etc = self.base / "etc"
        self.assertEqual(_linux_policy_status(etc), ("not-configured", "not-configured"))
        self.policy("a.json", '{"SafeBrowsingProtectionLevel": 2, '
                              '"ExtensionSettings": {"' + CANARY + '": {}}}')
        self.assertEqual(_linux_policy_status(etc), ("configured", "enhanced"))
        self.policy("b.json", '{"SafeBrowsingProtectionLevel": 1}')
        self.assertEqual(_linux_policy_status(etc), ("configured", "conflicting"))
        self.policy("b.json", '{"SafeBrowsingProtectionLevel": 0}')
        self.policy("a.json", '{"SafeBrowsingProtectionLevel": 0}')
        self.assertEqual(_linux_policy_status(etc), ("not-configured", "disabled"))
        self.policy("ignored.txt", "not json")
        self.assertEqual(_linux_policy_status(etc), ("not-configured", "disabled"))

    def test_malformed_policy_is_unknown_never_a_pass(self) -> None:
        etc = self.base / "etc"
        for content in ('{"SafeBrowsingProtectionLevel": true}', '{"SafeBrowsingProtectionLevel": 3}',
                        '{"SafeBrowsingProtectionLevel": "1"}', "{broken", "[]",
                        '{"SafeBrowsingProtectionLevel": 1, "SafeBrowsingProtectionLevel": 1}',
                        b"\xff\xfe", " " * (256_000 + 1)):
            with self.subTest(content=content[:30]):
                self.policy("p.json", content)
                self.assertEqual(_linux_policy_status(etc)[1], "unknown")
        self.policy("p.json", '{"ExtensionSettings": "text"}')
        self.assertEqual(_linux_policy_status(etc)[0], "unknown")

    @unittest.skipIf(os.name == "nt", "symlink creation needs privileges on Windows")
    def test_symlinked_policy_file_is_not_followed(self) -> None:
        outside = put(self.base / "outside.json", '{"SafeBrowsingProtectionLevel": 2}')
        link = self.base / "etc" / "opt" / "chrome" / "policies" / "managed" / "link.json"
        link.parent.mkdir(parents=True)
        link.symlink_to(outside)
        self.assertEqual(_linux_policy_status(self.base / "etc")[1], "unknown")

    def test_policy_findings_use_linux_wording_and_policy_evidence(self) -> None:
        (self.home / BrowserScanner.LINUX_ROOTS["Chrome"][0]).mkdir(parents=True)
        self.policy("p.json", '{"SafeBrowsingProtectionLevel": 0}')
        findings = self.scan()
        issue = next(item for item in findings if item.code == "BR-010")
        self.assertEqual((issue.risk, issue.status, issue.evidence_source),
                         (Risk.HIGH, Status.ISSUE, Evidence.POLICY))
        self.assertNotIn("registry", " ".join(issue.limitations).lower())
        extension = next(item for item in findings if item.code == "BR-009")
        self.assertIn("managed policy files", extension.title)
        self.assertNotIn("registry", extension.title.lower())

    def test_firefox_and_edge_are_never_given_chrome_policy_findings(self) -> None:
        (self.home / BrowserScanner.LINUX_ROOTS["Firefox"][0]).mkdir(parents=True)
        (self.home / BrowserScanner.LINUX_ROOTS["Edge"][0]).mkdir(parents=True)
        self.policy("p.json", '{"SafeBrowsingProtectionLevel": 0}')
        self.assertFalse(any(item.code in ("BR-009", "BR-010") for item in self.scan()))


class ReadOnlyAndNoSecretTests(TempCase):
    def build(self) -> Tree:
        tree = Tree(self.base, lambda argv: (0, "running\n"),
                    devices={"/dev/mapper/root": (253, 0)})
        tree.root_mount("/dev/mapper/root")
        tree.block(253, 0, uuid="CRYPT-LUKS2-" + CANARY)
        put(self.base / "etc" / "ufw" / "ufw.conf", "ENABLED=yes\nCANARY=" + CANARY + "\n")
        put(self.base / "sys" / "kernel" / "security" / "lsm", "selinux\n")
        put(self.base / "sys" / "fs" / "selinux" / "enforce", "1")
        put(self.base / "sys" / "firmware" / "efi" / "efivars" / SECURE_BOOT,
            b"\x07\x00\x00\x00\x01")
        (self.base / "run" / "systemd" / "system").mkdir(parents=True)
        put(self.base / "proc" / "net" / "tcp", tcp_table(("0A02A8C0:0016", "0A")))
        put(tree.firewall_cmd)
        chrome = BrowserScanner.LINUX_ROOTS["Chrome"][0]
        put(self.home / chrome / "Default" / "Extensions" / CANARY / "1.0" / "manifest.json",
            json.dumps({"name": CANARY, "permissions": ["cookies"], "update_url": "https://x/" + CANARY}))
        put(self.base / "etc" / "opt" / "chrome" / "policies" / "managed" / "p.json",
            json.dumps({"ExtensionSettings": {CANARY: {}}, "Other": CANARY}))
        for relative in (".env", ".ssh/id_test", ".aws/credentials", ".npmrc",
                         ".config/gh/hosts.yml", ".config/gcloud/application_default_credentials.json"):
            put(self.home / relative, "TOKEN=" + CANARY)
        return tree

    def test_full_linux_scan_never_reports_values_or_opens_credential_files(self) -> None:
        tree = self.build()
        opened: list[Path] = []
        real_os_open, real_path_open = os.open, Path.open

        def record_os_open(path: str | os.PathLike[str], flags: int, *args: int) -> int:
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC), 0)
            opened.append(Path(path))
            return real_os_open(path, flags, *args)

        def record_path_open(path: Path, *args: object, **kwargs: object) -> object:
            opened.append(path)
            return real_path_open(path, *args, **kwargs)  # type: ignore[arg-type]

        with (patch("security_audit.linux.os.open", side_effect=record_os_open),
              patch.object(Path, "open", record_path_open),
              patch("subprocess.run", side_effect=AssertionError("subprocess used")),
              patch.dict(os.environ, {"SYNTHETIC_API_TOKEN": CANARY})):
            findings = scan(tree.context(self.home))
        report = as_json(findings)
        for forbidden in (CANARY, "192.168", str(self.base), str(self.home)):
            self.assertNotIn(forbidden, report)
        protected = {".env", "id_test", "credentials", ".npmrc", "hosts.yml",
                     "application_default_credentials.json"}
        self.assertFalse([path for path in opened if path.name in protected])
        self.assertTrue(opened)  # the probes did read their fixed kernel/config files
        self.assertEqual(tree.calls, [[str(tree.firewall_cmd), "--state"],
                                      [str(tree.systemctl), "show", "-p", "LoadState",
                                       "-p", "ActiveState", *linux.SSH_UNITS]])

    def test_engine_keeps_linux_limitations_and_unavailable_reasons(self) -> None:
        tree = Tree(self.base)
        put(self.base / "proc" / "net" / "tcp",
            tcp_table(("00000000:1F90", "0A")) + "short line\n")
        by_code = {item.code: item for item in scan(tree.context(self.home), "network")}
        self.assertTrue(any("namespace" in text for text in by_code["NET-001"].limitations))
        self.assertEqual(by_code["NET-000"].status, Status.UNAVAILABLE)
        self.assertTrue(any("malformed" in text for text in by_code["NET-000"].limitations))
        # Legacy (macOS/Windows) network findings still get the engine's generic wording.
        legacy = Finding("NET-001", Risk.HIGH, "t", "l", "r")
        context = Context(self.home, self.home, system="Darwin")
        with patch("security_audit.engine.SCANNERS", (NetworkScanner(),)), \
                patch.object(NetworkScanner, "scan", return_value=[legacy]):
            described = scan(context, "network")[0]
        self.assertEqual(described.limitations,
                         ("Listening beyond loopback does not establish Internet exposure.",))

    def test_all_linux_findings_carry_explicit_evidence_and_status(self) -> None:
        tree = self.build()
        for item in scan(tree.context(self.home), "os") + scan(tree.context(self.home), "network"):
            self.assertNotEqual(item.evidence_source, Evidence.MANUAL)
            self.assertTrue(item.limitations)


class ReadOnlyRemediationTests(TempCase):
    @unittest.skipIf(os.name == "nt", "POSIX modes are not meaningful on Windows")
    def test_linux_reports_no_fixable_finding_and_fix_changes_nothing(self) -> None:
        key = put(self.home / ".ssh" / "id_test", "FAKE")
        key.chmod(0o644)
        (self.home / ".ssh").chmod(0o755)
        context = Context(self.home, self.home, system="Linux")
        findings = scan(context, "ssh")
        broad = [item for item in findings if item.code in ("SSH-001", "SSH-002")]
        self.assertTrue(broad)
        for item in broad:
            self.assertFalse(item.auto_fixable)
            self.assertIsNone(target(context, item))
        for arguments, code in (["fix", "ssh", "--repository", str(self.home)], 0),\
                (["fix", "ssh", "--apply", "--repository", str(self.home)], 2):
            stdout, stderr = io.StringIO(), io.StringIO()
            with (patch("pathlib.Path.home", return_value=self.home),
                  patch("security_audit.cli.Context", partial(Context, system="Linux")),
                  contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
                self.assertEqual(main(arguments), code)
            if code:
                self.assertIn("Unsupported", stderr.getvalue())
                self.assertNotIn("complete", stdout.getvalue())
            else:
                self.assertIn("Nothing was changed", stdout.getvalue())
                self.assertNotIn("Dry run", stdout.getvalue())
        self.assertEqual(key.stat().st_mode & 0o777, 0o644)

    @unittest.skipIf(os.name == "nt", "POSIX modes are not meaningful on Windows")
    def test_darwin_keeps_auto_fixable_permission_findings(self) -> None:
        put(self.home / ".ssh" / "id_test", "FAKE").chmod(0o644)
        (self.home / ".ssh").chmod(0o755)
        context = Context(self.home, self.home, system="Darwin")
        broad = [item for item in scan(context, "ssh") if item.code == "SSH-002"]
        self.assertTrue(broad and all(item.auto_fixable for item in broad))
        self.assertIsNotNone(target(context, broad[0]))


class CoverageTests(unittest.TestCase):
    def test_linux_rows_exist_and_claim_no_physical_validation(self) -> None:
        linux_rows = [row for row in rows() if row["os"] == "Linux"]
        self.assertEqual({row["browser"] for row in linux_rows},
                         {"-", "Chrome", "Brave", "Edge", "Firefox"})
        for row in linux_rows:
            self.assertTrue(row["physical_validation"].startswith("No documented Linux physical"))
        self.assertFalse(any(row["os"] == "Linux/other" for row in rows()))
        self.assertTrue(any(row["os"] == "Other" for row in rows()))


if __name__ == "__main__":
    unittest.main()
