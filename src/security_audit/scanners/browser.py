from __future__ import annotations

import importlib
import json
import stat
from pathlib import Path
from typing import ClassVar

from security_audit.model import Finding, Risk
from security_audit.scanners.base import Context

MAX_PROFILES = 20
MAX_EXTENSIONS_PER_PROFILE = 200
MAX_VERSIONS_PER_EXTENSION = 10
MAX_MANIFEST_BYTES = 256_000
CHROME_STORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
BROAD_HOST_PATTERNS = frozenset({"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "file:///*"})
REVIEW_PERMISSIONS = frozenset({
    "clipboardread", "cookies", "debugger", "downloads", "history", "management",
    "nativemessaging", "privacy", "proxy", "tabs", "webnavigation", "webrequest",
    "webrequestblocking",
})


def _metadata_is_reparse_point(metadata: object) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(getattr(metadata, "st_mode", 0)) or bool(attributes & reparse_flag)


def _is_reparse_point(path: Path) -> bool:
    try:
        return _metadata_is_reparse_point(path.lstat())
    except OSError:
        return False


def _bounded_directories(root: Path, limit: int, pattern: str | None = None
                          ) -> tuple[list[Path], bool, bool]:
    """Return bounded child directories, whether enumeration was capped, and whether it failed."""
    directories: list[Path] = []
    capped = False
    failed = False
    try:
        if _is_reparse_point(root):
            return directories, False, True
        children = root.glob(pattern) if pattern is not None else root.iterdir()
        for child in children:
            try:
                if _is_reparse_point(child) or not child.is_dir():
                    continue
            except OSError:
                failed = True
                continue
            if len(directories) == limit:
                capped = True
                break
            directories.append(child)
    except OSError:
        failed = True
    return directories, capped, failed


def _read_manifest(path: Path, profile: Path) -> dict[str, object] | None:
    """Read a small regular manifest only when it resolves inside its Chrome profile."""
    try:
        metadata = path.lstat()
        if (_metadata_is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > MAX_MANIFEST_BYTES):
            return None
        resolved = path.resolve(strict=True)
        resolved.relative_to(profile.resolve(strict=True))
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _broad_host_pattern(value: object) -> bool:
    return isinstance(value, str) and value.strip().lower() in BROAD_HOST_PATTERNS


def _extension_policy_status(system: str) -> str:
    """Report only whether a bounded ExtensionSettings policy value is present."""
    if system != "Windows":
        return "not-applicable"
    try:
        winreg = importlib.import_module("winreg")
    except ImportError:
        return "unknown"

    policy_path = r"Software\Policies\Google\Chrome"
    unknown = False
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            key = winreg.OpenKey(hive, policy_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue
        except OSError:
            unknown = True
            continue
        try:
            try:
                value, value_type = winreg.QueryValueEx(key, "ExtensionSettings")
            except FileNotFoundError:
                continue
            except OSError:
                unknown = True
                continue
            if (value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ)
                    or not isinstance(value, str) or len(value) > MAX_MANIFEST_BYTES):
                unknown = True
                continue
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError, RecursionError):
                unknown = True
                continue
            if isinstance(parsed, dict):
                return "configured"
            unknown = True
        finally:
            winreg.CloseKey(key)
    return "unknown" if unknown else "not-configured"


def _safe_browsing_policy_status(system: str) -> str:
    """Read only the bounded Windows Safe Browsing policy enum; never user preferences."""
    if system != "Windows":
        return "not-applicable"
    try:
        winreg = importlib.import_module("winreg")
    except ImportError:
        return "unknown"

    policy_path = r"Software\Policies\Google\Chrome"
    values: list[int] = []
    unknown = False
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            key = winreg.OpenKey(hive, policy_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue
        except OSError:
            unknown = True
            continue
        try:
            try:
                value, value_type = winreg.QueryValueEx(key, "SafeBrowsingProtectionLevel")
            except FileNotFoundError:
                continue
            except OSError:
                unknown = True
                continue
            if (value_type != winreg.REG_DWORD or isinstance(value, bool)
                    or not isinstance(value, int) or value not in (0, 1, 2)):
                unknown = True
                continue
            values.append(value)
        finally:
            winreg.CloseKey(key)

    if unknown:
        return "unknown"
    if not values:
        return "not-configured"
    if len(set(values)) != 1:
        return "conflicting"
    return {0: "disabled", 1: "standard", 2: "enhanced"}[values[0]]


class BrowserScanner:
    category = "browser"
    MAC_ROOTS: ClassVar[dict[str, str]] = {
        "Chrome": "Library/Application Support/Google/Chrome",
        "Brave": "Library/Application Support/BraveSoftware/Brave-Browser",
        "Edge": "Library/Application Support/Microsoft Edge",
        "Firefox": "Library/Application Support/Firefox/Profiles",
        "Safari": "Library/Safari",
    }
    WINDOWS_ROOTS: ClassVar[dict[str, str]] = {
        "Chrome": "AppData/Local/Google/Chrome/User Data",
        "Brave": "AppData/Local/BraveSoftware/Brave-Browser/User Data",
        "Edge": "AppData/Local/Microsoft/Edge/User Data",
        "Firefox": "AppData/Roaming/Mozilla/Firefox/Profiles",
    }

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Review extension publishers, permissions and update settings in the browser UI.",)

    def scan(self, context: Context) -> list[Finding]:
        findings: list[Finding] = []
        roots = self.WINDOWS_ROOTS if context.system == "Windows" else self.MAC_ROOTS
        chrome_found = False
        for browser, relative in roots.items():
            root = context.home / relative
            if _is_reparse_point(root) or not root.is_dir():
                continue
            findings.append(Finding("BR-001", Risk.INFO, f"{browser} data directory found",
                                    browser, "Review browser updates and security settings."))
            if browser not in ("Chrome", "Brave", "Edge"):
                continue
            chrome_found = chrome_found or browser == "Chrome"
            profiles, profiles_capped, profiles_failed = _bounded_directories(
                root, MAX_PROFILES - 1, "Profile *")
            profiles.insert(0, root / "Default")
            extension_count = 0
            broad_host_count = 0
            review_permission_count = 0
            custom_update_count = 0
            unknown_update_count = 0
            incomplete = profiles_capped or profiles_failed

            for profile in profiles:
                try:
                    if _is_reparse_point(profile) or not profile.is_dir():
                        continue
                except OSError:
                    incomplete = True
                    continue
                extension_root = profile / "Extensions"
                if _is_reparse_point(extension_root):
                    incomplete = True
                    continue
                if not extension_root.is_dir():
                    continue
                extension_dirs, capped, failed = _bounded_directories(
                    extension_root, MAX_EXTENSIONS_PER_PROFILE)
                incomplete = incomplete or capped or failed
                extension_count += len(extension_dirs)
                for extension_dir in extension_dirs:
                    if browser != "Chrome":
                        continue
                    versions, version_capped, version_failed = _bounded_directories(
                        extension_dir, MAX_VERSIONS_PER_EXTENSION)
                    incomplete = incomplete or version_capped or version_failed
                    manifests: list[dict[str, object]] = []
                    for version in versions:
                        data = _read_manifest(version / "manifest.json", profile)
                        if data is not None:
                            manifests.append(data)
                    if not manifests:
                        incomplete = True
                        continue

                    extension_has_broad_host = False
                    extension_has_review_permission = False
                    extension_has_custom_update = False
                    extension_has_explicit_update = False
                    for manifest in manifests:
                        permissions: set[str] = set()
                        for key in ("permissions", "optional_permissions"):
                            value = manifest.get(key)
                            if isinstance(value, list):
                                permissions.update(item.casefold() for item in value
                                                   if isinstance(item, str))
                        extension_has_review_permission |= bool(permissions & REVIEW_PERMISSIONS)

                        host_patterns: list[object] = []
                        for key in ("host_permissions", "optional_host_permissions"):
                            value = manifest.get(key)
                            if isinstance(value, list):
                                host_patterns.extend(value)
                        content_scripts = manifest.get("content_scripts")
                        if isinstance(content_scripts, list):
                            for script in content_scripts:
                                if (isinstance(script, dict)
                                        and isinstance(script.get("matches"), list)):
                                    host_patterns.extend(script["matches"])
                        extension_has_broad_host |= any(_broad_host_pattern(item)
                                                        for item in host_patterns)

                        update_url = manifest.get("update_url")
                        if isinstance(update_url, str) and update_url.strip():
                            extension_has_explicit_update = True
                            extension_has_custom_update |= (
                                update_url.strip().rstrip("/").casefold()
                                != CHROME_STORE_UPDATE_URL.casefold())

                    broad_host_count += int(extension_has_broad_host)
                    review_permission_count += int(extension_has_review_permission)
                    custom_update_count += int(extension_has_custom_update)
                    unknown_update_count += int(not extension_has_explicit_update)

            if extension_count:
                findings.append(Finding("BR-002", Risk.LOW,
                    f"{extension_count} extension directory or directories found", browser,
                    "Inspect extension publishers and permissions in the browser UI."))
            location = "Chrome extension metadata"
            if broad_host_count:
                findings.append(Finding("BR-004", Risk.MEDIUM,
                    f"{broad_host_count} stored extension package(s) declare broad website access",
                    location, "Review active extension site access in the browser UI."))
            if review_permission_count:
                findings.append(Finding("BR-005", Risk.LOW,
                    f"{review_permission_count} stored extension package(s) request "
                    "high-impact permissions",
                    location, "Review the requested permissions and publisher in the browser UI."))
            if custom_update_count:
                findings.append(Finding("BR-006", Risk.MEDIUM,
                    f"{custom_update_count} stored extension package(s) declare "
                    "a nonstandard update URL",
                    location, "Verify the extension source and update policy in the browser UI."))
            if unknown_update_count:
                findings.append(Finding("BR-007", Risk.INFO,
                    "Update source could not be determined from "
                    f"{unknown_update_count} stored extension package(s)",
                    location,
                    "Confirm each active extension's source and update status in the browser UI."))
            if incomplete:
                findings.append(Finding("BR-008", Risk.INFO,
                    "Some browser extension metadata could not be inspected",
                    location, "Review active extensions in the browser UI."))

        if chrome_found and context.system == "Windows":
            policy_status = _extension_policy_status(context.system)
            if policy_status == "configured":
                title = "Chrome ExtensionSettings policy is present"
                recommendation = "Review effective extension policy in chrome://policy."
            elif policy_status == "not-configured":
                title = ("Chrome ExtensionSettings policy was not found in the checked "
                         "registry hives")
                recommendation = ("Review extension restrictions and managed settings "
                                  "in chrome://policy.")
            else:
                title = "Chrome ExtensionSettings policy status is unavailable"
                recommendation = "Review managed extension settings in chrome://policy."
            findings.append(Finding("BR-009", Risk.INFO, title, "Chrome policy",
                                    recommendation))
            safe_browsing = _safe_browsing_policy_status(context.system)
            if safe_browsing == "disabled":
                findings.append(Finding(
                    "BR-010", Risk.HIGH,
                    "Chrome Safe Browsing policy explicitly selects no protection",
                    "Chrome security policy",
                    "Verify the effective value in chrome://policy and review the setting "
                    "in chrome://settings/security."))
            elif safe_browsing == "conflicting":
                findings.append(Finding(
                    "BR-010", Risk.INFO,
                    "Chrome Safe Browsing policy values conflict across registry hives",
                    "Chrome security policy",
                    "Review the effective value in chrome://policy; the checked registry "
                    "values do not identify which setting is effective."))
            elif safe_browsing in ("standard", "enhanced"):
                findings.append(Finding(
                    "BR-010", Risk.INFO,
                    f"Chrome Safe Browsing policy is set to {safe_browsing} protection",
                    "Chrome security policy",
                    "Confirm the effective value in chrome://policy; this registry check "
                    "does not include cloud policy or user preferences."))
            else:
                findings.append(Finding(
                    "BR-010", Risk.INFO,
                    "Chrome Safe Browsing effective setting is unknown",
                    "Chrome security policy",
                    "Review chrome://settings/security and chrome://policy in Chrome."))
        return findings
