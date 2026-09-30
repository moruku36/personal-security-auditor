from __future__ import annotations

from typing import ClassVar

from security_audit.model import Finding, Risk
from security_audit.scanners.base import Context


class BrowserScanner:
    category = "browser"
    ROOTS: ClassVar[dict[str, str]] = {
        "Chrome": "Library/Application Support/Google/Chrome",
        "Brave": "Library/Application Support/BraveSoftware/Brave-Browser",
        "Edge": "Library/Application Support/Microsoft Edge",
        "Firefox": "Library/Application Support/Firefox/Profiles",
        "Safari": "Library/Safari",
    }

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Review installed extensions and browser privacy settings manually.",)

    def scan(self, context: Context) -> list[Finding]:
        findings: list[Finding] = []
        for browser, relative in self.ROOTS.items():
            root = context.home / relative
            if not root.is_dir():
                continue
            findings.append(Finding("BR-001", Risk.INFO, f"{browser} data directory found",
                                    browser, "Review browser updates and security settings."))
            if browser in ("Chrome", "Brave", "Edge"):
                profiles = [root / "Default", *list(root.glob("Profile *"))[:20]]
                extension_count = 0
                for profile in profiles:
                    directory = profile / "Extensions"
                    if directory.is_dir():
                        try:
                            extension_count += len(list(directory.iterdir())[:100])
                        except OSError:
                            findings.append(Finding("BR-003", Risk.INFO,
                                "Extension directory could not be inspected", browser,
                                "Review extensions in the browser UI."))
                if extension_count:
                    findings.append(Finding("BR-002", Risk.LOW,
                        f"{extension_count} extension directory or directories found", browser,
                        "Inspect extension publishers and permissions in the browser UI."))
        return findings
