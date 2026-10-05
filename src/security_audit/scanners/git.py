from __future__ import annotations

from pathlib import Path

from security_audit.model import Finding, Risk
from security_audit.safety import label
from security_audit.scanners.base import Context


class GitScanner:
    category = "git"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Review Git history with an offline secret scanner before publishing.",)

    def scan(self, context: Context) -> list[Finding]:
        findings: list[Finding] = []
        roots = [context.repository]
        if context.full:
            candidates = [context.home / "Documents", context.home / "Developer"]
            if context.system == "Windows":
                candidates.append(context.home / "source" / "repos")
            roots.extend(path for path in candidates
                         if path.is_dir())
        repos: list[Path] = []
        for root in roots:
            if (root / ".git").exists():
                repos.append(root)
            elif root != context.repository:
                repos.extend(path for path in list(root.iterdir())[:100] if (path / ".git").exists())
        for repo in repos[:100]:
            if not (repo / ".gitignore").is_file():
                findings.append(Finding("GIT-001", Risk.MEDIUM, "Repository has no .gitignore",
                                        label(repo, context.home), "Add ignores for credentials and local reports."))
            findings.append(Finding("GIT-002", Risk.INFO, "Git history secret scan not performed",
                                    label(repo, context.home),
                                    "Run a vetted offline history scanner before publishing."))
        return findings
