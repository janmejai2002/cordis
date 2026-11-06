"""Pre-Flight Repository Governance & Policy Scraper (Anti-AI & Issue Prerequisite Guard)."""
from __future__ import annotations

import configparser
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Set


@dataclass
class PolicyAuditReport:
    status: str  # "BLOCKED_POLICY" | "ISSUE_REQUIRED" | "PERMITTED"
    ai_banned: bool = False
    issue_required: bool = False
    governance_files_scanned: List[str] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)
    advice: str = ""

    @property
    def triggers(self) -> List[str]:
        return self.citations

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ai_banned": self.ai_banned,
            "issue_required": self.issue_required,
            "governance_files_scanned": self.governance_files_scanned,
            "citations": self.citations,
            "triggers": self.citations,
            "advice": self.advice,
        }


ANTI_AI_PATTERNS = [
    re.compile(r"palletsprojects\.com/contributing/llm-ai", re.IGNORECASE),
    re.compile(
        r"(?:no|prohibit(?:s|ed|ing)?|disallow(?:ed|ing)?|ban(?:ned|ning)?|not\s+accept(?:ed|ing)?)\s+(?:any\s+)?(?:ai|llm|copilot|chatgpt|generative\s+ai|machine[\s-]generated)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:ai|llm|chatgpt|copilot|generative\s+ai)[\s-]generated\s+(?:code|pull\s+requests?|prs?|contributions?)",
        re.IGNORECASE,
    ),
    re.compile(r"\[no-ai\]", re.IGNORECASE),
    re.compile(r"\banti-ai\b", re.IGNORECASE),
    re.compile(r"zero-tolerance\s+policy\s+against\s+(?:ai|llm)", re.IGNORECASE),
    re.compile(r"clearly\s+ai\s+generated\s+description.*?(?:ignored|closed)", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bno\s+(?:ai-generated|llm-generated|ai-assisted)\b", re.IGNORECASE),
    re.compile(r"pull\s+requests?\s+generated\s+by\s+(?:ai|llms?|chatgpt)", re.IGNORECASE),
    re.compile(r"contributions?\s+generated\s+by\s+(?:ai|llms?|chatgpt)", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+submit\s+(?:any\s+)?(?:ai|llm|chatgpt|copilot)\b", re.IGNORECASE),
]

ISSUE_REQUIRED_PATTERNS = [
    re.compile(
        r"(?:all|every)\s+pull\s+requests?\s+must\s+(?:reference|link|have)\s+an?\s+(?:existing\s+)?issue",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:open|create|file)\s+an?\s+issue\s+(?:first|before\s+(?:submitting|creating|opening))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:must|require[ds]?)\s+(?:be\s+)?assigned\s+(?:to\s+)?an?\s+issue",
        re.IGNORECASE,
    ),
    re.compile(r"must\s+link\s+to\s+an\s+issue", re.IGNORECASE),
    re.compile(r"an\s+issue\s+is\s+required", re.IGNORECASE),
    re.compile(r"\[require-issue\]", re.IGNORECASE),
    re.compile(r"fixes\s*#.*?(?:required|mandatory)", re.IGNORECASE),
    re.compile(r"prs?\s+without\s+prior\s+approval\s+will\s+be\s+closed", re.IGNORECASE),
    re.compile(r"before\s+opening\s+a\s+pr,?\s+open\s+(?:a\s+ticket|an\s+issue)", re.IGNORECASE),
    re.compile(r"(?:all\s+external\s+)?prs\s+must\s+link\s+to\s+an\s+issue", re.IGNORECASE),
]


def _discover_governance_files(root: Path) -> List[Path]:
    target_names = {
        "contributing.md",
        "contributing.rst",
        "contributing.txt",
        "contributing",
        "pull_request_template.md",
        "pull_request_template.rst",
        "pull_request_template.txt",
        "pull_request_template",
        "readme.md",
        "readme.rst",
        "readme.txt",
        "readme",
        "ai_policy.md",
        "ai-policy.md",
        "aipolicy.md",
        "policy.md",
        "governance.md",
        "governance.rst",
        "security.md",
        "security.rst",
        "code_of_conduct.md",
    }
    search_dirs = [
        root,
        root / ".github",
        root / "docs",
        root / ".github" / "PULL_REQUEST_TEMPLATE",
        root / ".github" / "pull_request_template",
    ]
    found: List[Path] = []
    seen_paths: Set[str] = set()

    for d in search_dirs:
        if not d.is_dir():
            continue
        try:
            for item in d.iterdir():
                if item.is_file():
                    name_lower = item.name.lower()
                    if name_lower in target_names or (
                        "pull_request_template" in d.name.lower() and name_lower.endswith(".md")
                    ):
                        resolved_str = str(item.resolve())
                        if resolved_str not in seen_paths:
                            seen_paths.add(resolved_str)
                            found.append(item)
        except (PermissionError, OSError):
            continue

    return found


def audit_repository_policy(repo_path: str | Path) -> PolicyAuditReport:
    """Scans repository governance files (CONTRIBUTING, PULL_REQUEST_TEMPLATE, README)
    case-insensitively across root, .github/, and docs/ to detect anti-AI contribution
    bans and mandatory issue prerequisites.
    """
    root = Path(repo_path).resolve()
    if not root.exists() or not root.is_dir():
        return PolicyAuditReport(
            status="PERMITTED",
            ai_banned=False,
            issue_required=False,
            governance_files_scanned=[],
            citations=[],
            advice=f"Repository path `{repo_path}` does not exist or is not a directory; default to PERMITTED.",
        )

    governance_files = _discover_governance_files(root)
    scanned_rel_paths: List[str] = []
    citations: List[str] = []
    ai_banned = False
    issue_required = False

    for gfile in governance_files:
        try:
            rel_str = str(gfile.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_str = str(gfile).replace("\\", "/")
        scanned_rel_paths.append(rel_str)

        try:
            content = gfile.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
        except Exception:
            continue

        if not content.strip():
            continue

        # Check anti-AI patterns
        for pat in ANTI_AI_PATTERNS:
            match = pat.search(content)
            if match:
                ai_banned = True
                snippet = match.group(0).strip().replace("\n", " ")
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context_snippet = content[start:end].strip().replace("\n", " ")
                citations.append(f"{rel_str}: Matches anti-AI pattern `{snippet}`: \"...{context_snippet}...\"")
                break

        # Check mandatory issue patterns
        for pat in ISSUE_REQUIRED_PATTERNS:
            match = pat.search(content)
            if match:
                issue_required = True
                snippet = match.group(0).strip().replace("\n", " ")
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context_snippet = content[start:end].strip().replace("\n", " ")
                citations.append(f"{rel_str}: Matches issue requirement pattern `{snippet}`: \"...{context_snippet}...\"")
                break

    # Check for hook tampering if .git is a directory
    hook_tampered = False
    git_dir = root / ".git"
    if git_dir.is_dir():
        # 1. Inspect .git/config for core.hooksPath override
        git_config_path = git_dir / "config"
        if git_config_path.is_file():
            hooks_path_val: Optional[str] = None
            try:
                cp = configparser.ConfigParser()
                cp.read(str(git_config_path), encoding="utf-8")
                if cp.has_section("core") and "hookspath" in cp["core"]:
                    hooks_path_val = cp["core"]["hookspath"].strip()
            except Exception:
                pass

            if hooks_path_val is None:
                try:
                    cfg_text = git_config_path.read_text(encoding="utf-8", errors="replace")
                    in_core = False
                    for line in cfg_text.splitlines():
                        sline = line.strip()
                        if sline.startswith("[") and sline.endswith("]"):
                            in_core = (sline.lower() == "[core]")
                        elif in_core and "=" in sline:
                            k, v = sline.split("=", 1)
                            if k.strip().lower() == "hookspath":
                                hooks_path_val = v.strip().strip("'\"")
                                break
                except Exception:
                    pass

            if hooks_path_val is not None:
                clean_hp = hooks_path_val.strip().strip("'\"")
                norm_hp = clean_hp.lower().replace("\\", "/")
                is_suppressed = (
                    not clean_hp
                    or norm_hp in ("/dev/null", "nul", "null", ":", "false", "none", "/dev/zero")
                    or (not (root / clean_hp).exists() and not Path(clean_hp).exists())
                )
                if is_suppressed:
                    hook_tampered = True
                    citations.append("[HOOK_TAMPERING]: git core.hooksPath is overridden to invalid/suppressed target")

        # 2. Inspect .git/hooks/pre-commit
        hook_path = git_dir / "hooks" / "pre-commit"
        if hook_path.is_file():
            is_empty = False
            try:
                is_empty = (os.path.getsize(hook_path) == 0)
            except OSError:
                pass

            is_stripped = False
            if hasattr(os, "X_OK"):
                if os.name != "nt":
                    is_stripped = not os.access(hook_path, os.X_OK)
                else:
                    if not os.access(hook_path, os.X_OK):
                        is_stripped = True

            if is_empty or is_stripped:
                hook_tampered = True
                citations.append("[HOOK_TAMPERING]: .git/hooks/pre-commit is stripped of executable permissions or emptied")

    if ai_banned:
        status = "BLOCKED_POLICY"
        advice = (
            "Repository governance explicitly prohibits AI/LLM-generated code or pull requests. "
            "Do not submit automated pull requests to this repository."
        )
    elif hook_tampered:
        status = "BLOCKED_POLICY"
        advice = (
            "Repository policy violated: git hook tampering or suppression detected. "
            "Ensure .git/hooks/pre-commit is executable and core.hooksPath is not overridden."
        )
    elif issue_required:
        status = "ISSUE_REQUIRED"
        advice = (
            "Repository governance requires an existing issue or maintainer approval before opening a pull request. "
            "Open, reference, or link a valid issue first."
        )
    else:
        status = "PERMITTED"
        advice = "No anti-AI bans or mandatory issue prerequisites detected in governance files."

    return PolicyAuditReport(
        status=status,
        ai_banned=ai_banned,
        issue_required=issue_required,
        governance_files_scanned=scanned_rel_paths,
        citations=citations,
        advice=advice,
    )
