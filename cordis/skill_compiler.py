"""Universal Cross-Agent Skill & Rules Manifest Compiler (Engine 9.1).
Synchronizes Cordis prosecutor skill and rules across Antigravity, Claude Code,
Cursor, and Gemini/Codex environments, and provides static security auditing
against Snyk ToxicSkills and OWASP Agentic Top 10 vulnerabilities.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class SkillSecurityFinding:
    file_path: str
    line_number: int
    rule: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM"
    snippet: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule": self.rule,
            "severity": self.severity,
            "snippet": self.snippet,
            "message": self.message,
        }


@dataclass
class SkillSecurityReport:
    clean: bool
    violations: List[str] = field(default_factory=list)
    findings: List[SkillSecurityFinding] = field(default_factory=list)
    scanned_files: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.clean

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean": self.clean,
            "passed": self.clean,
            "violations": self.violations,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_files": self.scanned_files,
        }


# Security Detection Patterns (Snyk ToxicSkills / OWASP Agentic Skills Top 10)
# 1. Hidden Unicode Tag, Bidi, and Zero-Width Characters
# Tag: U+E0000..U+E007F, Bidi: U+202A..U+202E, Zero-Width/Format: U+200B..U+200F
RE_HIDDEN_UNICODE = re.compile(r"[\U000E0000-\U000E007F\u202A-\u202E\u200B-\u200F]")

# 2. Prompt-Injection Verification Bypass Directives
RE_BYPASS_NO_VERIFY = re.compile(
    r"(?:\bgit\s+commit[^\n]*\s(?:--no-verify|-n\b)|(?<!\w)--no-verify\b)",
    re.IGNORECASE,
)
RE_BYPASS_TEST_SKIP = re.compile(
    r"(?<!\w)(?:@?pytest\.mark\.skip|pytest\.skip|unittest\.skip|skipTest|it\.skip|test\.skip|describe\.skip|xit)\b",
    re.IGNORECASE,
)
RE_BYPASS_MOCK = re.compile(
    r"\b(?:vi\.mock|jest\.mock)\b",
    re.IGNORECASE,
)
RE_BYPASS_CORDIS = re.compile(
    r"\b(?:bypass|disable|ignore|skip)\s+cordis\b",
    re.IGNORECASE,
)

# 3. Covert Data Exfiltration & Pipe-to-Shell Commands
RE_EXFIL_DATA = re.compile(
    r"\b(?:curl\s+[^\n]*(?:-d|--data|-F|--upload-file|-X\s*POST)|wget\s+[^\n]*--post-data)\b",
    re.IGNORECASE,
)
RE_EXFIL_URL_VARS = re.compile(
    r"\b(?:curl|wget)\s+[^\n]*https?://[^\s]*(\$[A-Za-z0-9_]+|\$\{[A-Za-z0-9_]+\}|%[A-Za-z0-9_]+%|\btoken=|\bkey=|\bsecret=)",
    re.IGNORECASE,
)
RE_EXFIL_PIPE_SHELL = re.compile(
    r"\b(?:curl|wget)[^\n]*\|\s*(?:sh|bash|powershell|pwsh|python|python3)\b",
    re.IGNORECASE,
)

# Prohibition prefix pattern to distinguish security directives from attack injections
RE_PROHIBITION_PREFIX = re.compile(
    r"^\s*[-*]?\s*(?:do\s+not|don't|never|prohibit(?:s|ed|ing)?|forbid(?:s|den|ding)?|must\s+not|avoid)\b",
    re.IGNORECASE,
)

# Canonical Manifest Templates
SKILL_MD_CONTENT = """---
name: cordis-prosecutor
description: "Enforce zero-token mutation prosecution and prevent counterfeit/hollow test creation before git commits."
---

# Cordis Adversarial Invariant Prosecutor Skill

## When to Use This Skill
Use this skill whenever authoring or modifying code and unit tests in Python or TypeScript/JavaScript.

## Mandatory Pre-Commit Workflow
1. Before committing any patch, run:
   ```bash
   python -m cordis.cli verify-git
   ```
2. If any mutant survives in Gate 2, run:
   ```bash
   python -m cordis.cli probe --source <source_file> --test <test_file> --func <func_name> --suggest-test
   ```
3. Copy the synthesized mutant-killing invariants into your test file.

## Prohibited Reward-Hacking Patterns
- DO NOT weaken assertions to `assert x is not None` or `expect(x).toBeDefined()`.
- DO NOT mock internal domain functions or sibling package helpers (keep MAR low).
- DO NOT add tautological assertions like `assert f(x) == f(x)` or `assert wrapper(x) == f(x)`.
- DO NOT swallow exceptions with bare `except:` or `pytest.raises(Exception)` without matching specific errors.
- DO NOT bypass hooks with `git commit --no-verify` or `git stash --keep-index`.
"""

BOUNDED_BLOCK_CONTENT = """<!-- CORDIS-PROSECUTOR:START -->
## 🛡️ Cordis Adversarial Invariant Prosecution Guard
All coding agents operating in this repository must comply with Cordis invariant verification:
1. **Pre-Commit Verification**: Run `python -m cordis.cli verify-git` on all modified files.
2. **Zero Surviving Mutants**: If Gate 2 reports surviving mutants, synthesize strong invariant tests using `python -m cordis.cli probe --source <src> --test <test> --func <fn> --suggest-test`.
3. **Strict Assertion Quality**: Never weaken assertions to `is not None`, never mock internal domain logic, and never swallow exceptions via broad `except Exception: pass`.
<!-- CORDIS-PROSECUTOR:END -->"""

CURSOR_MDC_CONTENT = """---
description: Cordis Adversarial Invariant Prosecution Rule
globs: *
alwaysApply: true
---

# Cordis Invariant Guard
- Before committing changes, run `python -m cordis.cli verify-git`.
- Ensure 100% of generated mutants are killed in Gate 2.
- Never weaken test assertions or inject broad exception swallowing.
- Use `python -m cordis.cli probe --suggest-test` to synthesize test assertions for surviving mutants.
"""

SKILL_ENTRY = {
    "name": "cordis-prosecutor",
    "description": "Enforce zero-token mutation prosecution and prevent counterfeit/hollow test creation before git commits.",
    "path": ".agents/skills/cordis-prosecutor/SKILL.md",
}


def _inject_or_update_bounded_block(file_path: Path, block: str) -> None:
    start_marker = "<!-- CORDIS-PROSECUTOR:START -->"
    end_marker = "<!-- CORDIS-PROSECUTOR:END -->"

    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists():
        file_path.write_text(block.strip() + "\n", encoding="utf-8", newline="\n")
        return

    content = file_path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")

    if start_marker in content and end_marker in content:
        start_idx = content.find(start_marker)
        end_idx = content.find(end_marker) + len(end_marker)
        new_content = content[:start_idx] + block.strip() + content[end_idx:]
    elif start_marker in content:
        start_idx = content.find(start_marker)
        new_content = content[:start_idx] + block.strip() + "\n"
    else:
        if content and not content.endswith("\n"):
            content += "\n"
        if content and not content.endswith("\n\n"):
            content += "\n"
        new_content = content + block.strip() + "\n"

    file_path.write_text(new_content, encoding="utf-8", newline="\n")


def _generate_or_update_gemini_index(gemini_file: Path, skill_entry: Dict[str, str]) -> None:
    gemini_file.parent.mkdir(parents=True, exist_ok=True)
    data: Dict[str, Any] = {"version": "1.0.0", "skills": [dict(skill_entry)]}
    if gemini_file.exists():
        try:
            content = gemini_file.read_text(encoding="utf-8", errors="replace").strip()
            if content:
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    data = loaded
                    if "version" not in data:
                        data["version"] = "1.0.0"
                    skills = data.get("skills")
                    if isinstance(skills, list):
                        found = False
                        for idx, item in enumerate(skills):
                            if isinstance(item, dict) and item.get("name") == skill_entry["name"]:
                                skills[idx] = dict(skill_entry)
                                found = True
                                break
                        if not found:
                            skills.append(dict(skill_entry))
                    else:
                        data["skills"] = [dict(skill_entry)]
        except Exception:
            data = {"version": "1.0.0", "skills": [dict(skill_entry)]}

    gemini_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def compile_agent_skill_manifests(repo_dir: str | Path = ".") -> List[str]:
    """Compiles and synchronizes cross-harness skill manifests and rule configs:
    1. .agents/skills/cordis-prosecutor/SKILL.md
    2. AGENTS.md (bounded <!-- CORDIS-PROSECUTOR:START --> ... <!-- CORDIS-PROSECUTOR:END -->)
    3. CLAUDE.md (bounded <!-- CORDIS-PROSECUTOR:START --> ... <!-- CORDIS-PROSECUTOR:END -->)
    4. .cursor/rules/cordis.mdc
    5. .gemini/skills-index.json

    Returns list of modified or generated file paths.
    """
    root = Path(repo_dir)
    root.mkdir(parents=True, exist_ok=True)

    # 1. .agents/skills/cordis-prosecutor/SKILL.md
    skill_file = root / ".agents" / "skills" / "cordis-prosecutor" / "SKILL.md"
    skill_file.parent.mkdir(parents=True, exist_ok=True)
    skill_file.write_text(SKILL_MD_CONTENT.strip() + "\n", encoding="utf-8", newline="\n")

    # 2. AGENTS.md
    agents_file = root / "AGENTS.md"
    _inject_or_update_bounded_block(agents_file, BOUNDED_BLOCK_CONTENT)

    # 3. CLAUDE.md
    claude_file = root / "CLAUDE.md"
    _inject_or_update_bounded_block(claude_file, BOUNDED_BLOCK_CONTENT)

    # 4. .cursor/rules/cordis.mdc
    cursor_file = root / ".cursor" / "rules" / "cordis.mdc"
    cursor_file.parent.mkdir(parents=True, exist_ok=True)
    cursor_file.write_text(CURSOR_MDC_CONTENT.strip() + "\n", encoding="utf-8", newline="\n")

    # 5. .gemini/skills-index.json
    gemini_file = root / ".gemini" / "skills-index.json"
    _generate_or_update_gemini_index(gemini_file, SKILL_ENTRY)

    manifest_paths = [
        (root / ".agents" / "skills" / "cordis-prosecutor" / "SKILL.md").as_posix(),
        (root / "AGENTS.md").as_posix(),
        (root / "CLAUDE.md").as_posix(),
        (root / ".cursor" / "rules" / "cordis.mdc").as_posix(),
        (root / ".gemini" / "skills-index.json").as_posix(),
    ]
    return manifest_paths


def audit_skill_manifests(repo_dir: str | Path = ".") -> SkillSecurityReport:
    """Audits skill manifests and agent instruction files for security risks:
    - Scanned targets: .agents/skills/**/SKILL.md, CLAUDE.md, AGENTS.md, .cursor/rules/*.mdc
    - Checks for:
      * Hidden Unicode tag / bidi / zero-width characters (U+E0000..U+E007F, U+202A..U+202E, U+200B..U+200F)
      * Prompt-injection verification bypass directives (--no-verify, pytest.skip, vi.mock)
      * Covert curl/wget exfiltration and pipe-to-shell commands
    """
    root = Path(repo_dir)
    scanned_files: List[str] = []
    findings: List[SkillSecurityFinding] = []

    if not root.exists():
        return SkillSecurityReport(clean=True, violations=[], findings=[], scanned_files=[])

    candidates: List[Path] = []

    # 1. .agents/skills/**/SKILL.md
    skills_root = root / ".agents" / "skills"
    if skills_root.is_dir():
        for p in sorted(skills_root.rglob("*")):
            if p.is_file() and p.name.lower() == "skill.md":
                candidates.append(p)

    # 2. AGENTS.md and CLAUDE.md (case-insensitive search in root directory)
    if root.is_dir():
        for item in sorted(root.iterdir()):
            if item.is_file() and item.name.lower() in ("agents.md", "claude.md"):
                if item not in candidates:
                    candidates.append(item)

    # 3. .cursor/rules/*.mdc
    cursor_rules_dir = root / ".cursor" / "rules"
    if cursor_rules_dir.is_dir():
        for p in sorted(cursor_rules_dir.glob("*.mdc")):
            if p.is_file() and p not in candidates:
                candidates.append(p)

    for target_path in candidates:
        try:
            rel_str = str(target_path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_str = str(target_path).replace("\\", "/")
        scanned_files.append(rel_str)

        try:
            content = target_path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
        except Exception:
            continue

        normalized_content = re.sub(r"\\\r?\n\s*", " ", content)
        lines = normalized_content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            # 1. Hidden Unicode Characters (Tag, Bidi, Zero-Width)
            m_uni = RE_HIDDEN_UNICODE.search(line)
            if m_uni:
                ch = m_uni.group(0)
                findings.append(
                    SkillSecurityFinding(
                        file_path=rel_str,
                        line_number=line_idx,
                        rule="hidden_unicode",
                        severity="CRITICAL",
                        snippet=line.strip()[:100],
                        message=f"Hidden Unicode character detected: U+{ord(ch):04X}",
                    )
                )

            # 2. Covert Data Exfiltration & Pipe-to-Shell Commands
            m_data = RE_EXFIL_DATA.search(line)
            if m_data:
                findings.append(
                    SkillSecurityFinding(
                        file_path=rel_str,
                        line_number=line_idx,
                        rule="covert_exfiltration_data",
                        severity="CRITICAL",
                        snippet=m_data.group(0)[:100],
                        message="Covert data exfiltration command attempting POST/upload",
                    )
                )

            m_url = RE_EXFIL_URL_VARS.search(line)
            if m_url:
                findings.append(
                    SkillSecurityFinding(
                        file_path=rel_str,
                        line_number=line_idx,
                        rule="covert_exfiltration_url_vars",
                        severity="CRITICAL",
                        snippet=m_url.group(0)[:100],
                        message="Covert exfiltration passing sensitive tokens or environment variables in URL",
                    )
                )

            m_pipe = RE_EXFIL_PIPE_SHELL.search(line)
            if m_pipe:
                findings.append(
                    SkillSecurityFinding(
                        file_path=rel_str,
                        line_number=line_idx,
                        rule="covert_exfiltration_pipe_shell",
                        severity="CRITICAL",
                        snippet=m_pipe.group(0)[:100],
                        message="Covert execution downloading and piping directly to shell",
                    )
                )

            # 3. Prompt-Injection Verification Bypass Directives (only when not a prohibition guard)
            is_prohibition = bool(RE_PROHIBITION_PREFIX.match(line))
            if not is_prohibition:
                m_nv = RE_BYPASS_NO_VERIFY.search(line)
                if m_nv:
                    findings.append(
                        SkillSecurityFinding(
                            file_path=rel_str,
                            line_number=line_idx,
                            rule="verification_bypass_no_verify",
                            severity="HIGH",
                            snippet=m_nv.group(0)[:100],
                            message="Prompt directive bypassing verification hooks via --no-verify or -n",
                        )
                    )

                m_skip = RE_BYPASS_TEST_SKIP.search(line)
                if m_skip:
                    findings.append(
                        SkillSecurityFinding(
                            file_path=rel_str,
                            line_number=line_idx,
                            rule="verification_bypass_test_skip",
                            severity="HIGH",
                            snippet=m_skip.group(0)[:100],
                            message="Prompt directive instructing test framework skip",
                        )
                    )

                m_mock = RE_BYPASS_MOCK.search(line)
                if m_mock:
                    findings.append(
                        SkillSecurityFinding(
                            file_path=rel_str,
                            line_number=line_idx,
                            rule="verification_bypass_mock",
                            severity="HIGH",
                            snippet=m_mock.group(0)[:100],
                            message="Prompt directive instructing internal mock injection",
                        )
                    )

                m_cordis = RE_BYPASS_CORDIS.search(line)
                if m_cordis:
                    findings.append(
                        SkillSecurityFinding(
                            file_path=rel_str,
                            line_number=line_idx,
                            rule="verification_bypass_cordis",
                            severity="HIGH",
                            snippet=m_cordis.group(0)[:100],
                            message="Prompt directive attempting to bypass or disable Cordis verification",
                        )
                    )

    violations = [
        f"{f.file_path}:{f.line_number} [{f.severity}] {f.rule}: {f.message}"
        for f in findings
    ]
    return SkillSecurityReport(
        clean=(len(findings) == 0),
        violations=violations,
        findings=findings,
        scanned_files=scanned_files,
    )
