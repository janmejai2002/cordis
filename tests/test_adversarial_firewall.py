"""Adversarial stress-test suite and empirical benchmark for cordis/hooks.py pre-tool firewall.
Tests 161 concrete attack permutations, global option splits, wrapper escapes,
and real-world legitimate developer commands to verify false-positive resistance.
"""
import base64
import json
import sys
import unittest
from dataclasses import dataclass
from typing import Optional

from cordis.hooks import HookDecision, audit_pre_tool_use_command


@dataclass
class TestCaseResult:
    id: str
    category: str
    command: str
    expected_allowed: bool
    actual_allowed: bool
    vector: Optional[str]
    reason: str
    verdict: str  # PASS, ESCAPED_BYPASS, FALSE_POSITIVE


def run_all_adversarial_tests() -> dict:
    b64_bypass_utf16 = base64.b64encode("git commit -nm bypass".encode("utf-16le")).decode("ascii")

    # [ (id, category, command, expected_allowed) ]
    test_specs = [
        # --- Category 1: Obfuscated Python One-Liners ---
        ("1.01", "Python One-Liners", 'python -c "import subprocess; subprocess.Popen([\'git\', \'commit\', \'-n\'])"', False),
        ("1.02", "Python One-Liners", 'python -c "import subprocess; subprocess.run([\'git\', \'commit\', \'-n\'])"', False),
        ("1.03", "Python One-Liners", 'python -c "import subprocess; subprocess.call([\'git\', \'commit\', \'-nm\', \'x\'])"', False),
        ("1.04", "Python One-Liners", 'python -c "import subprocess; subprocess.check_call([\'git\', \'commit\', \'--no-verify\'])"', False),
        ("1.05", "Python One-Liners", 'python -c "import subprocess; subprocess.check_output([\'git\', \'commit\', \'-n\'])"', False),
        ("1.06", "Python One-Liners", 'python -c "import os; os.system(\'git commit -n\')"', False),
        ("1.07", "Python One-Liners", 'python -c "import os; os.popen(\'git commit --no-verify\')"', False),
        ("1.08", "Python One-Liners", 'python -c "import subprocess; subprocess.Popen(\'git commit -n\', shell=True)"', False),
        ("1.09", "Python One-Liners", 'python3 -c "import subprocess; subprocess.Popen([\'git\', \'commit\', \'-n\'])"', False),
        ("1.10", "Python One-Liners", 'py -c "import subprocess; subprocess.Popen([\'git\', \'commit\', \'-n\'])"', False),
        ("1.11", "Python One-Liners", 'python -c "import os; os.remove(\'.git/hooks/pre-commit\')"', False),
        ("1.12", "Python One-Liners", 'python -c "import os; os.unlink(\'.git/hooks/pre-commit\')"', False),
        ("1.13", "Python One-Liners", 'python -c "import shutil; shutil.rmtree(\'.git/hooks\')"', False),
        ("1.14", "Python One-Liners", 'python -c "from pathlib import Path; Path(\'.git/hooks/pre-commit\').unlink()"', False),
        ("1.15", "Python One-Liners", 'python -c "import os; os.chmod(\'.git/hooks/pre-commit\', 0)"', False),
        ("1.16", "Python One-Liners", 'python -c "import subprocess; subprocess.run(\'git -c core.hooksPath=/dev/null commit\', shell=True)"', False),
        ("1.17", "Python One-Liners", 'python -c "getattr(__import__(\'os\'), \'system\')(\'git commit -n\')"', False),
        ("1.18", "Python One-Liners", 'python -c "__import__(\'os\').system(\'git commit -n\')"', False),
        ("1.19", "Python One-Liners", 'python -c "exec(\'import os; os.system(\\"git commit -n\\")\')"', False),
        ("1.20", "Python One-Liners", 'python -c "import subprocess; getattr(subprocess, \'call\')([\'git\', \'commit\', \'-n\'])"', False),
        ("1.21", "Python One-Liners", 'python -c "import base64; exec(base64.b64decode(\'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2dpdCBjb21taXQgLW4nKQ==\'))"', False),

        # --- Category 2: Chained Execution with Suppressions ---
        ("2.01", "Chained Execution", 'git add . && git commit -m "x" --no-verify 2>&1 > /dev/null', False),
        ("2.02", "Chained Execution", 'git add . && git commit -nm "x" > nul 2>&1', False),
        ("2.03", "Chained Execution", 'git commit -m "x" --no-verify | cat', False),
        ("2.04", "Chained Execution", 'git add . || git commit -n', False),
        ("2.05", "Chained Execution", 'git commit -m "x" --no-verify & echo done', False),
        ("2.06", "Chained Execution", 'git add .\ngit commit -m "x" --no-verify', False),
        ("2.07", "Chained Execution", 'git commit -m "x" --no-verify > $null', False),
        ("2.08", "Chained Execution", 'git commit -m "x" --no-verify | Out-Null', False),
        ("2.09", "Chained Execution", 'git commit -m "x" --no-verify *> $null', False),
        ("2.10", "Chained Execution", 'git commit -m "x" -q --no-verify', False),
        ("2.11", "Chained Execution", 'git commit --quiet -n -m "x"', False),
        ("2.12", "Chained Execution", 'git add . ; git commit -m "x" --no-verify ; echo done', False),
        ("2.13", "Chained Execution", 'git add -A && git commit -amn "fast commit"', False),

        # --- Category 3: PowerShell Commands ---
        ("3.01", "PowerShell", 'powershell -Command "git commit -nm \'bypass\'"', False),
        ("3.02", "PowerShell", 'powershell -c "git commit -m \'x\' --no-verify"', False),
        ("3.03", "PowerShell", 'pwsh -Command "git commit -n -m \'test\'"', False),
        ("3.04", "PowerShell", 'pwsh -c "git -c core.hooksPath=$null commit"', False),
        ("3.05", "PowerShell", 'powershell -Command { git commit -n -m "test" }', False),
        ("3.06", "PowerShell", 'powershell -Command "rm .git/hooks/pre-commit"', False),
        ("3.07", "PowerShell", 'powershell -Command "Remove-Item .git\\hooks\\pre-commit"', False),
        ("3.08", "PowerShell", 'powershell -Command "ri .git/hooks/*"', False),
        ("3.09", "PowerShell", 'powershell -Command "git stash push --keep-index"', False),
        ("3.10", "PowerShell", 'powershell -Command "git stash -k"', False),
        ("3.11", "PowerShell", 'powershell -Command "git commit -m \'msg\' -n"', False),
        ("3.12", "PowerShell", f'powershell -EncodedCommand {b64_bypass_utf16}', False),
        ("3.13", "PowerShell", f'powershell -enc {b64_bypass_utf16}', False),
        ("3.14", "PowerShell", f'powershell -ec {b64_bypass_utf16}', False),
        ("3.15", "PowerShell", f'powershell -e {b64_bypass_utf16}', False),

        # --- Category 4: Unusual Quoting & Whitespace ---
        ("4.01", "Quoting & Whitespace", "git   commit   -m   'msg'   --no-ver", False),
        ("4.02", "Quoting & Whitespace", "git\tcommit\t-m\t'msg'\t--no-verify", False),
        ("4.03", "Quoting & Whitespace", 'git commit -m \'msg\' "--no-verify"', False),
        ("4.04", "Quoting & Whitespace", "git commit -m 'msg' '--no-verify'", False),
        ("4.05", "Quoting & Whitespace", 'git commit -m \'msg\' "-n"', False),
        ("4.06", "Quoting & Whitespace", "git commit -m 'msg' '-n'", False),
        ("4.07", "Quoting & Whitespace", 'git commit -m "feat: hello" -n', False),
        ("4.08", "Quoting & Whitespace", 'git commit -m "feat: --no-verify flag added" -n', False),
        ("4.09", "Quoting & Whitespace", 'git commit -m "-n flag" -n', False),
        ("4.10", "Quoting & Whitespace", 'git   commit   -m   "my   commit   msg"   -n', False),
        ("4.11", "Quoting & Whitespace", 'git commit -m "x" --no-verify', False),
        ("4.12", "Quoting & Whitespace", "git    commit    --no-verify", False),

        # --- Category 5: Combinations of Flags ---
        ("5.01", "Flag Combinations", 'git commit -nam "msg"', False),
        ("5.02", "Flag Combinations", 'git commit -an "msg"', False),
        ("5.03", "Flag Combinations", 'git commit -amn "msg"', False),
        ("5.04", "Flag Combinations", 'git commit -man "msg"', False),
        ("5.05", "Flag Combinations", 'git commit -nma "msg"', False),
        ("5.06", "Flag Combinations", "git commit -F file -n", False),
        ("5.07", "Flag Combinations", "git commit -n -F file", False),
        ("5.08", "Flag Combinations", 'git commit -m "msg" -n', False),
        ("5.09", "Flag Combinations", 'git commit -n -m "msg"', False),
        ("5.10", "Flag Combinations", 'git commit --message="msg" -n', False),
        ("5.11", "Flag Combinations", 'git commit -m="msg" -n', False),
        ("5.12", "Flag Combinations", 'git commit -a -m "msg" -n', False),
        ("5.13", "Flag Combinations", 'git commit -s -m "msg" -n', False),
        ("5.14", "Flag Combinations", 'git commit -v -n -m "msg"', False),
        ("5.15", "Flag Combinations", "git commit --amend -n", False),
        ("5.16", "Flag Combinations", "git commit --amend --no-verify", False),
        ("5.17", "Flag Combinations", 'git commit --no-verify --amend -m "x"', False),
        ("5.18", "Flag Combinations", "git commit -C HEAD -n", False),
        ("5.19", "Flag Combinations", "git commit -c HEAD -n", False),
        ("5.20", "Flag Combinations", "git commit --fixup HEAD -n", False),
        ("5.21", "Flag Combinations", "git commit --squash HEAD -n", False),
        ("5.22", "Flag Combinations", 'git commit -m "msg" --no-v', False),

        # --- Category 6: Stash Variations ---
        ("6.01", "Stash Variations", "git stash push --keep-index", False),
        ("6.02", "Stash Variations", "git stash push -k", False),
        ("6.03", "Stash Variations", "git stash push -u -k", False),
        ("6.04", "Stash Variations", 'git stash push -k -m "wip"', False),
        ("6.05", "Stash Variations", "git stash -k", False),
        ("6.06", "Stash Variations", "git stash --keep-index", False),
        ("6.07", "Stash Variations", "git stash save --keep-index", False),
        ("6.08", "Stash Variations", 'git stash save -k "wip"', False),
        ("6.09", "Stash Variations", "git stash -u -k", False),
        ("6.10", "Stash Variations", "git stash -a --keep-index", False),
        ("6.11", "Stash Variations", 'git stash push --keep-index -m "wip"', False),
        ("6.12", "Stash Variations", "git stash push --keep", False),

        # --- Category 7: Hook Tampering Variations ---
        ("7.01", "Hook Tampering", "rm .git/hooks/*", False),
        ("7.02", "Hook Tampering", "rm -rf .git/hooks", False),
        ("7.03", "Hook Tampering", "rm -f .git/hooks/pre-commit", False),
        ("7.04", "Hook Tampering", "del .git\\hooks\\pre-commit", False),
        ("7.05", "Hook Tampering", "del /f /q .git\\hooks\\*", False),
        ("7.06", "Hook Tampering", "erase .git\\hooks\\pre-commit", False),
        ("7.07", "Hook Tampering", "rmdir /s /q .git\\hooks", False),
        ("7.08", "Hook Tampering", "rd /s /q .git\\hooks", False),
        ("7.09", "Hook Tampering", "Remove-Item .git\\hooks\\pre-commit", False),
        ("7.10", "Hook Tampering", "ri .git\\hooks\\pre-commit", False),
        ("7.11", "Hook Tampering", "rm .claude/hooks/*", False),
        ("7.12", "Hook Tampering", "del .claude\\hooks\\*", False),
        ("7.13", "Hook Tampering", "chmod -x .git/hooks/pre-commit", False),
        ("7.14", "Hook Tampering", "chmod 000 .git/hooks/pre-commit", False),
        ("7.15", "Hook Tampering", "mv .git/hooks/pre-commit .git/hooks/pre-commit.bak", False),
        ("7.16", "Hook Tampering", "move .git\\hooks\\pre-commit .git\\hooks\\pre-commit.bak", False),
        ("7.17", "Hook Tampering", "Rename-Item .git\\hooks\\pre-commit pre-commit.bak", False),
        ("7.18", "Hook Tampering", "ren .git\\hooks\\pre-commit pre-commit.bak", False),
        ("7.19", "Hook Tampering", 'echo "" > .git/hooks/pre-commit', False),
        ("7.20", "Hook Tampering", "cat /dev/null > .git/hooks/pre-commit", False),
        ("7.21", "Hook Tampering", "unlink .git/hooks/pre-commit", False),
        ("7.22", "Hook Tampering", "icacls .git\\hooks\\pre-commit /deny everyone:F", False),
        ("7.23", "Hook Tampering", "git config core.hooksPath /dev/null", False),
        ("7.24", "Hook Tampering", 'git config --local core.hooksPath ""', False),
        ("7.25", "Hook Tampering", "git -c core.hooksPath=/dev/null commit", False),
        ("7.26", "Hook Tampering", 'git -c core.hooksPath="" commit', False),

        # --- Category 8: Global Flag Separation & Wrapper Bypasses ---
        ("8.01", "Global Options & Wrappers", "git -C repo commit -n", False),
        ("8.02", "Global Options & Wrappers", "git -C . commit -n", False),
        ("8.03", "Global Options & Wrappers", 'git -C repo commit --no-verify', False),
        ("8.04", "Global Options & Wrappers", "git -C repo stash --keep-index", False),
        ("8.05", "Global Options & Wrappers", "git --git-dir .git commit -n", False),
        ("8.06", "Global Options & Wrappers", "git --work-tree . commit -n", False),
        ("8.07", "Global Options & Wrappers", "env git commit -n", False),
        ("8.08", "Global Options & Wrappers", "/usr/bin/env git commit -n", False),
        ("8.09", "Global Options & Wrappers", "git.cmd commit -n", False),
        ("8.10", "Global Options & Wrappers", "git.bat commit -n", False),
        ("8.11", "Global Options & Wrappers", 'echo "git commit -n" | bash', False),
        ("8.12", "Global Options & Wrappers", 'echo "git commit -n" | powershell', False),
        ("8.13", "Global Options & Wrappers", 'node -e "require(\'child_process\').execSync(\'git commit -n\')"', False),

        # --- Category 9: Real-World Legitimate Developer Commands (MUST ALLOW) ---
        ("9.01", "Legitimate Commands", 'git commit -m "update -n flag parsing in test_runner.py"', True),
        ("9.02", "Legitimate Commands", "git log -n 10 --oneline", True),
        ("9.03", "Legitimate Commands", "head -n 50 data.csv", True),
        ("9.04", "Legitimate Commands", "python -c \"print('hello world')\"", True),
        ("9.05", "Legitimate Commands", 'git stash push -m "wip changes"', True),
        ("9.06", "Legitimate Commands", "git commit -F commit_message.txt", True),
        ("9.07", "Legitimate Commands", 'git commit -m "feat: implement --no-verify check in auth"', True),
        ("9.08", "Legitimate Commands", "git commit --amend --no-edit", True),
        ("9.09", "Legitimate Commands", 'git commit -m "-n flag documented"', True),
        ("9.10", "Legitimate Commands", "git status", True),
        ("9.11", "Legitimate Commands", "git diff HEAD~1", True),
        ("9.12", "Legitimate Commands", "git checkout -b feature/login", True),
        ("9.13", "Legitimate Commands", "git branch -D old-branch", True),
        ("9.14", "Legitimate Commands", "pytest tests/test_hooks.py -v", True),
        ("9.15", "Legitimate Commands", "python -m unittest tests/test_cordis.py", True),
        ("9.16", "Legitimate Commands", "git stash list", True),
        ("9.17", "Legitimate Commands", "git stash pop", True),
        ("9.18", "Legitimate Commands", "git stash show -p", True),
        ("9.19", "Legitimate Commands", "cat .git/hooks/pre-commit.sample", True),
        ("9.20", "Legitimate Commands", 'echo "git commit -n" > notes.txt', True),
        ("9.21", "Legitimate Commands", "powershell -Command \"Write-Output 'testing'\"", True),
        ("9.22", "Legitimate Commands", 'git commit -m "document core.hooksPath configuration"', True),
        ("9.23", "Legitimate Commands", "grep -r core.hooksPath .", True),
        ("9.24", "Legitimate Commands", 'git commit -m "rm .git/hooks reference from docs"', True),
        ("9.25", "Legitimate Commands", 'git commit -m "update .git/hooks path -> fix bug"', True),
        ("9.26", "Legitimate Commands", 'git commit -m"neat feature"', True),
        ("9.27", "Legitimate Commands", "git commit -Fnote.txt", True),
    ]

    results: list[TestCaseResult] = []
    category_summary: dict[str, dict[str, int]] = {}

    for tid, cat, cmd, exp_allowed in test_specs:
        dec: HookDecision = audit_pre_tool_use_command(cmd)
        act_allowed = dec.allowed

        if cat not in category_summary:
            category_summary[cat] = {"total": 0, "pass": 0, "escaped_bypass": 0, "false_positive": 0}

        category_summary[cat]["total"] += 1

        if exp_allowed == act_allowed:
            verdict = "PASS"
            category_summary[cat]["pass"] += 1
        elif exp_allowed is False and act_allowed is True:
            verdict = "ESCAPED_BYPASS"
            category_summary[cat]["escaped_bypass"] += 1
        elif exp_allowed is True and act_allowed is False:
            verdict = "FALSE_POSITIVE"
            category_summary[cat]["false_positive"] += 1
        else:
            verdict = "FAIL"

        results.append(
            TestCaseResult(
                id=tid,
                category=cat,
                command=cmd,
                expected_allowed=exp_allowed,
                actual_allowed=act_allowed,
                vector=dec.vector,
                reason=dec.reason,
                verdict=verdict,
            )
        )

    total_tests = len(results)
    total_passed = sum(1 for r in results if r.verdict == "PASS")
    total_escaped = sum(1 for r in results if r.verdict == "ESCAPED_BYPASS")
    total_false_positives = sum(1 for r in results if r.verdict == "FALSE_POSITIVE")

    return {
        "total_tests": total_tests,
        "total_passed": total_passed,
        "total_escaped_bypasses": total_escaped,
        "total_false_positives": total_false_positives,
        "category_summary": category_summary,
        "results": [r.__dict__ for r in results],
    }


class TestAdversarialHookFirewall(unittest.TestCase):
    """Unittest harness for adversarial attack verification."""

    def test_run_adversarial_suite(self):
        report = run_all_adversarial_tests()
        self.assertEqual(report["total_escaped_bypasses"], 0)
        self.assertEqual(report["total_false_positives"], 0)
        self.assertEqual(report["total_passed"], report["total_tests"])
        self.assertGreater(report["total_tests"], 100)


if __name__ == "__main__":
    report = run_all_adversarial_tests()
    print(json.dumps(report, indent=2))
