"""Teamwork Challenger Empirical Stress Harness for Cordis Core Engine Upgrades.

Adversarial stress-testing of:
1. AST Reachability & Mutator expansions (cordis/mutator.py)
2. MAR diagnostic calculation & TestTamperingReport (cordis/ast_gate.py)
3. Pre-flight repository policy scraper (cordis/policy_guard.py)
4. CLI subcommands check-policy and probe (cordis/cli.py)
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from cordis.ast_gate import (
    TestTamperingReport,
    audit_test_tampering,
    calculate_mock_to_assertion_ratio,
)
from cordis.cli import run_check_policy_cli, run_probe_cli
from cordis.mutator import (
    _is_boundary_constrained,
    generate_ast_mutants,
    run_in_memory_mutation_gate,
)
from cordis.policy_guard import (
    PolicyAuditReport,
    audit_repository_policy,
)


class TestChallengerMutatorStress:
    """Adversarial stress tests for cordis/mutator.py."""

    def test_oracle_mutants_are_always_syntactically_valid(self):
        """Oracle test: every mutant produced from complex code must compile via ast.parse."""
        complex_snippets = [
            """
def walrus_func(x):
    if (n := len(x)) > 5:
        return n
    return 0
""",
            """
def chained_func(a, b, c):
    if 0 <= a < b <= c < 100:
        return True
    return False
""",
            """
def nested_unary(x, y):
    if not (not (x and not y)):
        return 1
    return 0
""",
            """
def identity_membership(val, items):
    if val is None:
        return 0
    if val is not None:
        if val in items:
            return 1
        elif val not in items:
            return 2
    return 3
""",
            """
def subscript_slices(lst, d):
    a = lst[0]
    b = lst[0:]
    c = lst[:5]
    d_val = d["key"]
    e = lst[-1]
    f = lst[::2]
    return a + len(b)
""",
            """
def augassign_func(x):
    if x <= 10:
        return x
    x += 1
    if x > 10:
        return x
    return 0
""",
            """
def walrus_reassign_func(x):
    if x <= 10:
        return x
    if (x := x + 2) > 10:
        return x
    return 0
""",
            """
class Handler:
    def process(self):
        if 0 <= self.delay <= 60:
            return self.delay
        if self.delay > 60:
            return 60
        return 0
""",
            """
def return_types(flag):
    if flag == 1:
        return 42
    elif flag == 2:
        return 3.14
    elif flag == 3:
        return True
    elif flag == 4:
        return None
    return "result"
""",
            """
def while_loop(count):
    while count > 0:
        count -= 1
    return count
""",
        ]

        for snippet in complex_snippets:
            mutants = generate_ast_mutants(snippet, max_mutants=20)
            assert isinstance(mutants, list)
            for desc, lineno, mutated_src in mutants:
                try:
                    parsed = ast.parse(mutated_src)
                    assert parsed is not None
                except SyntaxError as e:
                    pytest.fail(f"Mutant produced invalid Python syntax!\nSnippet:\n{snippet}\nMutant:\n{mutated_src}\nError: {e}")

    def test_reachability_pruning_with_attribute_guard(self):
        """Verify reachability pruning works on object attributes (e.g. self.timeout)."""
        src = """
def check_timeout(self):
    if 0 <= self.timeout <= 30:
        return self.timeout
    if self.timeout > 30:
        return 30
    return 0
"""
        tree = ast.parse(src)
        compares = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)]
        second_compare = next(c for c in compares if isinstance(c.ops[0], ast.Gt))
        assert _is_boundary_constrained(tree, second_compare, "compare_gt_gte") is True

    def test_reachability_retains_when_variable_reassigned_in_sibling(self):
        """Verify boundary shift is NOT pruned when variable is modified between guard and compare."""
        src = """
def worker(val):
    if val <= 10:
        return val
    val = val - 5
    if val > 10:
        return 10
    return 0
"""
        tree = ast.parse(src)
        compares = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)]
        gt_compare = next(c for c in compares if isinstance(c.ops[0], ast.Gt))
        assert _is_boundary_constrained(tree, gt_compare, "compare_gt_gte") is False

    def test_reachability_retains_when_preceding_if_is_not_terminal(self):
        """Verify boundary shift is NOT pruned when preceding if does not terminate."""
        src = """
def worker(val):
    if val <= 10:
        print("logging")
    if val > 10:
        return 10
    return 0
"""
        tree = ast.parse(src)
        compares = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)]
        gt_compare = next(c for c in compares if isinstance(c.ops[0], ast.Gt))
        assert _is_boundary_constrained(tree, gt_compare, "compare_gt_gte") is False

    def test_reachability_lower_bound_pruning(self):
        """Verify lower bound pruning (e.g. delay >= 5: return; delay < 5: return)."""
        src = """
def guard_low(delay):
    if delay >= 5:
        return delay
    if delay < 5:
        return 5
    return 0
"""
        tree = ast.parse(src)
        compares = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)]
        lt_compare = next(c for c in compares if isinstance(c.ops[0], ast.Lt))
        assert _is_boundary_constrained(tree, lt_compare, "compare_lt_lte") is True

    def test_subscript_mutator_ignores_store_and_del(self):
        """Verify subscript perturbation never mutates assignments or deletes."""
        src = """
def test_assign(arr):
    arr[0] = 99
    del arr[0]
    return arr[0]
"""
        mutants = generate_ast_mutants(src, max_mutants=10)
        for desc, lineno, mutated in mutants:
            if "Perturb container index" in desc:
                assert "arr[0] = 99" in mutated
                assert "del arr[0]" in mutated
                assert "return arr[1]" in mutated

    def test_subscript_mutator_ignores_tuples_and_booleans(self):
        """Verify subscript perturbation safely ignores multi-dimensional tuple indices and booleans."""
        src = """
def matrix_lookup(mat, flags):
    x = mat[0, 1]
    y = flags[False]
    return x + y
"""
        mutants = generate_ast_mutants(src, max_mutants=10)
        subscript_mutants = [m for m in mutants if "subscript" in m[0].lower()]
        assert len(subscript_mutants) == 0


class TestChallengerMARStress:
    """Adversarial stress tests for cordis/ast_gate.py MAR calculation."""

    def test_mar_boundary_exact_thresholds(self):
        """Test MAR thresholds: LOW (<0.10), MODERATE (0.10 to 0.25), HIGH_RISK (>0.25)."""
        r1 = calculate_mock_to_assertion_ratio("")
        assert r1["mar"] == 0.0
        assert r1["risk_level"] == "LOW"
        assert r1["is_high_risk"] is False

        code_10pct = """
from unittest.mock import Mock
def test_all():
    assert 1 == 1
    assert 2 == 2
    assert 3 == 3
    assert 4 == 4
    assert 5 == 5
    assert 6 == 6
    assert 7 == 7
    assert 8 == 8
    assert 9 == 9
    assert 10 == 10
""" + "\n".join(f"    assert {i} == {i}" for i in range(11, 21))
        r_low = calculate_mock_to_assertion_ratio(code_10pct)
        assert r_low["total_mocks"] == 1
        assert r_low["total_assertions"] == 20
        assert r_low["mar"] == 0.05
        assert r_low["risk_level"] == "LOW"

        code_25pct = """
import mock
def test_exact_25():
    assert 1 == 1
    assert 2 == 2
    assert 3 == 3
    assert 4 == 4
"""
        r_25 = calculate_mock_to_assertion_ratio(code_25pct)
        assert r_25["total_mocks"] == 1
        assert r_25["total_assertions"] == 4
        assert r_25["mar"] == 0.25
        assert r_25["risk_level"] == "MODERATE"
        assert r_25["is_high_risk"] is False

        code_high = """
import mock
def test_high():
    m = mock.MagicMock()
    assert 1 == 1
    assert 2 == 2
    assert 3 == 3
    assert 4 == 4
    assert 5 == 5
    assert 6 == 6
    assert 7 == 7
"""
        r_high = calculate_mock_to_assertion_ratio(code_high)
        assert r_high["mar"] > 0.25
        assert r_high["risk_level"] == "HIGH_RISK"
        assert r_high["is_high_risk"] is True

    def test_mar_zero_assertions_with_many_mocks(self):
        """Zero assertions with 50 mocks must not divide by zero and must be HIGH_RISK."""
        mock_calls = "\n".join(f"    m_{i} = Mock()" for i in range(50))
        code = f"""
from unittest.mock import Mock
def test_hollow():
{mock_calls}
"""
        r = calculate_mock_to_assertion_ratio(code)
        assert r["total_assertions"] == 0
        assert r["total_mocks"] == 51
        assert r["mar"] == 51.0
        assert r["risk_level"] == "HIGH_RISK"
        assert r["is_high_risk"] is True

    def test_tampering_report_includes_mar_fields(self):
        """Verify TestTamperingReport carries MAR data correctly."""
        old_test = "def test_ok(): assert 1 == 1"
        new_test = """
from unittest.mock import MagicMock
def test_ok():
    m = MagicMock()
    assert 1 == 1
"""
        report = audit_test_tampering(old_test, new_test)
        assert hasattr(report, "total_mocks")
        assert hasattr(report, "mar")
        assert hasattr(report, "risk_level")
        assert hasattr(report, "mar_risk_level")
        assert report.total_mocks == 2
        assert report.mar == 2.0
        assert report.risk_level == "HIGH_RISK"
        assert report.mar_risk_level == "HIGH_RISK"


class TestChallengerPolicyScraper:
    """Adversarial stress tests for cordis/policy_guard.py."""

    def test_policy_case_insensitivity_and_doc_dirs(self, tmp_path: Path):
        """Verify policy discovery finds lowercase, uppercase, and docs/ files."""
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        contributing_file = docs_dir / "contributing.md"
        contributing_file.write_text("We disallow AI generated contributions.", encoding="utf-8")

        rep = audit_repository_policy(tmp_path)
        assert rep.status == "BLOCKED_POLICY"
        assert rep.ai_banned is True
        assert len(rep.governance_files_scanned) == 1
        assert "docs/contributing.md" in rep.governance_files_scanned[0].replace("\\", "/")

    def test_policy_empty_files_remain_permitted(self, tmp_path: Path):
        """Empty governance files must not crash and should result in PERMITTED."""
        (tmp_path / "CONTRIBUTING.md").write_text("", encoding="utf-8")
        (tmp_path / "README.md").write_text("   \n\n  ", encoding="utf-8")

        rep = audit_repository_policy(tmp_path)
        assert rep.status == "PERMITTED"
        assert rep.ai_banned is False
        assert rep.issue_required is False
        assert len(rep.governance_files_scanned) == 2

    def test_policy_benign_ai_library_readme_is_permitted(self, tmp_path: Path):
        """A library ABOUT AI that allows contributions must NOT be falsely blocked."""
        readme = tmp_path / "README.md"
        readme.write_text(
            """
# AI Agent Toolkit
This is a python library for developing generative AI workflows with LLM integration.
We welcome community contributions! Please read our guidelines below.
""",
            encoding="utf-8",
        )
        rep = audit_repository_policy(tmp_path)
        assert rep.status == "PERMITTED"
        assert rep.ai_banned is False

    def test_policy_ai_ban_precedence_over_issue_required(self, tmp_path: Path):
        """If a repository has both an AI ban and mandatory issues, BLOCKED_POLICY takes precedence."""
        (tmp_path / "CONTRIBUTING.md").write_text("No AI-generated PRs accepted.", encoding="utf-8")
        gh = tmp_path / ".github"
        gh.mkdir()
        (gh / "PULL_REQUEST_TEMPLATE.md").write_text("All pull requests must reference an issue.", encoding="utf-8")

        rep = audit_repository_policy(tmp_path)
        assert rep.status == "BLOCKED_POLICY"
        assert rep.ai_banned is True
        assert rep.issue_required is True
        assert len(rep.citations) == 2


class TestChallengerCLISmoke:
    """Adversarial stress tests for cordis/cli.py."""

    def test_cli_check_policy_returns_zero_on_permitted(self, tmp_path: Path):
        """Verify check-policy exits 0 on permitted repository and generates valid JSON."""
        (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\nFeel free to open PRs!", encoding="utf-8")
        json_out = tmp_path / "policy.json"

        code = run_check_policy_cli(repo_dir=str(tmp_path), output_json=str(json_out))
        assert code == 0
        assert json_out.exists()

        data = json.loads(json_out.read_text(encoding="utf-8"))
        assert data["status"] == "PERMITTED"
        assert data["ai_banned"] is False
        assert data["issue_required"] is False
        assert "CONTRIBUTING.md" in data["governance_files_scanned"][0]

    def test_cli_check_policy_returns_one_on_blocked(self, tmp_path: Path):
        """Verify check-policy exits 1 on blocked repository."""
        (tmp_path / "CONTRIBUTING.md").write_text("We ban machine-generated pull requests.", encoding="utf-8")
        code = run_check_policy_cli(repo_dir=str(tmp_path))
        assert code == 1

    def test_cli_probe_on_isolated_target(self, tmp_path: Path):
        """Verify probe subcommand executes offline on an isolated source and test fixture."""
        src_file = tmp_path / "calc_toy.py"
        src_file.write_text(
            """
def add(a, b):
    return a + b
""",
            encoding="utf-8",
        )
        test_file = tmp_path / "test_toy.py"
        test_file.write_text(
            """
from calc_toy import add

def test_add():
    assert add(1, 2) == 3
    assert add(0, 0) == 0
    assert add(-1, 1) == 0
""",
            encoding="utf-8",
        )
        json_out = tmp_path / "probe_out.json"
        code = run_probe_cli(
            repo=str(tmp_path),
            target="calc_toy.py",
            test="test_toy.py",
            function="add",
            max_mutants=1,
            output_json=str(json_out),
            timeout=10.0,
        )
        assert code == 0
        assert json_out.exists()

        data = json.loads(json_out.read_text(encoding="utf-8"))
        assert data["zero_token"] is True
        assert data["llm_tokens_consumed"] == 0
        assert data["passed"] is True
        assert data["total_mutants"] == 1
        assert data["killed_mutants"] == 1
        assert data["survived_mutants"] == 0
        assert data["kill_rate"] == 1.0
        assert "mar" in data
