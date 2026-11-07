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
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import pytest

from cordis.ast_gate import (
    ASTAnchor,
    TestTamperingReport,
    audit_test_tampering,
    calculate_mock_to_assertion_ratio,
    compute_node_hash,
    index_ast_anchors,
    _is_boundary_target,
    _is_broad_exception_type,
    _is_concrete_oracle_node,
    _is_tautological_assert,
    _is_unittest_assert_call,
    _is_weak_not_none_assert,
)
from cordis.cli import run_check_policy_cli, run_probe_cli
from cordis.forge_guard import (
    ForgeGuardReport,
    GitActorInfo,
    audit_current_environment,
    audit_forge_guard,
    compute_diff_attestation_digest,
    inspect_git_actor,
    is_bot_identity,
    verify_commit_attestation_trailer,
)
from cordis.fuzzer import (
    BenchmarkGateReport,
    DifferentialFuzzReport,
    FuzzCounterexample,
    _deep_equals,
    _generate_adversarial_values_for_type,
    _inspect_code_constants,
    _outcomes_match,
    harvest_ast_constants,
    load_repo_function_pair,
    mann_whitney_u_one_sided,
    run_differential_fuzz_gate,
    run_statistical_benchmark_gate,
)
from cordis.hooks import (
    HookDecision,
    _audit_embedded_powershell,
    _audit_embedded_python,
    _audit_embedded_shell,
    _audit_single_command,
    _compute_digest_fallback,
    _split_pipeline_segments,
    _strip_outer_quotes,
    _tokenize_command,
    audit_pre_tool_use_command,
    install_harness_hooks,
    run_stop_hook_prosecutor,
)
from cordis.mutator import (
    MutantResult,
    MutationGateReport,
    _collect_arid_ast_nodes,
    _expr_to_str,
    _extract_and_comparisons,
    _find_target_function_node,
    _is_boundary_constrained,
    _is_overload_stub,
    _is_pure_expression,
    _is_terminal_block,
    _is_terminal_statement,
    _is_tie_boundary_equivalent,
    _statement_modifies_var,
    generate_ast_mutants,
    inject_coverage_probe,
    run_in_memory_mutation_gate,
    run_repo_mutation_gate,
)
from cordis.policy_guard import (
    PolicyAuditReport,
    _discover_governance_files,
    audit_repository_policy,
)
from cordis.repair import (
    _build_candidate_inputs,
    _deduce_target_function_from_ast,
    _extract_function_from_code,
    _format_value_for_code,
    _kills_mutant,
    synthesize_mutant_killing_assertions,
    synthesize_mutant_killing_test,
)
from cordis.ts_gate import (
    AnchorDict,
    _extract_signature,
    _find_matching_brace,
    _find_matching_paren,
    _find_toplevel_relational_op,
    _is_boundary_mock,
    _is_regex_start,
    audit_ts_test_tampering,
    generate_ts_mutants,
    index_ts_ast_anchors,
    mask_ts_code,
    strip_ts_comments,
)


class TestChallengerMutatorStress(unittest.TestCase):
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


class TestChallengerMARStress(unittest.TestCase):
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


class TestChallengerPolicyScraper(unittest.TestCase):
    """Adversarial stress tests for cordis/policy_guard.py."""

    def test_policy_case_insensitivity_and_doc_dirs(self, tmp_path=None):
        """Verify policy discovery finds lowercase, uppercase, and docs/ files."""
        if tmp_path is None or not isinstance(tmp_path, Path):
            td = tempfile.TemporaryDirectory()
            self.addCleanup(td.cleanup)
            tmp_path = Path(td.name)
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        contributing_file = docs_dir / "contributing.md"
        contributing_file.write_text("We disallow AI generated contributions.", encoding="utf-8")

        rep = audit_repository_policy(tmp_path)
        assert rep.status == "BLOCKED_POLICY"
        assert rep.ai_banned is True
        assert len(rep.governance_files_scanned) == 1
        assert "docs/contributing.md" in rep.governance_files_scanned[0].replace("\\", "/")

    def test_policy_empty_files_remain_permitted(self, tmp_path=None):
        """Empty governance files must not crash and should result in PERMITTED."""
        if tmp_path is None or not isinstance(tmp_path, Path):
            td = tempfile.TemporaryDirectory()
            self.addCleanup(td.cleanup)
            tmp_path = Path(td.name)
        (tmp_path / "CONTRIBUTING.md").write_text("", encoding="utf-8")
        (tmp_path / "README.md").write_text("   \n\n  ", encoding="utf-8")

        rep = audit_repository_policy(tmp_path)
        assert rep.status == "PERMITTED"
        assert rep.ai_banned is False
        assert rep.issue_required is False
        assert len(rep.governance_files_scanned) == 2

    def test_policy_benign_ai_library_readme_is_permitted(self, tmp_path=None):
        """A library ABOUT AI that allows contributions must NOT be falsely blocked."""
        if tmp_path is None or not isinstance(tmp_path, Path):
            td = tempfile.TemporaryDirectory()
            self.addCleanup(td.cleanup)
            tmp_path = Path(td.name)
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

    def test_policy_ai_ban_precedence_over_issue_required(self, tmp_path=None):
        """If a repository has both an AI ban and mandatory issues, BLOCKED_POLICY takes precedence."""
        if tmp_path is None or not isinstance(tmp_path, Path):
            td = tempfile.TemporaryDirectory()
            self.addCleanup(td.cleanup)
            tmp_path = Path(td.name)
        (tmp_path / "CONTRIBUTING.md").write_text("No AI-generated PRs accepted.", encoding="utf-8")
        gh = tmp_path / ".github"
        gh.mkdir()
        (gh / "PULL_REQUEST_TEMPLATE.md").write_text("All pull requests must reference an issue.", encoding="utf-8")

        rep = audit_repository_policy(tmp_path)
        assert rep.status == "BLOCKED_POLICY"
        assert rep.ai_banned is True
        assert rep.issue_required is True
        assert len(rep.citations) == 2


class TestChallengerCLISmoke(unittest.TestCase):
    """Adversarial stress tests for cordis/cli.py."""

    def test_cli_check_policy_returns_zero_on_permitted(self, tmp_path=None):
        """Verify check-policy exits 0 on permitted repository and generates valid JSON."""
        if tmp_path is None or not isinstance(tmp_path, Path):
            td = tempfile.TemporaryDirectory()
            self.addCleanup(td.cleanup)
            tmp_path = Path(td.name)
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

    def test_cli_check_policy_returns_one_on_blocked(self, tmp_path=None):
        """Verify check-policy exits 1 on blocked repository."""
        if tmp_path is None or not isinstance(tmp_path, Path):
            td = tempfile.TemporaryDirectory()
            self.addCleanup(td.cleanup)
            tmp_path = Path(td.name)
        (tmp_path / "CONTRIBUTING.md").write_text("We ban machine-generated pull requests.", encoding="utf-8")
        code = run_check_policy_cli(repo_dir=str(tmp_path))
        assert code == 1

    def test_cli_probe_on_isolated_target(self, tmp_path=None):
        """Verify probe subcommand executes offline on an isolated source and test fixture."""
        if tmp_path is None or not isinstance(tmp_path, Path):
            td = tempfile.TemporaryDirectory()
            self.addCleanup(td.cleanup)
            tmp_path = Path(td.name)
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


class TestChallengerRepairStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/repair.py."""

    def test_format_value_for_code_all_variants(self):
        self.assertEqual(_format_value_for_code(float("nan")), "float('nan')")
        self.assertEqual(_format_value_for_code(float("inf")), "float('inf')")
        self.assertEqual(_format_value_for_code(float("-inf")), "float('-inf')")
        self.assertEqual(_format_value_for_code(3.14), "3.14")
        self.assertEqual(_format_value_for_code([1, "x"]), "[1, 'x']")
        self.assertEqual(_format_value_for_code((1,)), "(1,)")
        self.assertEqual(_format_value_for_code((1, 2)), "(1, 2)")
        self.assertEqual(_format_value_for_code({"k": 1}), "{'k': 1}")
        self.assertEqual(_format_value_for_code(set()), "set()")
        self.assertEqual(_format_value_for_code({1}), "{1}")
        self.assertEqual(_format_value_for_code("abc"), "'abc'")
        self.assertEqual(_format_value_for_code(42), "42")

    def test_deduce_target_function_from_ast_positions(self):
        src = (
            "def fn1(x):\n"
            "    return x + 1\n\n"
            "def fn2(y):\n"
            "    return y * 2\n"
        )
        self.assertEqual(_deduce_target_function_from_ast(src, 1), "fn1")
        self.assertEqual(_deduce_target_function_from_ast(src, 2), "fn1")
        self.assertEqual(_deduce_target_function_from_ast(src, 4), "fn2")
        self.assertEqual(_deduce_target_function_from_ast(src, 5), "fn2")
        self.assertEqual(_deduce_target_function_from_ast(src, 99), "fn1")
        self.assertEqual(_deduce_target_function_from_ast("invalid syntax {{{", 1), "")

    def test_extract_function_from_code_all_targets(self):
        src = (
            "def standalone(a, b):\n"
            "    return a + b\n\n"
            "class MathCls:\n"
            "    def inst_method(self, a, b):\n"
            "        return a * b\n"
            "    @staticmethod\n"
            "    def stat_method(a, b):\n"
            "        return a - b\n"
        )
        fn1, p1 = _extract_function_from_code(src, "standalone")
        self.assertTrue(callable(fn1))
        self.assertEqual(p1, "standalone")
        self.assertEqual(fn1(2, 3), 5)

        fn2, p2 = _extract_function_from_code(src, "MathCls.inst_method")
        self.assertTrue(callable(fn2))
        self.assertEqual(p2, "MathCls().inst_method")
        self.assertEqual(fn2(2, 3), 6)

        fn3, p3 = _extract_function_from_code(src, "MathCls.stat_method")
        self.assertTrue(callable(fn3))
        self.assertEqual(p3, "MathCls().stat_method")
        self.assertEqual(fn3(10, 3), 7)

        fn4, p4 = _extract_function_from_code("syntax error {", "foo")
        self.assertIsNone(fn4)
        self.assertEqual(p4, "foo")

        fn5, p5 = _extract_function_from_code(src, "not_found")
        self.assertIsNone(fn5)
        self.assertEqual(p5, "not_found")

    def test_kills_mutant_matrix(self):
        self.assertFalse(_kills_mutant(10, None, 10, None))
        self.assertTrue(_kills_mutant(10, None, 20, None))
        self.assertTrue(_kills_mutant(10, None, None, ValueError("err")))
        self.assertTrue(_kills_mutant(None, ValueError("err"), 10, None))
        self.assertTrue(_kills_mutant(None, ValueError("err"), None, TypeError("err")))
        self.assertFalse(_kills_mutant(None, ValueError("err"), None, ValueError("other")))

    def test_build_candidate_inputs_coverage(self):
        def f0():
            return 0
        def f1(x: int):
            return x
        def f2(a: float, b: str):
            return a
        def f3(a, b, c):
            return a
        def f4(a, b, c, d):
            return a
        def fb(b: bytes):
            return b
        def f_bool(flag: bool):
            return flag

        self.assertEqual(_build_candidate_inputs(f0, {}), [()])
        c1 = _build_candidate_inputs(f1, {"int": [99]})
        self.assertIn((99,), c1)
        self.assertIn((0,), c1)
        c2 = _build_candidate_inputs(f2, {"float": [1.25], "str": ["alpha"]})
        self.assertTrue(any(isinstance(t[0], float) and isinstance(t[1], str) for t in c2))
        c3 = _build_candidate_inputs(f3, {})
        self.assertTrue(len(c3) > 0 and len(c3[0]) == 3)
        c4 = _build_candidate_inputs(f4, {})
        self.assertTrue(len(c4) > 0 and len(c4[0]) == 4)
        cb = _build_candidate_inputs(fb, {"bytes": [b"test"]})
        self.assertIn((b"test",), cb)
        c_bool = _build_candidate_inputs(f_bool, {})
        self.assertEqual(c_bool, [(False,), (True,)])

    def test_synthesize_mutant_killing_assertions_and_test(self):
        src = (
            "def calculate(n: int) -> int:\n"
            "    if n > 5:\n"
            "        return n * 10\n"
            "    return n + 1\n"
        )
        mutants = generate_ast_mutants(src, target_function="calculate", max_mutants=5)
        self.assertTrue(len(mutants) > 0)
        surviving = [
            MutantResult(
                mutant_id=i,
                description=d,
                lineno=l,
                killed=False,
                mutated_code_snippet="",
                mutated_source=s,
            )
            for i, (d, l, s) in enumerate(mutants, start=1)
        ]
        assertions = synthesize_mutant_killing_assertions(src, "calculate", surviving)
        self.assertTrue(isinstance(assertions, list))
        self.assertTrue(len(assertions) > 0)
        self.assertTrue(all("calculate(" in a for a in assertions))

        # Empty surviving
        self.assertEqual(synthesize_mutant_killing_assertions(src, "calculate", []), [])
        # Empty / bad code
        self.assertEqual(synthesize_mutant_killing_assertions("bad syntax {", "calculate", surviving), [])

        # Full test generation
        test_str = synthesize_mutant_killing_test(src, "calculate", surviving)
        self.assertIn("def test_calculate_cordis_invariants():", test_str)
        self.assertIn("calculate(", test_str)
        self.assertNotIn("import math", test_str)

        # Explicit name preservation vs deduced fallback
        test_custom = synthesize_mutant_killing_test(src, "custom_name", surviving)
        self.assertIn("def test_custom_name_cordis_invariants():", test_custom)
        test_deduced = synthesize_mutant_killing_test(src, "", surviving)
        self.assertIn("def test_calculate_cordis_invariants():", test_deduced)

        # Empty surviving -> pass
        test_empty = synthesize_mutant_killing_test(src, "calculate", [])
        self.assertIn("def test_calculate_cordis_invariants():", test_empty)
        self.assertIn("pass", test_empty)

        # Nan case
        src_nan = "def nan_calc(x):\n    return float('nan')\n"
        m_nan = generate_ast_mutants(src_nan, target_function="nan_calc", max_mutants=2)
        surv_nan = [
            MutantResult(mutant_id=i, description=d, lineno=l, killed=False, mutated_code_snippet="", mutated_source=s)
            for i, (d, l, s) in enumerate(m_nan, start=1)
        ]
        test_nan = synthesize_mutant_killing_test(src_nan, "nan_calc", surv_nan)
        self.assertIn("test_nan_calc_cordis_invariants", test_nan)
        self.assertIn("import math", test_nan)


class TestChallengerHooksStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/hooks.py."""

    def test_split_pipeline_segments(self):
        cmd = "echo a && echo b || echo c; echo d | echo e & echo f \n echo g"
        segs = _split_pipeline_segments(cmd)
        self.assertEqual(segs, ["echo a", "echo b", "echo c", "echo d", "echo e", "echo f", "echo g"])

        single_q = "echo 'a && b || c'"
        self.assertEqual(_split_pipeline_segments(single_q), ["echo 'a && b || c'"])

        double_q = 'echo "a && b || c"'
        self.assertEqual(_split_pipeline_segments(double_q), ['echo "a && b || c"'])

        escaped = r'echo "a \" && b"'
        self.assertEqual(len(_split_pipeline_segments(escaped)), 1)
        self.assertEqual(_split_pipeline_segments(""), [""])

    def test_tokenize_command(self):
        toks = _tokenize_command('git commit -m "feat: cordis v3"')
        self.assertEqual(toks, ["git", "commit", "-m", '"feat: cordis v3"'])
        win_path = r"C:\git\bin\git.exe status"
        self.assertEqual(_tokenize_command(win_path), [r"C:\git\bin\git.exe", "status"])
        unmatched = "git 'unmatched"
        self.assertEqual(_tokenize_command(unmatched), ["git", "'unmatched"])

    def test_strip_outer_quotes(self):
        self.assertEqual(_strip_outer_quotes('"hello"'), "hello")
        self.assertEqual(_strip_outer_quotes("'world'"), "world")
        self.assertEqual(_strip_outer_quotes("{block}"), "block")
        self.assertEqual(_strip_outer_quotes("plain"), "plain")

    def test_audit_embedded_python(self):
        d1 = _audit_embedded_python("import os; os.system('git commit -n')", "cmd")
        self.assertIsNotNone(d1)
        self.assertFalse(d1.allowed)
        self.assertEqual(d1.vector, "EMBEDDED_SUBVERSION")

        d2 = _audit_embedded_python("import subprocess; subprocess.run(['git', 'commit', '--no-verify'])", "cmd")
        self.assertIsNotNone(d2)
        self.assertFalse(d2.allowed)

        import base64
        b64_py = base64.b64encode(b"import os; os.system('git commit -n')").decode("ascii")
        d3 = _audit_embedded_python(f"import base64; exec(base64.b64decode('{b64_py}'))", "cmd")
        self.assertIsNotNone(d3)
        self.assertFalse(d3.allowed)

        d4 = _audit_embedded_python("import os; os.remove('.git/hooks/pre-commit')", "cmd")
        self.assertIsNotNone(d4)
        self.assertFalse(d4.allowed)

        d5 = _audit_embedded_python("git commit --no-verify invalid syntax {", "cmd")
        self.assertIsNotNone(d5)
        self.assertFalse(d5.allowed)

        d_clean = _audit_embedded_python("print('clean output')", "cmd")
        self.assertIsNone(d_clean)

    def test_audit_embedded_powershell_and_shell(self):
        dp1 = _audit_embedded_powershell("git commit -n", "ps")
        self.assertIsNotNone(dp1)
        self.assertFalse(dp1.allowed)

        dp_clean = _audit_embedded_powershell("Get-Date", "ps")
        self.assertIsNone(dp_clean)

        ds1 = _audit_embedded_shell("git commit --no-verify", "sh")
        self.assertIsNotNone(ds1)
        self.assertFalse(ds1.allowed)

        ds_clean = _audit_embedded_shell("echo hello", "sh")
        self.assertIsNone(ds_clean)

    def test_audit_single_command_and_pre_tool_firewall(self):
        # Empty
        self.assertTrue(_audit_single_command("").allowed)
        self.assertTrue(audit_pre_tool_use_command("").allowed)

        # Vector 1: no-verify / -n
        d_nv = audit_pre_tool_use_command("git commit --no-verify -m 'msg'")
        self.assertFalse(d_nv.allowed)
        self.assertEqual(d_nv.exit_code, 2)
        self.assertEqual(d_nv.vector, "NO_VERIFY")

        d_n = audit_pre_tool_use_command("git commit -n -m 'msg'")
        self.assertFalse(d_n.allowed)
        self.assertEqual(d_n.vector, "NO_VERIFY")

        # Vector 2: core.hooksPath
        d_hp = audit_pre_tool_use_command("git -c core.hooksPath=/dev/null commit -m 'msg'")
        self.assertFalse(d_hp.allowed)
        self.assertEqual(d_hp.vector, "HOOKS_PATH_OVERRIDE")

        # Vector 3: hooks tampering
        d_rm = audit_pre_tool_use_command("rm .git/hooks/pre-commit")
        self.assertFalse(d_rm.allowed)
        self.assertEqual(d_rm.vector, "HOOKS_TAMPERING")

        d_del = audit_pre_tool_use_command("del .git/hooks/pre-commit")
        self.assertFalse(d_del.allowed)
        self.assertEqual(d_del.vector, "HOOKS_TAMPERING")

        # Vector 4: stash keep index
        d_st1 = audit_pre_tool_use_command("git stash --keep-index")
        self.assertFalse(d_st1.allowed)
        self.assertEqual(d_st1.vector, "STASH_KEEP_INDEX")

        d_st2 = audit_pre_tool_use_command("git stash -k")
        self.assertFalse(d_st2.allowed)
        self.assertEqual(d_st2.vector, "STASH_KEEP_INDEX")

        # Vector 5: embedded
        d_py = audit_pre_tool_use_command("python -c \"import os; os.system('git commit -n')\"")
        self.assertFalse(d_py.allowed)
        self.assertEqual(d_py.vector, "EMBEDDED_SUBVERSION")

        d_ps = audit_pre_tool_use_command("powershell -c \"git commit -n\"")
        self.assertFalse(d_ps.allowed)
        self.assertEqual(d_ps.vector, "EMBEDDED_SUBVERSION")

        # Vector 6: pipe
        d_pipe = audit_pre_tool_use_command("echo 'git commit -n' | bash")
        self.assertFalse(d_pipe.allowed)

        # Legitimate commands
        self.assertTrue(audit_pre_tool_use_command("git commit -m 'valid message'").allowed)
        self.assertTrue(audit_pre_tool_use_command("git commit -am 'valid message'").allowed)
        self.assertTrue(audit_pre_tool_use_command("git status").allowed)
        self.assertTrue(audit_pre_tool_use_command("python -m unittest discover").allowed)

    def test_compute_digest_fallback(self):
        d_empty = _compute_digest_fallback({}, 1.0)
        self.assertEqual(len(d_empty), 16)
        self.assertEqual(d_empty, "3e4ef1b4a9c485fe")

        anchors = {"file.py::func": "¶file.py#1234567890abcdef"}
        d_val = _compute_digest_fallback(anchors, 1.0)
        self.assertEqual(len(d_val), 16)
        self.assertNotEqual(d_empty, d_val)

    def test_install_harness_hooks_and_run_stop_hook(self):
        with tempfile.TemporaryDirectory() as td:
            installed = install_harness_hooks(repo_dir=td, targets=["git", "claude"])
            self.assertEqual(len(installed), 2)
            self.assertTrue(Path(td, ".git", "hooks", "pre-commit").is_file())
            self.assertTrue(Path(td, ".claude", "settings.local.json").is_file())

            # Stop hook on empty clean dir -> returns 0
            code = run_stop_hook_prosecutor(repo_dir=td)
            self.assertEqual(code, 0)


class TestChallengerTypeScriptStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/ts_gate.py."""

    def test_is_regex_start_scenarios(self):
        self.assertTrue(_is_regex_start("/abc/", 0))
        self.assertTrue(_is_regex_start("return /abc/", 7))
        self.assertTrue(_is_regex_start("x = /abc/", 4))
        self.assertTrue(_is_regex_start("( /abc/", 2))
        self.assertFalse(_is_regex_start("a / b", 2))
        self.assertFalse(_is_regex_start("x++ / y", 4))
        self.assertTrue(_is_regex_start("x+++ /abc/", 5))

    def test_mask_ts_code_and_strip_comments(self):
        code = (
            "// line comment\n"
            "const x = 'str1'; /* block */\n"
            "const y = `template ${foo} end`;\n"
        )
        masked = mask_ts_code(code, mask_strings=True)
        self.assertEqual(len(masked), len(code))
        self.assertNotIn("line comment", masked)
        self.assertNotIn("str1", masked)
        self.assertNotIn("block", masked)
        self.assertIn("foo", masked)

        stripped = strip_ts_comments(code)
        self.assertNotIn("line comment", stripped)
        self.assertNotIn("block", stripped)
        self.assertIn("const x", stripped)

    def test_matching_brace_and_paren(self):
        code1 = "{ a { b } c }"
        self.assertEqual(_find_matching_brace(code1, 0), len(code1) - 1)
        self.assertEqual(_find_matching_brace("{ unclosed", 0), len("{ unclosed") - 1)

        code2 = "( a ( b ) c )"
        self.assertEqual(_find_matching_paren(code2, 0), len(code2) - 1)
        self.assertEqual(_find_matching_paren("( unclosed", 0), -1)

    def test_find_toplevel_relational_op_and_signature(self):
        res1 = _find_toplevel_relational_op("a === b")
        self.assertIsNotNone(res1)
        self.assertEqual(res1[0], "===")
        self.assertEqual(res1[1], "a")
        self.assertEqual(res1[2], "b")

        res2 = _find_toplevel_relational_op("a !== b")
        self.assertIsNotNone(res2)
        self.assertEqual(res2[0], "!==")

        res3 = _find_toplevel_relational_op("a <= b")
        self.assertIsNotNone(res3)
        self.assertEqual(res3[0], "<=")

        res4 = _find_toplevel_relational_op("foo(a, b)")
        self.assertIsNone(res4)

        sig = _extract_signature("name: string, age: number")
        self.assertEqual(sig, "(name, age)")

    def test_index_ts_ast_anchors_and_dict(self):
        ts_code = (
            "export function add(a: number, b: number): number {\n"
            "    return a + b;\n"
            "}\n"
            "export const multiply = (x: number, y: number): number => {\n"
            "    return x * y;\n"
            "};\n"
            "export class Calc {\n"
            "    divide(p: number, q: number): number {\n"
            "        return p / q;\n"
            "    }\n"
            "}\n"
        )
        anchors = index_ts_ast_anchors(ts_code, "math.ts")
        self.assertIn("add", anchors)
        self.assertIn("multiply", anchors)
        self.assertIn("Calc.divide", anchors)

        a_add = anchors["add"]
        self.assertEqual(a_add.identifier, "add")
        self.assertTrue(a_add.tag.startswith("¶math.ts#"))
        self.assertTrue(len(a_add.hash_tag) == 16)
        self.assertIn(a_add.tag, anchors)

    def test_is_boundary_mock(self):
        self.assertTrue(_is_boundary_mock("axios"))
        self.assertTrue(_is_boundary_mock("fs"))
        self.assertFalse(_is_boundary_mock("my_internal_module"))

    def test_audit_ts_test_tampering(self):
        old_test = "test('calc', () => { expect(add(1, 2)).toBe(3); });"
        new_test = (
            "test('calc', () => {\n"
            "    expect(true).toBe(true);\n"
            "    expect(add(1, 2)).toBeDefined();\n"
            "    vi.mock('./calc');\n"
            "});\n"
            "it.skip('disabled test', () => {});\n"
        )
        rep = audit_ts_test_tampering(old_test, new_test)
        self.assertFalse(rep.passed)
        self.assertTrue(len(rep.violations) >= 1)
        self.assertEqual(rep.total_mocks, 1)

    def test_generate_ts_mutants(self):
        ts_code = (
            "function compare(a: number, b: number): boolean {\n"
            "    if (a === b && a <= 10) {\n"
            "        return true;\n"
            "    }\n"
            "    return false;\n"
            "}\n"
        )
        mutants = generate_ts_mutants(ts_code, max_mutants=10)
        self.assertTrue(len(mutants) > 0)
        descs = [d for d, _, _ in mutants]
        self.assertTrue(any("===" in d or "<=" in d or "&&" in d or "return" in d for d in descs))


class TestChallengerFuzzerStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/fuzzer.py."""

    def test_inspect_code_constants(self):
        def sample():
            a = 123
            b = 4.56
            c = "harvest_me"
            d = b"bytes_val"
            e = True
            f = "a" * 100
            return a

        ints, floats, strings, bts = set(), set(), set(), set()
        _inspect_code_constants(sample.__code__, ints, floats, strings, bts)
        self.assertIn(123, ints)
        self.assertIn(4.56, floats)
        self.assertIn("harvest_me", strings)
        self.assertIn(b"bytes_val", bts)
        self.assertNotIn("a" * 100, strings)

    def test_harvest_ast_constants_chunk_and_types(self):
        def chunk_fn():
            CHUNK_SIZE = 1024
            RATE = 2.5
            TAG = "worker"
            RAW = b"ping"
            return CHUNK_SIZE

        class CallableObj:
            def __call__(self):
                VAL = 5555
                return VAL

        class TypeObj:
            def __init__(self):
                INIT_VAL = 7777

        pool = harvest_ast_constants([chunk_fn, CallableObj(), TypeObj])
        self.assertIn("int", pool)
        self.assertIn(1024, pool["int"])
        self.assertIn(1023, pool["int"])
        self.assertIn(1025, pool["int"])
        self.assertIn(5555, pool["int"])
        self.assertIn(7777, pool["int"])
        self.assertIn(2.5, pool["float"])
        self.assertIn(2.51, pool["float"])
        self.assertIn("worker", pool["str"])
        self.assertIn("worker_mut", pool["str"])
        self.assertIn(b"ping", pool["bytes"])
        self.assertIn(b"ping_mut", pool["bytes"])

    def test_generate_adversarial_values_for_type(self):
        vals_int = _generate_adversarial_values_for_type(int, count=10, harvested={"int": [999]})
        self.assertIn(999, vals_int)
        self.assertIn(0, vals_int)

        vals_str = _generate_adversarial_values_for_type(str, count=10, harvested={"str": ["custom"]})
        self.assertIn("custom", vals_str)
        self.assertIn("", vals_str)

        vals_bytes = _generate_adversarial_values_for_type(bytes, count=10, harvested={"bytes": [b"custom"]})
        self.assertIn(b"custom", vals_bytes)
        self.assertIn(b"", vals_bytes)

        vals_list = _generate_adversarial_values_for_type(list, count=10)
        self.assertIn([], vals_list)

        vals_dict = _generate_adversarial_values_for_type(dict, count=10)
        self.assertIn({}, vals_dict)

        vals_set = _generate_adversarial_values_for_type(set, count=10)
        self.assertIn(set(), vals_set)

        vals_tuple = _generate_adversarial_values_for_type(tuple, count=10)
        self.assertIn((), vals_tuple)

        vals_float = _generate_adversarial_values_for_type(float, count=10, harvested={"float": [3.14]})
        self.assertIn(3.14, vals_float)
        self.assertTrue(any(math.isnan(v) for v in vals_float if isinstance(v, float)))

        vals_def = _generate_adversarial_values_for_type(object, count=5)
        self.assertTrue(len(vals_def) >= 5)

    def test_load_repo_function_pair(self):
        f_old, f_new = load_repo_function_pair(".", "cordis/fuzzer.py", "__init__")
        self.assertIsNone(f_old)
        self.assertIsNone(f_new)

        f_old2, f_new2 = load_repo_function_pair(".", "cordis/fuzzer.py", "_deep_equals")
        self.assertTrue(callable(f_new2))
        self.assertEqual(f_new2.__name__, "_deep_equals")

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "test.v2.py").write_text("def v2_fn():\n    return 333\n", encoding="utf-8")
            f_old3, f_new3 = load_repo_function_pair(td, "test.v2.py", "v2_fn")
            self.assertTrue(callable(f_new3))
            self.assertEqual(f_new3(), 333)

    def test_deep_equals_all_scenarios(self):
        self.assertTrue(_deep_equals(float("nan"), float("nan")))
        self.assertTrue(_deep_equals(1.0, 1.000000000001))
        self.assertTrue(_deep_equals([1, 2, 3], [1, 2, 3]))
        self.assertTrue(_deep_equals({"a": 1, "b": 2}, {"b": 2, "a": 1}))
        self.assertTrue(_deep_equals({1, 2, 3}, {3, 2, 1}))
        self.assertFalse(_deep_equals([1, 2], (1, 2)))
        self.assertFalse(_deep_equals(10, 20))
        self.assertFalse(_deep_equals({"a": 1}, {"a": 2}))

    def test_outcomes_match(self):
        m1, r1 = _outcomes_match(42, None, 42, None)
        self.assertTrue(m1)
        self.assertEqual(r1, "Exact match")

        m2, r2 = _outcomes_match(None, ValueError("x"), None, ValueError("y"))
        self.assertTrue(m2)
        self.assertEqual(r2, "Both raised same exception")

        m3, _ = _outcomes_match(42, None, None, ValueError("err"))
        self.assertFalse(m3)

        m4, _ = _outcomes_match(None, ValueError("err"), None, TypeError("err"))
        self.assertFalse(m4)

        m5, _ = _outcomes_match(1.5, None, 2.5, None)
        self.assertFalse(m5)

    def test_run_differential_fuzz_gate(self):
        def ref(x: int) -> int:
            return x * 2

        def cand_good(x: int) -> int:
            return x * 2

        def cand_bad(x: int) -> int:
            if x == 10:
                return 999
            return x * 2

        rep_pass = run_differential_fuzz_gate(ref, cand_good, num_samples=30)
        self.assertTrue(rep_pass.passed)
        self.assertEqual(len(rep_pass.counterexamples), 0)

        rep_fail = run_differential_fuzz_gate(ref, cand_bad, num_samples=30)
        self.assertFalse(rep_fail.passed)
        self.assertTrue(len(rep_fail.counterexamples) > 0)

        # Arity 0
        def ref0() -> int:
            return 42
        def cand0() -> int:
            return 42
        rep_0 = run_differential_fuzz_gate(ref0, cand0, num_samples=5)
        self.assertTrue(rep_0.passed)

        # Arity 2 with closure sentinel default to kill arity inversion mutants
        sentinel = object()
        def ref2(a: int, b: int = sentinel) -> int:
            if b is sentinel:
                return a + 1
            return a + b
        def cand2(a: int, b: int = sentinel) -> int:
            if b is sentinel:
                return a + 2
            return a + b
        rep_2 = run_differential_fuzz_gate(ref2, cand2, num_samples=20)
        self.assertTrue(rep_2.passed)

    def test_mann_whitney_u_one_sided(self):
        u0, p0 = mann_whitney_u_one_sided([], [])
        self.assertEqual((u0, p0), (0.0, 1.0))

        baseline = [100.0, 102.0, 105.0, 101.0, 103.0] * 5
        candidate = [50.0, 52.0, 49.0, 51.0, 50.0] * 5
        u1, p1 = mann_whitney_u_one_sided(baseline, candidate)
        self.assertTrue(p1 < 0.05)

        u2, p2 = mann_whitney_u_one_sided(candidate, baseline)
        self.assertTrue(p2 > 0.5)

    def test_run_statistical_benchmark_gate(self):
        def b_fn():
            sum(range(500))

        def c_fn():
            sum(range(500))

        rep = run_statistical_benchmark_gate(
            b_fn, c_fn, rounds=6, iterations_per_round=20, max_regression_pct=50.0
        )
        self.assertEqual(type(rep).__name__, "BenchmarkGateReport")
        self.assertEqual(rep.rounds, 6)
        self.assertTrue(rep.baseline_median_us > 0)
        self.assertTrue(rep.candidate_median_us > 0)
        self.assertTrue(rep.passed)

        # Require speedup with faster candidate
        rep_speedup = run_statistical_benchmark_gate(
            lambda: sum(range(5000)),
            lambda: sum(range(10)),
            rounds=8,
            iterations_per_round=20,
            require_speedup=True,
        )
        self.assertTrue(rep_speedup.passed)
        self.assertIn("Speedup", rep_speedup.note)

        # Require speedup with slower candidate
        rep_no_speedup = run_statistical_benchmark_gate(
            lambda: sum(range(10)),
            lambda: sum(range(5000)),
            rounds=8,
            iterations_per_round=20,
            require_speedup=True,
        )
        self.assertFalse(rep_no_speedup.passed)


class TestChallengerForgeGuardStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/forge_guard.py."""

    def test_is_bot_identity(self):
        self.assertTrue(is_bot_identity("github-actions[bot]"))
        self.assertTrue(is_bot_identity("dependabot"))
        self.assertTrue(is_bot_identity("coderabbit"))
        self.assertTrue(is_bot_identity("antigravity-agent"))
        self.assertTrue(is_bot_identity("devin"))
        self.assertTrue(is_bot_identity("user", "bot@company.com"))
        self.assertTrue(is_bot_identity("user", "actions@github.com"))
        self.assertTrue(is_bot_identity("user", "123+name@users.noreply.github.com"))
        self.assertFalse(is_bot_identity("Alice Smith", "alice@company.com"))
        self.assertFalse(is_bot_identity("", ""))

    def test_inspect_git_actor(self):
        actor = inspect_git_actor(repo_dir=".", ref="HEAD")
        self.assertIsInstance(actor, GitActorInfo)
        self.assertNotEqual(actor.author_name, "unknown")
        self.assertTrue(actor.author_name)
        self.assertTrue(actor.commit_message)

        actor_err = inspect_git_actor(repo_dir=".", ref="non_existent_ref_99999")
        self.assertIsInstance(actor_err, GitActorInfo)
        self.assertEqual(actor_err.author_name, "unknown")
        self.assertEqual(actor_err.author_email, "unknown@unknown.com")
        self.assertFalse(actor_err.is_bot)

    def test_audit_forge_guard_and_current_environment(self):
        bot_actor = GitActorInfo(
            author_name="dependabot[bot]",
            author_email="dependabot@github.com",
            committer_name="dependabot[bot]",
            committer_email="dependabot@github.com",
            is_bot=True,
        )
        rep_bot = audit_forge_guard(actor_info=bot_actor)
        self.assertTrue(rep_bot.is_bot_authored)

        env_rep = audit_current_environment(repo_dir=".")
        self.assertIsInstance(env_rep, ForgeGuardReport)

        # Self approval
        rep_self = audit_forge_guard(pr_author="alice", reviewer="alice", review_state="APPROVED")
        self.assertFalse(rep_self.passed)
        self.assertTrue(rep_self.is_self_approved)
        self.assertTrue(any("SELF_APPROVAL" in v for v in rep_self.violations))

        # Bot collusion
        rep_col = audit_forge_guard(pr_author="dependabot[bot]", reviewer="coderabbit[bot]", review_state="APPROVED")
        self.assertFalse(rep_col.passed)
        self.assertTrue(any("BOT_COLLUSION" in v for v in rep_col.violations))

        # Single token auto merge
        rep_merge = audit_forge_guard(pr_author="dependabot[bot]", auto_merge_requested=True)
        self.assertFalse(rep_merge.passed)
        self.assertTrue(any("SINGLE_TOKEN_AUTO_MERGE" in v for v in rep_merge.violations))

        # GitHub actor self approval
        env_gh = {"GITHUB_ACTOR": "dependabot[bot]", "GITHUB_EVENT_NAME": "pull_request_review"}
        rep_gh = audit_forge_guard(env=env_gh, pr_author="dependabot[bot]", reviewer="human_reviewer", review_state="APPROVED")
        self.assertFalse(rep_gh.passed)
        self.assertTrue(any("GITHUB_ACTOR_SELF_APPROVAL" in v for v in rep_gh.violations))
        self.assertTrue(len(rep_gh.warnings) > 0)

        # Clean review passes
        rep_clean = audit_forge_guard(pr_author="alice", reviewer="bob", review_state="APPROVED")
        self.assertTrue(rep_clean.passed)
        self.assertEqual(len(rep_clean.violations), 0)
        self.assertFalse(rep_clean.is_self_approved)

    def test_compute_diff_attestation_digest_and_verify_trailer(self):
        d_empty = compute_diff_attestation_digest({}, 1.0)
        self.assertEqual(len(d_empty), 16)
        self.assertEqual(d_empty, "3e4ef1b4a9c485fe")

        anchors = {"main.py::calc": "¶main.py#1122334455667788"}
        d_val = compute_diff_attestation_digest(anchors, 1.0)
        self.assertEqual(len(d_val), 16)
        self.assertEqual(d_val, "f54f9bfe7d568291")
        self.assertNotEqual(d_empty, d_val)

        msg_with_sym = f"feat: ship feature\n\nCordis-Attestation: ¶{d_val}\n"
        self.assertTrue(verify_commit_attestation_trailer(msg_with_sym, d_val))

        msg_plain = f"feat: ship feature\n\nCordis-Attestation: {d_val}\n"
        self.assertTrue(verify_commit_attestation_trailer(msg_plain, d_val))

        msg_bad = "feat: ship feature\n\nCordis-Attestation: 0000000000000000\n"
        self.assertFalse(verify_commit_attestation_trailer(msg_bad, d_val))
        self.assertFalse(verify_commit_attestation_trailer("", d_val))
        self.assertFalse(verify_commit_attestation_trailer(msg_plain, ""))
        self.assertFalse(verify_commit_attestation_trailer(msg_plain, None))
        self.assertFalse(verify_commit_attestation_trailer(None, d_val))


class TestChallengerMutatorDeepStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/mutator.py."""

    def test_is_overload_stub(self):
        tree = ast.parse(
            "from typing import overload\n"
            "@overload\n"
            "def foo(x: int) -> int: ...\n"
            "def foo(x: int) -> int: return x\n"
            "@typing.overload\n"
            "def foo_attr(x: str) -> str: pass\n"
            "def foo_ellipsis(x: int) -> int: ...\n"
            "@my_decorator\n"
            "def foo_decorated(x):\n"
            "    x = 1\n"
            "    return x\n"
            "def foo_docstring(x):\n"
            "    '''Docstring'''\n"
            "    return x\n"
            "def foo_constant_expr(x):\n"
            "    123\n"
            "def foo_pass(x):\n"
            "    pass\n"
            "def foo_ellipsis_and_code(x):\n"
            "    ...\n"
            "    return x\n"
        )
        self.assertTrue(_is_overload_stub(tree.body[1]))
        self.assertFalse(_is_overload_stub(tree.body[2]))
        self.assertTrue(_is_overload_stub(tree.body[3]))
        self.assertTrue(_is_overload_stub(tree.body[4]))
        self.assertFalse(_is_overload_stub(tree.body[5]))
        self.assertFalse(_is_overload_stub(tree.body[6]))
        self.assertFalse(_is_overload_stub(tree.body[7]))
        self.assertFalse(_is_overload_stub(tree.body[8]))
        self.assertFalse(_is_overload_stub(tree.body[9]))

    def test_find_target_function_node(self):
        src = (
            "from typing import overload\n"
            "@overload\n"
            "def target_fn(x: int) -> int: ...\n"
            "def target_fn(x: int) -> int:\n"
            "    return x * 2\n"
            "class MyClass:\n"
            "    def method_fn(self):\n"
            "        return 42\n"
            "def conflict_fn(): return 'top'\n"
            "class StubCls:\n"
            "    @overload\n"
            "    def conflict_fn(self): ...\n"
            "@overload\n"
            "def only_top_stub(x: int) -> int: ...\n"
        )
        tree = ast.parse(src)
        fn_node = _find_target_function_node(tree, "target_fn")
        self.assertIsNotNone(fn_node)
        self.assertFalse(_is_overload_stub(fn_node))

        m_node = _find_target_function_node(tree, "MyClass.method_fn")
        self.assertIsNotNone(m_node)
        self.assertEqual(m_node.name, "method_fn")

        # Stub resolution in class when top-level implementation exists
        cls_stub = _find_target_function_node(tree, "StubCls.conflict_fn")
        self.assertIsNotNone(cls_stub)
        self.assertTrue(_is_overload_stub(cls_stub))

        # Only stub at top-level
        top_stub = _find_target_function_node(tree, "only_top_stub")
        self.assertIsNotNone(top_stub)
        self.assertTrue(isinstance(top_stub, (ast.FunctionDef, ast.AsyncFunctionDef)))
        self.assertTrue(_is_overload_stub(top_stub))

        # Non-existent
        self.assertIsNone(_find_target_function_node(tree, "StubCls.nonexistent"))
        self.assertIsNone(_find_target_function_node(tree, "completely_missing"))

    def test_is_pure_expression_and_expr_to_str(self):
        tree = ast.parse("x; self.attr; func(); func().attr")
        expr_name = tree.body[0].value
        expr_attr = tree.body[1].value
        expr_call = tree.body[2].value
        expr_impure_attr = tree.body[3].value

        self.assertIs(_is_pure_expression(expr_name), True)
        self.assertIs(_is_pure_expression(expr_attr), True)
        self.assertIs(_is_pure_expression(expr_call), False)
        self.assertIs(_is_pure_expression(expr_impure_attr), False)
        self.assertEqual(_expr_to_str(expr_name), "x")
        self.assertEqual(_expr_to_str(expr_attr), "self.attr")
        self.assertEqual(_expr_to_str(None), "")
        self.assertEqual(_expr_to_str(ast.BinOp(left=ast.Name(id="a"), op=None, right=ast.Name(id="b"))), "")

    def test_is_terminal_statement_and_block(self):
        t1 = ast.parse("return 1").body[0]
        t2 = ast.parse("raise ValueError()").body[0]
        t3 = ast.parse("break").body[0]
        t4 = ast.parse("continue").body[0]
        t5 = ast.parse("x = 1").body[0]

        self.assertTrue(_is_terminal_statement(t1))
        self.assertTrue(_is_terminal_statement(t2))
        self.assertTrue(_is_terminal_statement(t3))
        self.assertTrue(_is_terminal_statement(t4))
        self.assertFalse(_is_terminal_statement(t5))

        self.assertTrue(_is_terminal_block([t5, t1]))
        self.assertFalse(_is_terminal_block([t1, t5]))
        self.assertFalse(_is_terminal_block([]))

    def test_statement_modifies_var(self):
        s1 = ast.parse("x = 10").body[0]
        s2 = ast.parse("x += 5").body[0]
        s3 = ast.parse("y = 10").body[0]

        self.assertTrue(_statement_modifies_var(s1, "x"))
        self.assertTrue(_statement_modifies_var(s2, "x"))
        self.assertFalse(_statement_modifies_var(s3, "x"))

    def test_extract_and_comparisons(self):
        c1 = ast.parse("x < 10").body[0].value
        c_and = ast.parse("x < 10 and y > 20 and z == 30").body[0].value
        c_or = ast.parse("x < 10 or y > 20").body[0].value
        c_other = ast.parse("x").body[0].value

        r1 = _extract_and_comparisons(c1)
        r_and = _extract_and_comparisons(c_and)
        r_or = _extract_and_comparisons(c_or)
        r_other = _extract_and_comparisons(c_other)

        self.assertEqual(len(r1), 1)
        self.assertEqual(len(r_and), 3)
        self.assertEqual(len(r_or), 0)
        self.assertEqual(len(r_other), 0)

    def test_is_boundary_constrained(self):
        code1 = (
            "def check(x):\n"
            "    if x <= 0:\n"
            "        return\n"
            "    if x > 0:\n"
            "        return True\n"
        )
        t1 = ast.parse(code1)
        cmps1 = [n for n in ast.walk(t1) if isinstance(n, ast.Compare)]
        self.assertTrue(_is_boundary_constrained(t1, cmps1[1], "compare_gt_gte"))
        self.assertFalse(_is_boundary_constrained(t1, cmps1[0], "compare_gt_gte"))

        # Reassigned in between
        code_reassign = (
            "def check(x):\n"
            "    if x <= 0:\n"
            "        return\n"
            "    x = 10\n"
            "    if x > 0:\n"
            "        return True\n"
        )
        t_re = ast.parse(code_reassign)
        cmps_re = [n for n in ast.walk(t_re) if isinstance(n, ast.Compare)]
        self.assertFalse(_is_boundary_constrained(t_re, cmps_re[1], "compare_gt_gte"))

        # Multi-comparator or impure
        t_multi = ast.parse("1 < x < 10")
        cmp_multi = t_multi.body[0].value
        self.assertFalse(_is_boundary_constrained(t_multi, cmp_multi, "compare_gt_gte"))

        t_impure = ast.parse("foo() > 10")
        cmp_impure = t_impure.body[0].value
        self.assertFalse(_is_boundary_constrained(t_impure, cmp_impure, "compare_gt_gte"))

        # lt_lte branch
        code_lt = (
            "def check_lt(x):\n"
            "    if x >= 10:\n"
            "        return\n"
            "    if x < 10:\n"
            "        return True\n"
        )
        t_lt = ast.parse(code_lt)
        cmps_lt = [n for n in ast.walk(t_lt) if isinstance(n, ast.Compare)]
        self.assertTrue(_is_boundary_constrained(t_lt, cmps_lt[1], "compare_lt_lte"))

    def test_collect_arid_ast_nodes_and_tie_equivalent(self):
        code = "def worker(a, b):\n    return a if a < b else b\n"
        tree = ast.parse(code)
        arid = _collect_arid_ast_nodes(tree)
        self.assertIsInstance(arid, set)

        code_comprehensive = (
            "if __name__ == '__main__':\n"
            "    print('main')\n"
            "if TYPE_CHECKING:\n"
            "    from typing import Any\n"
            "if x > 0:\n"
            "    y = 1\n"
            "logging.info('test')\n"
            "def worker(a):\n"
            "    return a\n"
        )
        t_comp = ast.parse(code_comprehensive)
        arid_comp = _collect_arid_ast_nodes(t_comp)
        if_main = t_comp.body[0]
        if_type = t_comp.body[1]
        if_regular = t_comp.body[2]
        fn_worker = t_comp.body[4]

        self.assertIn(if_main, arid_comp)
        self.assertIn(if_type, arid_comp)
        self.assertNotIn(if_regular, arid_comp)
        self.assertNotIn(fn_worker, arid_comp)

        cmp_node = next(n for n in ast.walk(tree) if isinstance(n, ast.Compare))
        is_tie = _is_tie_boundary_equivalent(tree, cmp_node)
        self.assertTrue(is_tie)

        code_if = "def worker(a, b):\n    if a < b:\n        return a\n    else:\n        return b\n"
        t_if = ast.parse(code_if)
        cmp_if = next(n for n in ast.walk(t_if) if isinstance(n, ast.Compare))
        self.assertTrue(_is_tie_boundary_equivalent(t_if, cmp_if))

        code_non_tie = "def worker(a, b):\n    if a < b:\n        return a + 1\n    else:\n        return b\n"
        t_non_tie = ast.parse(code_non_tie)
        cmp_non_tie = next(n for n in ast.walk(t_non_tie) if isinstance(n, ast.Compare))
        self.assertFalse(_is_tie_boundary_equivalent(t_non_tie, cmp_non_tie))

        code_eq = "def worker(a, b):\n    if a == b:\n        return a\n    else:\n        return b\n"
        t_eq = ast.parse(code_eq)
        cmp_eq = next(n for n in ast.walk(t_eq) if isinstance(n, ast.Compare))
        self.assertFalse(_is_tie_boundary_equivalent(t_eq, cmp_eq))

        t_multi = ast.parse("1 < a < b")
        self.assertFalse(_is_tie_boundary_equivalent(t_multi, t_multi.body[0].value))

        # Asymmetric compare node where len(ops) != 1 but len(comparators) == 1
        c_asym = ast.Compare(
            left=ast.Name(id="a", ctx=ast.Load()),
            ops=[ast.Lt(), ast.Gt()],
            comparators=[ast.Name(id="b", ctx=ast.Load())],
        )
        t_asym = ast.parse("def f(a, b): return a if True else b")
        t_asym.body[0].body[0].value.test = c_asym
        self.assertFalse(_is_tie_boundary_equivalent(t_asym, c_asym))

    def test_inject_coverage_probe(self):
        code = "def target():\n    return 42\n"
        injected = inject_coverage_probe(code, "target")
        self.assertIsNotNone(injected)
        self.assertIn("CORDIS_COVERAGE_PROBE", injected)

        # With docstring
        code_doc = "def target():\n    '''My docstring'''\n    return 42\n"
        inj_doc = inject_coverage_probe(code_doc, "target")
        self.assertIsNotNone(inj_doc)
        self.assertIn("CORDIS_COVERAGE_PROBE", inj_doc)
        self.assertIn("My docstring", inj_doc)

        # Missing target
        self.assertIsNone(inject_coverage_probe(code, "missing"))

        # Syntax error
        self.assertIsNone(inject_coverage_probe("def broken(", "target"))

    def test_run_in_memory_mutation_gate(self):
        src = "def add(a, b):\n    return a + b\n"
        test = "from add import add\ndef test_add():\n    assert add(1, 2) == 3\n"
        rep = run_in_memory_mutation_gate(src, test, target_function="add", max_mutants=2)
        self.assertIsInstance(rep, MutationGateReport)
        self.assertTrue(rep.total_mutants > 0)
        self.assertTrue(rep.killed_mutants > 0)
        self.assertTrue(rep.passed)
        self.assertEqual(rep.survived_mutants, 0)
        self.assertAlmostEqual(rep.kill_rate, 1.0)

        # Hollow test that survives
        test_hollow = "def test_add(): pass\n"
        rep_hollow = run_in_memory_mutation_gate(src, test_hollow, target_function="add", max_mutants=2)
        self.assertFalse(rep_hollow.passed)
        self.assertEqual(rep_hollow.survived_mutants, rep_hollow.total_mutants)

        # Empty mutants
        rep_empty = run_in_memory_mutation_gate("x = 1", "pass", max_mutants=0)
        self.assertTrue(rep_empty.passed)
        self.assertEqual(rep_empty.total_mutants, 0)

        # Wrapper tautology detection
        test_taut = "def test_add(): assert add(1, 2) == add(1, 2)\n"
        rep_taut = run_in_memory_mutation_gate(src, test_taut, target_function="add", max_mutants=2)
        self.assertTrue(rep_taut.wrapper_tautology_detected)

    def test_generate_ast_mutants_canary_flag(self):
        src = "def calc(x):\n    return x + 1\n"
        # 1. Default include_canary=False
        muts_no_canary = generate_ast_mutants(src, max_mutants=2)
        self.assertFalse(any("IEEE-754 NaN canary" in m[0] for m in muts_no_canary))

        # 2. include_canary=True with max_mutants=2
        muts_canary = generate_ast_mutants(src, include_canary=True, max_mutants=2)
        self.assertTrue(any("IEEE-754 NaN canary" in m[0] for m in muts_canary))

        # 3. max_mutants limit enforced
        self.assertEqual(len(muts_no_canary), 2)
        self.assertEqual(len(muts_canary), 2)

        # 4. Invariant: canary swap when return_nan_canary occurs after max_mutants
        src3 = (
            "def test_fn(x, y, a):\n"
            "    if x == 1:\n"
            "        pass\n"
            "    if y == 2:\n"
            "        pass\n"
            "    return a\n"
        )
        m_swap = generate_ast_mutants(src3, include_canary=True, max_mutants=3)
        self.assertTrue(any("canary" in x[0] for x in m_swap))
        m_swap_no = generate_ast_mutants(src3, include_canary=False, max_mutants=3)
        self.assertFalse(any("canary" in x[0] for x in m_swap_no))

    def test_run_repo_mutation_gate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "my_math.py").write_text("def mul(a, b):\n    return a * b\n", encoding="utf-8")
            (root / "test_math.py").write_text("from my_math import mul\ndef test_mul():\n    assert mul(2, 3) == 6\n", encoding="utf-8")

            # 1. Successful run killing mutants
            rep = run_repo_mutation_gate(
                repo_root=root,
                source_rel_path="my_math.py",
                test_rel_path="test_math.py",
                target_function="mul",
                max_mutants=2,
            )
            self.assertTrue(rep.passed)
            self.assertEqual(rep.survived_mutants, 0)
            self.assertTrue(rep.target_executed)

            # 2. Non-existent source file returns empty report
            rep_none = run_repo_mutation_gate(
                repo_root=root,
                source_rel_path="missing.py",
                test_rel_path="test_math.py",
            )
            self.assertTrue(rep_none.passed)
            self.assertEqual(rep_none.total_mutants, 0)
            self.assertFalse(rep_none.target_executed)

            # 3. Crash recovery (.cordis.bak present)
            bak = root / "my_math.py.cordis.bak"
            bak.write_text("def mul(a, b):\n    return a * b\n", encoding="utf-8")
            (root / "my_math.py").write_text("corrupted", encoding="utf-8")
            rep_bak = run_repo_mutation_gate(
                repo_root=root,
                source_rel_path="my_math.py",
                test_rel_path="test_math.py",
                target_function="mul",
                max_mutants=1,
            )
            self.assertFalse(bak.exists())
            self.assertTrue(rep_bak.passed)


class TestChallengerASTGateStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/ast_gate.py."""

    def test_compute_node_hash_and_index_ast_anchors(self):
        code = (
            "def func1(x):\n"
            "    return x + 1\n\n"
            "async def async_fn(y):\n"
            "    return y * 2\n\n"
            "class MyCls:\n"
            "    def meth(self):\n"
            "        return 10\n"
        )
        h1 = compute_node_hash("test.py", "<module>", "FunctionDef", "func1", "(x)", "dump")
        self.assertEqual(len(h1), 16)
        self.assertEqual(h1, "a48d5bf6104d8435")

        anchors = index_ast_anchors(code, "test.py")
        self.assertIn("func1", anchors)
        self.assertIn("async_fn", anchors)
        self.assertIn("MyCls.meth", anchors)
        self.assertEqual(anchors["func1"].tag, "¶test.py#7c139436c780b147")
        self.assertEqual(anchors["func1"].hash_tag, "7c139436c780b147")
        self.assertEqual(anchors["func1"].lineno, 1)
        self.assertEqual(anchors["func1"].end_lineno, 2)
        self.assertEqual(anchors["func1"].signature, "(x)")

    def test_is_unittest_assert_call(self):
        c1 = ast.parse("self.assertEqual(a, b)").body[0].value
        c2 = ast.parse("self.assertTrue(x)").body[0].value
        c3 = ast.parse("self.other_call(x)").body[0].value

        self.assertTrue(_is_unittest_assert_call(c1))
        self.assertTrue(_is_unittest_assert_call(c2))
        self.assertFalse(_is_unittest_assert_call(c3))

    def test_is_tautological_assert(self):
        a1 = ast.parse("assert True").body[0]
        a2 = ast.parse("assert 1 == 1").body[0]
        a3 = ast.parse("assert x == x").body[0]
        a4 = ast.parse("assert a == b").body[0]
        c1 = ast.parse("self.assertTrue(True)").body[0].value
        c2 = ast.parse("self.assertEqual(x, x)").body[0].value
        c3 = ast.parse("self.assertEqual(a, b)").body[0].value
        c4 = ast.parse("self.assertTrue(x)").body[0].value
        non_assert = ast.parse("x = 1").body[0]

        self.assertIsNotNone(_is_tautological_assert(a1))
        self.assertIsNotNone(_is_tautological_assert(a2))
        self.assertIsNotNone(_is_tautological_assert(a3))
        self.assertIsNone(_is_tautological_assert(a4))
        self.assertIsNotNone(_is_tautological_assert(c1))
        self.assertIsNotNone(_is_tautological_assert(c2))
        self.assertIsNone(_is_tautological_assert(c3))
        self.assertIsNone(_is_tautological_assert(c4))
        self.assertIsNone(_is_tautological_assert(non_assert))

    def test_is_weak_not_none_assert(self):
        w1 = ast.parse("assert x is not None").body[0]
        w2 = ast.parse("assert x != None").body[0]
        w3 = ast.parse("self.assertIsNotNone(x)").body[0].value
        w4 = ast.parse("assert x == 42").body[0]
        w5 = ast.parse("assert x").body[0]
        w6 = ast.parse("assert 1 < x < 10").body[0]
        w7 = ast.parse("self.assertEqual(a, b)").body[0].value
        w8 = ast.parse("x = 1").body[0]

        self.assertTrue(_is_weak_not_none_assert(w1))
        self.assertTrue(_is_weak_not_none_assert(w2))
        self.assertTrue(_is_weak_not_none_assert(w3))
        self.assertFalse(_is_weak_not_none_assert(w4))
        self.assertFalse(_is_weak_not_none_assert(w5))
        self.assertFalse(_is_weak_not_none_assert(w6))
        self.assertFalse(_is_weak_not_none_assert(w7))
        self.assertFalse(_is_weak_not_none_assert(w8))

    def test_is_boundary_target(self):
        self.assertTrue(_is_boundary_target("requests"))
        self.assertTrue(_is_boundary_target("urllib"))
        self.assertFalse(_is_boundary_target("custom_internal"))

    def test_is_broad_exception_type(self):
        e1 = ast.parse("Exception").body[0].value
        e2 = ast.parse("BaseException").body[0].value
        e3 = ast.parse("ValueError").body[0].value

        self.assertTrue(_is_broad_exception_type(e1))
        self.assertTrue(_is_broad_exception_type(e2))
        self.assertFalse(_is_broad_exception_type(e3))

    def test_calculate_mock_to_assertion_ratio(self):
        # 1. Empty code
        r_empty = calculate_mock_to_assertion_ratio("")
        self.assertEqual(r_empty["total_assertions"], 0)
        self.assertEqual(r_empty["total_mocks"], 0)
        self.assertEqual(r_empty["mar"], 0.0)
        self.assertEqual(r_empty["risk_level"], "LOW")
        self.assertFalse(r_empty["is_high_risk"])

        # 2. Syntax error
        r_syntax = calculate_mock_to_assertion_ratio("def broken(")
        self.assertEqual(r_syntax["total_assertions"], 0)
        self.assertEqual(r_syntax["total_mocks"], 0)
        self.assertEqual(r_syntax["mar"], 0.0)

        # 3. Only assertions (Assert, Call, With pytest.raises, AsyncWith pytest.warns)
        code_asserts = (
            "async def test_all():\n"
            "    assert x == 1\n"
            "    assert_that(a)\n"
            "    with pytest.raises(ValueError):\n"
            "        pass\n"
            "    async with pytest.warns(UserWarning):\n"
            "        pass\n"
        )
        r_pure = calculate_mock_to_assertion_ratio(code_asserts)
        self.assertEqual(r_pure["total_assertions"], 4)
        self.assertEqual(r_pure["total_mocks"], 0)
        self.assertEqual(r_pure["mar"], 0.0)
        self.assertEqual(r_pure["risk_level"], "LOW")
        self.assertFalse(r_pure["is_high_risk"])

        # 4. Moderate MAR (1 mock, 5 assertions -> 1/5 = 0.20 -> MODERATE)
        code_mod = (
            "from unittest.mock import Mock\n"
            "def test_mod():\n"
            "    m = Mock()\n"
            "    assert 1 == 1\n"
            "    assert 2 == 2\n"
            "    assert 3 == 3\n"
            "    assert 4 == 4\n"
            "    assert 5 == 5\n"
        )
        r_mod = calculate_mock_to_assertion_ratio(code_mod)
        # 1 import mock + 1 Mock() = 2 mocks. Let's adjust so MAR is between 0.10 and 0.25
        # If total_assertions = 10, total_mocks = 2 -> mar = 0.20 -> MODERATE
        code_mod10 = (
            "import unittest.mock\n"
            "from unittest import mock\n"
            "def test_mod10():\n"
            "    assert 1\n"
            "    assert 2\n"
            "    assert 3\n"
            "    assert 4\n"
            "    assert 5\n"
            "    assert 6\n"
            "    assert 7\n"
            "    assert 8\n"
            "    assert 9\n"
            "    assert 10\n"
        )
        r_mod10 = calculate_mock_to_assertion_ratio(code_mod10)
        self.assertEqual(r_mod10["total_assertions"], 10)
        self.assertEqual(r_mod10["total_mocks"], 2)
        self.assertEqual(r_mod10["mar"], 0.2)
        self.assertEqual(r_mod10["risk_level"], "MODERATE")
        self.assertFalse(r_mod10["is_high_risk"])

        # 5. Boundary mock & High Risk
        code_high = (
            "@patch('requests.get')\n"
            "@patch.object(MyClass, 'method')\n"
            "def test_high():\n"
            "    with patch(target='urllib.request.urlopen'):\n"
            "        mocker.patch('boto3.client')\n"
            "        patch('os.environ', 'VAR')\n"
            "        patch(target=custom_attr)\n"
            "        patch(MyModule)\n"
            "    assert 1 == 1\n"
        )
        r_high = calculate_mock_to_assertion_ratio(code_high)
        self.assertEqual(r_high["total_assertions"], 1)
        self.assertTrue(r_high["is_high_risk"])
        self.assertEqual(r_high["risk_level"], "HIGH_RISK")
        self.assertTrue(r_high["boundary_mock_count"] >= 3)
        self.assertTrue(r_high["internal_mock_count"] >= 2)
        self.assertEqual(r_high["weighted_mar"], round(
            (1.0 * r_high["internal_mock_count"] + 0.25 * r_high["boundary_mock_count"]) / 1, 4
        ))

    def test_audit_test_tampering(self):
        # 1. Zero assert violations
        rep0 = audit_test_tampering("assert 1 == 1", "x = 1")
        self.assertFalse(rep0.passed)
        self.assertTrue(any("zero `assert`" in v for v in rep0.violations))
        self.assertTrue(any("decreased" in v for v in rep0.violations))

        # 2. Deleted assert count
        rep_drop = audit_test_tampering("assert 1\nassert 2", "assert 1")
        self.assertFalse(rep_drop.passed)
        self.assertTrue(any("decreased from 2 to 1" in v for v in rep_drop.violations))

        # 3. Weakened assertion to is not None
        rep_weak = audit_test_tampering("assert f(x) == 42", "assert f(x) is not None")
        self.assertFalse(rep_weak.passed)
        self.assertTrue(any("weakened" in v.lower() for v in rep_weak.violations))

        # 4. Deleted test function
        old_fn_code = "def test_a():\n    assert 1\ndef test_b():\n    assert 2"
        new_fn_code = "def test_a():\n    assert 1\n    assert 2"
        rep_del = audit_test_tampering(old_fn_code, new_fn_code)
        self.assertFalse(rep_del.passed)
        self.assertTrue(any("`test_b` was deleted" in v for v in rep_del.violations))

        # 5. Hollow newly added test function
        new_hollow = "def test_new():\n    assert x is not None"
        rep_hollow = audit_test_tampering("", new_hollow)
        self.assertFalse(rep_hollow.passed)
        self.assertTrue(any("is hollow" in v for v in rep_hollow.violations))

        # 6. Skip decorator and skip call
        code_skip = (
            "@pytest.mark.skip(reason='bypass')\n"
            "def test_skipped():\n"
            "    pytest.skip('skip call')\n"
            "    assert 1\n"
        )
        rep_skip = audit_test_tampering("", code_skip)
        self.assertFalse(rep_skip.passed)
        self.assertTrue(any("skip/xfail" in v for v in rep_skip.violations))
        self.assertTrue(any("Explicit `pytest.skip()`" in v for v in rep_skip.violations))

        # 7. Mocking target function
        code_tgt_mock = (
            "def test_tgt():\n"
            "    mock.patch('calc_tax')\n"
            "    assert 1\n"
        )
        rep_tgt = audit_test_tampering("", code_tgt_mock, target_function_names=["calc_tax"])
        self.assertFalse(rep_tgt.passed)
        self.assertTrue(any("mocks out target function `calc_tax`" in v for v in rep_tgt.violations))

        # 8. Exception swallowing pass
        code_swallow = (
            "def test_swallow():\n"
            "    try:\n"
            "        calc_tax(10)\n"
            "    except Exception:\n"
            "        pass\n"
            "    assert 1\n"
        )
        rep_swallow = audit_test_tampering("", code_swallow, target_function_names=["calc_tax"])
        self.assertFalse(rep_swallow.passed)
        self.assertTrue(any("swallows exceptions" in v for v in rep_swallow.violations))

        # 9. Direct alias tautology & Oracle-free call comparison
        code_alias = (
            "def test_alias():\n"
            "    a = calc_tax(10)\n"
            "    b = calc_tax(10)\n"
            "    assert a == b\n"
        )
        rep_alias = audit_test_tampering("", code_alias, target_function_names=["calc_tax"])
        self.assertFalse(rep_alias.passed)
        self.assertTrue(any("Direct alias tautology" in v for v in rep_alias.violations))

        # 10. Valid clean test update
        clean_old = "def test_valid():\n    assert calc_tax(10) == 1\n"
        clean_new = "def test_valid():\n    assert calc_tax(10) == 1\n    assert calc_tax(20) == 2\n"
        rep_clean = audit_test_tampering(clean_old, clean_new, target_function_names=["calc_tax"])
        self.assertTrue(rep_clean.passed)
        self.assertEqual(len(rep_clean.violations), 0)
        self.assertEqual(rep_clean.mar_risk_level, "LOW")


class TestChallengerPolicyScraperDeepStress(unittest.TestCase):
    """Rigorous invariant stress tests for cordis/policy_guard.py."""

    def test_discover_governance_files(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "CONTRIBUTING.md").write_text("rules", encoding="utf-8")
            (p / "README.md").write_text("info", encoding="utf-8")
            gh = p / ".github"
            gh.mkdir()
            (gh / "PULL_REQUEST_TEMPLATE.md").write_text("tmpl", encoding="utf-8")

            files = _discover_governance_files(p)
            self.assertTrue(len(files) >= 3)
            self.assertTrue(any("CONTRIBUTING.md" in str(f) for f in files))
            self.assertTrue(any("README.md" in str(f) for f in files))

    def test_audit_repository_policy_all_branches(self):
        rep_none = audit_repository_policy("non_existent_dir_12345")
        self.assertEqual(rep_none.status, "PERMITTED")
        self.assertFalse(rep_none.ai_banned)
        self.assertFalse(rep_none.issue_required)
        self.assertIn("does not exist", rep_none.advice)

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            rep_empty = audit_repository_policy(p)
            self.assertEqual(rep_empty.status, "PERMITTED")
            self.assertFalse(rep_empty.ai_banned)
            self.assertFalse(rep_empty.issue_required)

            # Anti-AI match
            (p / "CONTRIBUTING.md").write_text("Strictly no ai-generated pull requests allowed here.", encoding="utf-8")
            rep_ai = audit_repository_policy(p)
            self.assertEqual(rep_ai.status, "BLOCKED_POLICY")
            self.assertTrue(rep_ai.ai_banned)
            self.assertTrue(len(rep_ai.citations) > 0)
            self.assertIn("prohibits AI/LLM", rep_ai.advice)

            # Issue required match
            (p / "CONTRIBUTING.md").write_text("Welcome contributors!", encoding="utf-8")
            (p / "README.md").write_text("All pull requests must reference an existing issue first.", encoding="utf-8")
            rep_iss = audit_repository_policy(p)
            self.assertEqual(rep_iss.status, "ISSUE_REQUIRED")
            self.assertTrue(rep_iss.issue_required)
            self.assertFalse(rep_iss.ai_banned)
            self.assertIn("requires an existing issue", rep_iss.advice)

            # Hook tampering match
            (p / "README.md").write_text("Welcome!", encoding="utf-8")
            git_dir = p / ".git"
            git_dir.mkdir()
            (git_dir / "config").write_text("[core]\n\thookspath = /dev/null\n", encoding="utf-8")
            rep_tamper = audit_repository_policy(p)
            self.assertEqual(rep_tamper.status, "BLOCKED_POLICY")
            self.assertTrue(any("HOOK_TAMPERING" in c for c in rep_tamper.citations))
            self.assertIn("git hook tampering", rep_tamper.advice)

