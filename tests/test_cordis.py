"""Comprehensive test suite for Cordis 3-Gate Adversarial AI-PR Prosecutor.
Compatible with BOTH `python -m unittest discover -s tests -v` AND `pytest`!
100% Python standard library, zero external dependencies.
"""
from __future__ import annotations

import inspect
import io
import math
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cordis.ast_gate import (
    _is_tautological_assert,
    _is_unittest_assert_call,
    _is_weak_not_none_assert,
    audit_test_tampering,
    index_ast_anchors,
)
from cordis.benchmark_suite import format_benchmark_markdown_table, run_benchmark
from cordis.cli import format_github_prosecutor_comment, main, run_benchmark_cli, run_demo, run_verify_git
from cordis.forge_guard import audit_forge_guard, is_bot_identity
from cordis.fuzzer import (
    BenchmarkGateReport,
    DifferentialFuzzReport,
    _generate_adversarial_values_for_type,
    run_differential_fuzz_gate,
    run_statistical_benchmark_gate,
)
from cordis.git_diff import GitDiffReport, ModifiedFunction, extract_git_diff, is_test_file, parse_git_diff_text
from cordis.html_report import generate_html_report, save_html_report, save_markdown_report
from cordis.memory import EpisodicMemoryLedger
from cordis.mutator import generate_ast_mutants, run_in_memory_mutation_gate, run_repo_mutation_gate
from examples.fixproof_killer_demo import (
    BAD_AGENT_PATCH_SOURCE,
    GOOD_AGENT_TEST_SOURCE,
    REFERENCE_CORRECT_SOURCE,
)


class TestCordisProsecutor(unittest.TestCase):
    def test_64bit_ast_anchors_do_not_collide_on_identical_structure(self) -> None:
        code = """
def get_a(x):
    return x + 1

def get_b(x):
    return x + 1
"""
        anchors = index_ast_anchors(code, file_path="service.py")
        self.assertIn("get_a", anchors)
        self.assertIn("get_b", anchors)
        self.assertEqual(len(anchors["get_a"].hash_tag), 16)
        self.assertNotEqual(anchors["get_a"].hash_tag, anchors["get_b"].hash_tag)
        self.assertEqual(anchors["get_a"].tag, f"¶service.py#{anchors['get_a'].hash_tag}")

    def test_gate1_catches_weakened_asserts_mocks_and_skips(self) -> None:
        old_test = """
def test_calc():
    assert parse_discount_tier(0.0) == 0.0
    assert parse_discount_tier(200.0) == 0.15
"""
        tampered_test = """
import unittest
from unittest.mock import patch

@unittest.skip("flaky")
def test_calc():
    with patch("app.parse_discount_tier"):
        assert parse_discount_tier(0.0) is not None
        assert True
"""
        report = audit_test_tampering(
            old_test,
            tampered_test,
            target_function_names=["parse_discount_tier"],
        )
        self.assertFalse(report.passed)
        self.assertTrue(any("weakened" in v.lower() for v in report.violations))
        self.assertTrue(any("skip" in v.lower() for v in report.violations))
        self.assertTrue(any("mocks out target" in v for v in report.violations))
        self.assertTrue(any("tautological" in v.lower() for v in report.violations))

    def test_gate2_catches_hollow_tests_and_passes_strong_tests(self) -> None:
        hollow_code = """
def compute_fee(val: float) -> float:
    if val == 100.0:
        return 15.0
    if val < 0:
        return -1.0
    return val * 0.05
"""
        hollow_test = """
def test_only_100():
    assert compute_fee(100.0) == 15.0
"""
        bad_mut_report = run_in_memory_mutation_gate(
            hollow_code,
            hollow_test,
            target_function="compute_fee",
        )
        self.assertFalse(bad_mut_report.passed)
        self.assertGreater(bad_mut_report.survived_mutants, 0)

        good_mut_report = run_in_memory_mutation_gate(
            REFERENCE_CORRECT_SOURCE,
            GOOD_AGENT_TEST_SOURCE,
            target_function="parse_discount_tier",
        )
        self.assertTrue(good_mut_report.passed)
        self.assertEqual(good_mut_report.survived_mutants, 0)

    def test_gate3_differential_fuzzer_catches_single_input_overfit(self) -> None:
        env_bad: dict = {}
        env_ref: dict = {}
        exec(BAD_AGENT_PATCH_SOURCE, env_bad)
        exec(REFERENCE_CORRECT_SOURCE, env_ref)

        fuzz_report = run_differential_fuzz_gate(
            env_ref["parse_discount_tier"],
            env_bad["parse_discount_tier"],
            num_samples=200,
        )
        self.assertFalse(fuzz_report.passed)
        self.assertGreater(len(fuzz_report.counterexamples), 0)

    def test_gate3_statistical_benchmark_mann_whitney(self) -> None:
        bench = run_statistical_benchmark_gate(
            lambda: sum(range(50)),
            lambda: sum(range(50)),
            rounds=30,
            iterations_per_round=50,
            require_speedup=False,
            max_regression_pct=50.0,
        )
        self.assertEqual(bench.rounds, 30)
        self.assertGreater(bench.baseline_median_us, 0)

    def test_sqlite_rrf_memory_and_superseded_invalidation(self) -> None:
        ledger = EpisodicMemoryLedger(":memory:")
        id1 = ledger.record_outcome(
            ast_anchor="¶src/discount.py#a1b2c3d4e5f60123",
            function_name="parse_discount_tier",
            failure_mode="surviving_mutant",
            summary="Agent hardcoded amount == 100.0; failed on >100 boundary",
            tags="mutation discount boundary",
        )
        id2 = ledger.record_outcome(
            ast_anchor="¶src/discount.py#a1b2c3d4e5f60123",
            function_name="parse_discount_tier",
            failure_mode="surviving_mutant",
            summary="Agent hardcoded amount == 100.0; failed on >100 boundary",
            tags="mutation discount boundary",
        )
        self.assertEqual(id1, id2)
        hits = ledger.recall_rrf("parse_discount_tier boundary", tag_filter="mutation")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].flake_retry_count, 2)

        ledger.record_outcome(
            ast_anchor="¶src/discount.py#a1b2c3d4e5f60123",
            function_name="parse_discount_tier",
            failure_mode="verified_fix",
            summary="Replaced with >= 100.0 check and killed 5/5 mutants",
            tags="verified discount boundary",
            supersede_previous_for_anchor=True,
        )
        active_hits = ledger.recall_rrf("parse_discount_tier boundary")
        self.assertEqual(len(active_hits), 1)
        self.assertEqual(active_hits[0].failure_mode, "verified_fix")
        ledger.close()

    def test_git_diff_extractor_classifies_source_and_test_files(self) -> None:
        self.assertTrue(is_test_file("tests/test_logic.py"))
        self.assertTrue(is_test_file("logic_test.py"))
        self.assertTrue(is_test_file("test/sub/check.py"))
        self.assertFalse(is_test_file("cordis/mutator.py"))

        diff_sample = """diff --git a/cordis/core.py b/cordis/core.py
--- a/cordis/core.py
+++ b/cordis/core.py
@@ -1,5 +1,5 @@
-def alpha():
-    return 1
+def alpha():
+    return 2
diff --git a/tests/test_core.py b/tests/test_core.py
--- a/tests/test_core.py
+++ b/tests/test_core.py
@@ -1,5 +1,5 @@
 def test_alpha():
-    assert alpha() == 1
+    assert alpha() == 2
"""
        mock_files = {
            "cordis/core.py": "def alpha():\n    return 2\n",
            "tests/test_core.py": "def test_alpha():\n    assert alpha() == 2\n",
        }
        report = parse_git_diff_text(
            diff_sample,
            file_reader=lambda p: mock_files.get(p),
        )
        self.assertEqual(report.source_files, ["cordis/core.py"])
        self.assertEqual(report.test_files, ["tests/test_core.py"])
        self.assertIn("alpha", report.target_function_names)
        self.assertTrue(any(f.name == "test_alpha" and f.is_test for f in report.modified_functions))

    def test_git_diff_identifies_exact_modified_function_and_ignores_untouched(self) -> None:
        source = """def untouched_func(x):
    return x * 10

def target_func(y):
    # Changed line
    return y + 42

def another_untouched(z):
    return z - 1
"""
        diff = """diff --git a/service.py b/service.py
--- a/service.py
+++ b/service.py
@@ -5,2 +5,2 @@ def target_func(y):
-    return y + 1
+    return y + 42
"""
        report = parse_git_diff_text(diff, file_reader=lambda _: source)
        self.assertEqual(report.target_function_names, ["target_func"])
        self.assertEqual(len(report.modified_functions), 1)
        self.assertEqual(report.modified_functions[0].name, "target_func")
        self.assertEqual(report.modified_functions[0].lineno, 4)

    def test_is_bot_identity_detection(self) -> None:
        self.assertTrue(is_bot_identity("github-actions[bot]"))
        self.assertTrue(is_bot_identity("devin-ai"))
        self.assertTrue(is_bot_identity("cursor-agent"))
        self.assertTrue(is_bot_identity("claude-code[bot]"))
        self.assertTrue(is_bot_identity("Dependabot"))
        self.assertTrue(is_bot_identity("human", "41898282+github-actions[bot]@users.noreply.github.com"))
        self.assertFalse(is_bot_identity("Linus Torvalds", "torvalds@linux-foundation.org"))
        self.assertFalse(is_bot_identity("Alice Engineer", "alice@company.com"))

    def test_forge_guard_blocks_bot_self_approval(self) -> None:
        report = audit_forge_guard(
            pr_author="cursor-agent[bot]",
            reviewer="cursor-agent[bot]",
            review_state="APPROVED",
        )
        self.assertFalse(report.passed)
        self.assertTrue(report.is_self_approved)
        self.assertTrue(any("SELF_APPROVAL" in v for v in report.violations))

    def test_forge_guard_blocks_bot_to_bot_collusion(self) -> None:
        report = audit_forge_guard(
            pr_author="devin[bot]",
            reviewer="coderabbitai[bot]",
            review_state="APPROVED",
        )
        self.assertFalse(report.passed)
        self.assertTrue(any("BOT_COLLUSION" in v for v in report.violations))

    def test_forge_guard_blocks_single_token_auto_merge(self) -> None:
        report = audit_forge_guard(
            pr_author="claude-code[bot]",
            auto_merge_requested=True,
        )
        self.assertFalse(report.passed)
        self.assertTrue(any("SINGLE_TOKEN_AUTO_MERGE" in v for v in report.violations))

    def test_forge_guard_allows_human_review_of_agent_pr(self) -> None:
        report = audit_forge_guard(
            pr_author="antigravity-agent[bot]",
            reviewer="staff-engineer-janmejai",
            review_state="APPROVED",
        )
        self.assertTrue(report.passed)
        self.assertEqual(len(report.violations), 0)

    def test_forge_guard_detects_github_actions_actor_self_approval(self) -> None:
        mock_env = {
            "GITHUB_ACTOR": "ai-bot",
            "GITHUB_TRIGGERING_ACTOR": "ai-bot",
            "GITHUB_EVENT_NAME": "pull_request_review",
        }
        report = audit_forge_guard(
            env=mock_env,
            pr_author="ai-bot",
            review_state="APPROVED",
        )
        self.assertFalse(report.passed)
        self.assertTrue(any("SELF_APPROVAL" in v for v in report.violations))

    def test_html_report_generation_and_saving(self) -> None:
        g1 = audit_test_tampering("def test_x(): assert f(1) == 2", "def test_x(): assert f(1) == 2")
        g2 = run_in_memory_mutation_gate("def f(): return 1", "def test_f(): assert f() == 1", target_function="f")
        fuzz = DifferentialFuzzReport(passed=True, inputs_tested=200, counterexamples=[])
        bench = BenchmarkGateReport(
            passed=True,
            rounds=30,
            baseline_median_us=0.05,
            candidate_median_us=0.05,
            speedup_pct=0.0,
            u_statistic=0.0,
            p_value=1.0,
            note="Test benchmark",
        )
        html_out = generate_html_report(
            pr_title="PR #100 Test",
            fixproof_revert_passed=True,
            gate1_report=g1,
            gate2_report=g2,
            gate3_fuzz_report=fuzz,
            gate3_bench_report=bench,
        )
        self.assertIn("CORDIS ADVERSARIAL PR PROSECUTOR", html_out)
        self.assertIn("PR #100 Test", html_out)
        self.assertIn("VERIFIED APPROVED TO LAND", html_out)

        with tempfile.TemporaryDirectory() as tmpdir:
            h_path = Path(tmpdir) / "report.html"
            m_path = Path(tmpdir) / "report.md"
            saved_h = save_html_report(
                filepath=h_path,
                pr_title="PR #100 Test",
                fixproof_revert_passed=True,
                gate1_report=g1,
                gate2_report=g2,
                gate3_fuzz_report=fuzz,
                gate3_bench_report=bench,
            )
            self.assertTrue(saved_h.exists())
            self.assertGreater(saved_h.stat().st_size, 500)

            saved_m = save_markdown_report(m_path, "# Verdict\nPassed.")
            self.assertTrue(saved_m.exists())
            self.assertEqual(saved_m.read_text(encoding="utf-8"), "# Verdict\nPassed.")

    def test_format_github_prosecutor_comment(self) -> None:
        g1 = audit_test_tampering("def test_x(): assert f(1) == 2", "def test_x(): assert f(1) == 2")
        g2 = run_in_memory_mutation_gate("def f(): return 1", "def test_f(): assert f() == 1", target_function="f")
        fuzz = DifferentialFuzzReport(passed=True, inputs_tested=200, counterexamples=[])
        bench = BenchmarkGateReport(
            passed=True,
            rounds=30,
            baseline_median_us=0.05,
            candidate_median_us=0.05,
            speedup_pct=0.0,
            u_statistic=0.0,
            p_value=1.0,
            note="Test benchmark",
        )
        comment = format_github_prosecutor_comment(
            pr_title="PR #99 Unit Test",
            fixproof_revert_passed=True,
            gate1_report=g1,
            gate2_report=g2,
            gate3_fuzz_report=fuzz,
            gate3_bench_report=bench,
        )
        self.assertIn("## 🛡️ Cordis Adversarial AI-PR Prosecutor Verdict: PR #99 Unit Test", comment)
        self.assertIn("APPROVED TO LAND", comment)
        self.assertIn("Gate 1: AST Test-Tampering", comment)
        self.assertIn("Gate 2: In-Place AST Mutation", comment)
        self.assertIn("Gate 3A: Differential Property Fuzzing", comment)
        self.assertIn("Gate 3B: Mann-Whitney U Baseline Benchmark", comment)

    def test_cli_run_demo_and_verify_git(self) -> None:
        with redirect_stdout(io.StringIO()):
            with tempfile.TemporaryDirectory() as tmpdir:
                h_path = str(Path(tmpdir) / "demo_report.html")
                m_path = str(Path(tmpdir) / "demo_report.md")
                rc = run_demo(github_comment=True, output_html=h_path, output_md=m_path)
                self.assertEqual(rc, 0)
                self.assertTrue(Path(h_path).exists())
                self.assertTrue(Path(m_path).exists())

            # Test main CLI entrypoint with "demo", "verify-git", and default (no args)
            with patch.object(sys, "argv", ["cordis", "demo"]):
                self.assertEqual(main(), 0)

            with patch.object(sys, "argv", ["cordis"]):
                self.assertEqual(main(), 0)

            with patch.object(sys, "argv", ["cordis", "verify-git"]):
                with patch("cordis.cli.extract_git_diff") as mock_diff_main:
                    mock_diff_main.return_value = GitDiffReport(
                        base_ref="HEAD~1",
                        target_ref=None,
                        source_files=[],
                        test_files=[],
                    )
                    self.assertEqual(main(), 0)

            # Test run_verify_git with clean git diff (exit 0)
            with patch("cordis.cli.extract_git_diff") as mock_diff:
                mock_diff.return_value = GitDiffReport(
                    base_ref="HEAD~1",
                    target_ref=None,
                    source_files=[],
                    test_files=[],
                )
                rc_clean = run_verify_git(repo_dir=".")
                self.assertEqual(rc_clean, 0)

            # Test run_verify_git with multi-file modified source and test files
            with tempfile.TemporaryDirectory() as tmp_repo:
                src_p = Path(tmp_repo) / "calc.py"
                util_p = Path(tmp_repo) / "util.py"
                test_p = Path(tmp_repo) / "test_calc.py"
                src_p.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
                util_p.write_text("def mul(a, b):\n    return a * b\n", encoding="utf-8")
                test_p.write_text("def test_add():\n    assert add(1, 2) == 3\ndef test_mul():\n    assert mul(2, 3) == 6\n", encoding="utf-8")

                with patch("cordis.cli.extract_git_diff") as mock_diff_active:
                    mock_diff_active.return_value = GitDiffReport(
                        base_ref="HEAD~1",
                        target_ref=None,
                        source_files=["calc.py", "util.py"],
                        test_files=["test_calc.py"],
                        modified_functions=[
                            ModifiedFunction(name="add", file_path="calc.py", lineno=1, end_lineno=2, is_test=False),
                            ModifiedFunction(name="mul", file_path="util.py", lineno=1, end_lineno=2, is_test=False),
                            ModifiedFunction(name="test_add", file_path="test_calc.py", lineno=1, end_lineno=3, is_test=True),
                        ],
                    )
                    rc_active = run_verify_git(repo_dir=tmp_repo, github_comment=True)
                    self.assertEqual(rc_active, 0)

            # Test run_verify_git with hollow test returning exit 1
            with tempfile.TemporaryDirectory() as tmp_fail_repo:
                src_fail = Path(tmp_fail_repo) / "calc.py"
                test_fail = Path(tmp_fail_repo) / "test_calc.py"
                src_fail.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
                test_fail.write_text("def test_add():\n    assert add(1, 2) is not None\n", encoding="utf-8")

                with patch("cordis.cli.extract_git_diff") as mock_diff_fail:
                    mock_diff_fail.return_value = GitDiffReport(
                        base_ref="HEAD~1",
                        target_ref=None,
                        source_files=["calc.py"],
                        test_files=["test_calc.py"],
                        modified_functions=[
                            ModifiedFunction(name="add", file_path="calc.py", lineno=1, end_lineno=2, is_test=False),
                        ],
                    )
                    rc_fail = run_verify_git(repo_dir=tmp_fail_repo)
                    self.assertEqual(rc_fail, 1)

    def test_verify_git_real_repo_blocks_bad_commit(self) -> None:
        # Scenario 1: Zero modified test files, single-input overfit in source
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "ProsecutorTester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "prosecutor@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            calc_path = Path(tmp_dir) / "calc.py"
            calc_path.write_text(
                "def parse_discount(x: float) -> float:\n"
                "    if x < 0:\n"
                "        raise ValueError('negative')\n"
                "    if x > 100.0:\n"
                "        return 0.15\n"
                "    return 0.0\n",
                encoding="utf-8",
            )
            tests_dir = Path(tmp_dir) / "tests"
            tests_dir.mkdir()
            test_calc = tests_dir / "test_calc.py"
            test_calc.write_text(
                "from calc import parse_discount\n\n"
                "def test_discount():\n"
                "    assert parse_discount(0.0) == 0.0\n"
                "    assert parse_discount(150.0) == 0.15\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Commit 1: baseline implementation"], cwd=tmp_dir, check=True, capture_output=True)

            # Commit 2: Single-input overfit bug with 0 test files modified
            calc_path.write_text(
                "def parse_discount(x: float) -> float:\n"
                "    if x == 100.0:\n"
                "        return 0.15\n"
                "    return 0.0\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "calc.py"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Commit 2: agent overfit fix"], cwd=tmp_dir, check=True, capture_output=True)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = run_verify_git(base_ref="HEAD~1", target_ref="HEAD", repo_dir=tmp_dir)
            out = buf.getvalue()

            self.assertEqual(rc, 1)
            self.assertIn("BLOCKED", out)
            self.assertIn("Gate 3A Differential Fuzzing", out)
            self.assertIn("FAIL", out)
            self.assertIn("Discovered existing test files", out)

        # Scenario 2: Weakened test assertion in Commit 2
        with tempfile.TemporaryDirectory() as tmp_dir2:
            subprocess.run(["git", "init"], cwd=tmp_dir2, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "ProsecutorTester"], cwd=tmp_dir2, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "prosecutor@example.com"], cwd=tmp_dir2, check=True, capture_output=True)

            calc_path2 = Path(tmp_dir2) / "calc.py"
            calc_path2.write_text(
                "def parse_discount(x: float) -> float:\n"
                "    if x >= 100.0:\n"
                "        return 0.15\n"
                "    return 0.0\n",
                encoding="utf-8",
            )
            tests_dir2 = Path(tmp_dir2) / "tests"
            tests_dir2.mkdir()
            test_calc2 = tests_dir2 / "test_calc.py"
            test_calc2.write_text(
                "from calc import parse_discount\n\n"
                "def test_discount():\n"
                "    assert parse_discount(150.0) == 0.15\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=tmp_dir2, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Commit 1: baseline implementation"], cwd=tmp_dir2, check=True, capture_output=True)

            # Commit 2: Agent weakens assertion to hollow is not None
            test_calc2.write_text(
                "from calc import parse_discount\n\n"
                "def test_discount():\n"
                "    assert parse_discount(150.0) is not None\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "tests/test_calc.py"], cwd=tmp_dir2, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Commit 2: weakened assertion"], cwd=tmp_dir2, check=True, capture_output=True)

            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                rc2 = run_verify_git(base_ref="HEAD~1", target_ref="HEAD", repo_dir=tmp_dir2)
            out2 = buf2.getvalue()

            self.assertEqual(rc2, 1)
            self.assertIn("BLOCKED", out2)
            self.assertIn("Gate 1 Test-Tampering", out2)
            self.assertIn("FAIL", out2)

    def test_5_archetype_benchmark_suite(self) -> None:
        res = run_benchmark()
        self.assertEqual(len(res.cases), 5)
        self.assertEqual(res.pytest_score, "0/5")
        self.assertEqual(res.fixproof_score, "1/5")
        self.assertEqual(res.cordis_score, "5/5")
        self.assertGreater(res.total_time_ms, 0.0)

        # Markdown output formatting
        table = format_benchmark_markdown_table(res)
        self.assertIn("Cordis vs. Industry Verification: 5-Archetype Benchmark", table)
        self.assertIn("Single-Input Hardcoded Overfit", table)
        self.assertIn("Hollow Assertion Weakening", table)
        self.assertIn("Target Function Mocking", table)
        self.assertIn("Unchecked Boundary Off-by-One", table)
        self.assertIn("Silent NaN / Negative Float Regression", table)
        self.assertIn("5/5", table)

        # CLI benchmark execution
        with redirect_stdout(io.StringIO()):
            rc = run_benchmark_cli()
            self.assertEqual(rc, 0)

    def test_mutator_dataclass_support(self) -> None:
        src = """from dataclasses import dataclass

@dataclass
class Config:
    timeout: int = 30
    debug: bool = False

def get_timeout(c: Config) -> int:
    return c.timeout
"""
        test = """def test_config():
    c = Config(timeout=45)
    assert get_timeout(c) == 45
"""
        rep = run_in_memory_mutation_gate(src, test, target_function="get_timeout")
        self.assertTrue(rep.passed)
        self.assertGreater(rep.killed_mutants, 0)

    def test_mutator_unittest_testcase_support(self) -> None:
        src = "def add(a, b): return a + b"
        test = """import unittest
class AddTest(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(1, 2), 3)
"""
        rep = run_in_memory_mutation_gate(src, test, target_function="add")
        self.assertTrue(rep.passed)
        self.assertGreater(rep.killed_mutants, 0)

    def test_mutator_target_function_not_found_returns_empty(self) -> None:
        source = "def real_function(x): return x + 1"
        mutants = generate_ast_mutants(source, target_function="non_existent_func")
        self.assertEqual(mutants, [])

    def test_mutator_skips_dunder_name_main_comparisons(self) -> None:
        source = """def compute(x):
    return x == 42

if __name__ == "__main__":
    if compute(42) == True:
        print("Done")
"""
        mutants = generate_ast_mutants(source)
        self.assertGreater(len(mutants), 0)
        for desc, lineno, mutated_src in mutants:
            self.assertNotIn("__name__ !=", mutated_src)
            self.assertNotIn("!= '__main__'", mutated_src)
            self.assertNotIn('!= "__main__"', mutated_src)

    def test_fuzzer_adversarial_collection_generation(self) -> None:
        int_vals = _generate_adversarial_values_for_type(int, count=20)
        self.assertIn(0, int_vals)
        self.assertIn(-1, int_vals)
        float_vals = _generate_adversarial_values_for_type(float, count=30)
        self.assertIn(0.0, float_vals)
        self.assertIn(-0.0, float_vals)
        self.assertTrue(any(math.isnan(v) for v in float_vals if isinstance(v, float)))
        str_vals = _generate_adversarial_values_for_type(str, count=20)
        self.assertIn("", str_vals)
        bool_vals = _generate_adversarial_values_for_type(bool, count=20)
        self.assertIn(True, bool_vals)

        list_vals = _generate_adversarial_values_for_type(list, count=20)
        self.assertIn([], list_vals)
        self.assertTrue(all(isinstance(v, list) for v in list_vals))

        dict_vals = _generate_adversarial_values_for_type(dict, count=20)
        self.assertIn({}, dict_vals)
        self.assertTrue(all(isinstance(v, dict) for v in dict_vals))

        set_vals = _generate_adversarial_values_for_type(set, count=20)
        self.assertIn(set(), set_vals)
        self.assertTrue(all(isinstance(v, set) for v in set_vals))

        tuple_vals = _generate_adversarial_values_for_type(tuple, count=20)
        self.assertIn((), tuple_vals)
        self.assertTrue(all(isinstance(v, tuple) for v in tuple_vals))

        unannotated = _generate_adversarial_values_for_type(inspect._empty, count=50)
        self.assertIn([], unannotated)
        self.assertIn({}, unannotated)
        self.assertIn(set(), unannotated)
        self.assertIn((), unannotated)

    def test_mutator_foreign_module_patching(self) -> None:
        import cordis.fuzzer
        orig_fn = cordis.fuzzer.BenchmarkGateReport.latency_delta_pct
        src = Path(cordis.fuzzer.__file__).read_text(encoding="utf-8")
        test = """import unittest
from cordis.fuzzer import BenchmarkGateReport

class ForeignTest(unittest.TestCase):
    def test_latency(self):
        r = BenchmarkGateReport(passed=True, rounds=30, baseline_median_us=0.05, candidate_median_us=0.05, speedup_pct=15.0, u_statistic=0.0, p_value=1.0, note="")
        self.assertEqual(r.latency_delta_pct, -15.0)
"""
        rep = run_in_memory_mutation_gate(src, test, target_function="latency_delta_pct", module_name="cordis.fuzzer")
        self.assertTrue(rep.passed)
        self.assertGreater(rep.killed_mutants, 0)
        self.assertIs(cordis.fuzzer.BenchmarkGateReport.latency_delta_pct, orig_fn)

    def test_generate_ast_mutants_operators(self) -> None:
        src = "def f(x):\n    return x == 1\n"
        muts = generate_ast_mutants(src)
        self.assertEqual(len(muts), 2)
        self.assertTrue(any("Flip `==` to `!=`" in m[0] for m in muts))

        src2 = "def f(x):\n    return x + 1\n"
        muts2 = generate_ast_mutants(src2)
        self.assertEqual(len(muts2), 2)
        self.assertTrue(any("Flip `+` to `-`" in m[0] for m in muts2))

    def test_tautological_and_weak_assert_helpers(self) -> None:
        import ast
        t1 = ast.parse("assert True").body[0]
        self.assertIsNotNone(_is_tautological_assert(t1))
        t2 = ast.parse("assert x == x").body[0]
        self.assertIsNotNone(_is_tautological_assert(t2))
        t3 = ast.parse("assert x is x").body[0]
        self.assertIsNotNone(_is_tautological_assert(t3))
        t4 = ast.parse("self.assertTrue(True)").body[0].value
        self.assertIsNotNone(_is_tautological_assert(t4))
        t5 = ast.parse("self.assertEqual(a, a)").body[0].value
        self.assertIsNotNone(_is_tautological_assert(t5))
        normal = ast.parse("assert x == 42").body[0]
        self.assertIsNone(_is_tautological_assert(normal))

        w1 = ast.parse("assert x is not None").body[0]
        self.assertTrue(_is_weak_not_none_assert(w1))
        w2 = ast.parse("assert x != None").body[0]
        self.assertTrue(_is_weak_not_none_assert(w2))
        w3 = ast.parse("self.assertIsNotNone(x)").body[0].value
        self.assertTrue(_is_weak_not_none_assert(w3))
        strong1 = ast.parse("assert x == 1").body[0]
        self.assertFalse(_is_weak_not_none_assert(strong1))
        strong2 = ast.parse("assert x is not 42").body[0]
        self.assertFalse(_is_weak_not_none_assert(strong2))
        strong3 = ast.parse("self.assertEqual(x, 1)").body[0].value
        self.assertFalse(_is_weak_not_none_assert(strong3))

        # Check _is_unittest_assert_call helper
        assert_call = ast.parse("self.assertEqual(1, 1)").body[0].value
        self.assertTrue(_is_unittest_assert_call(assert_call))
        non_assert_call = ast.parse("self.helper(1, 1)").body[0].value
        self.assertFalse(_is_unittest_assert_call(non_assert_call))

    def test_run_repo_mutation_gate_multi_file_package(self) -> None:
        """Verifies run_repo_mutation_gate on a multi-file layout with cross-package imports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            pkg_dir = tmppath / "pkg"
            pkg_dir.mkdir()
            (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
            core_file = pkg_dir / "core.py"
            core_content = (
                "def compute_discount(price: float, member: bool) -> float:\n"
                "    if member:\n"
                "        return price * 0.8\n"
                "    return price\n"
            )
            core_file.write_text(core_content, encoding="utf-8")

            tests_dir = tmppath / "tests"
            tests_dir.mkdir()
            (tests_dir / "__init__.py").write_text("", encoding="utf-8")
            test_file = tests_dir / "test_core.py"
            test_content = (
                "import unittest\n"
                "from pkg.core import compute_discount\n\n"
                "class TestCore(unittest.TestCase):\n"
                "    def test_member_discount(self):\n"
                "        self.assertAlmostEqual(compute_discount(100.0, True), 80.0)\n"
                "    def test_non_member_discount(self):\n"
                "        self.assertAlmostEqual(compute_discount(100.0, False), 100.0)\n"
            )
            test_file.write_text(test_content, encoding="utf-8")

            # 1. Strong test suite: all mutants should be killed
            rep = run_repo_mutation_gate(
                repo_root=tmppath,
                source_rel_path="pkg/core.py",
                test_rel_path="tests/test_core.py",
                target_function="compute_discount",
                max_mutants=5,
            )
            self.assertTrue(rep.passed)
            self.assertGreater(rep.total_mutants, 0)
            self.assertEqual(rep.killed_mutants, rep.total_mutants)
            self.assertEqual(rep.survived_mutants, 0)
            # Verify file restored exactly
            self.assertEqual(core_file.read_text(encoding="utf-8"), core_content)

            # 2. Hollow test suite: asserts only is not None
            hollow_file = tests_dir / "test_hollow.py"
            hollow_content = (
                "import unittest\n"
                "from pkg.core import compute_discount\n\n"
                "class TestHollow(unittest.TestCase):\n"
                "    def test_hollow(self):\n"
                "        self.assertIsNotNone(compute_discount(100.0, True))\n"
            )
            hollow_file.write_text(hollow_content, encoding="utf-8")

            rep_hollow = run_repo_mutation_gate(
                repo_root=tmppath,
                source_rel_path="pkg/core.py",
                test_rel_path="tests/test_hollow.py",
                target_function="compute_discount",
                max_mutants=5,
            )
            self.assertFalse(rep_hollow.passed)
            self.assertGreater(rep_hollow.survived_mutants, 0)
            self.assertEqual(core_file.read_text(encoding="utf-8"), core_content)

    def test_wild_audit_configuration_and_formatter(self) -> None:
        from cordis.wild_audit import (
            WILD_TARGETS,
            WildAuditFinding,
            WildAuditTarget,
            append_wild_audit_to_file,
            format_wild_audit_markdown,
        )
        self.assertEqual(len(WILD_TARGETS), 10)
        repos = {t.repo_name for t in WILD_TARGETS}
        self.assertEqual(repos, {"python-dotenv", "boltons", "click"})

        mock_target = WildAuditTarget(
            repo_name="demo-repo",
            source_file="src/calc.py",
            test_file="tests/test_calc.py",
            function_name="calc_fn",
            description="Mock function description",
        )
        from cordis.mutator import MutantResult, MutationGateReport
        survived_mutant = MutantResult(
            mutant_id=1,
            description="Boundary shift `<` to `<=`",
            lineno=42,
            killed=False,
            mutated_code_snippet="return x <= 0",
        )
        rep = MutationGateReport(
            passed=False,
            total_mutants=1,
            killed_mutants=0,
            survived_mutants=1,
            results=[survived_mutant],
        )
        findings = [
            WildAuditFinding(
                target=mock_target,
                report=rep,
                surviving_mutants=[survived_mutant],
                latency_ms=12.5,
            )
        ]
        md = format_wild_audit_markdown(findings)
        self.assertIn("## 4. Experiment C: Wild Unmodified Open-Source Audit (Real Test Gaps Found)", md)
        self.assertIn("demo-repo", md)
        self.assertIn("Boundary shift `<` to `<=`", md)
        self.assertIn("Line 42", md)

        with tempfile.TemporaryDirectory() as tmpdir:
            test_doc = Path(tmpdir) / "DOC.md"
            test_doc.write_text("# Doc\n\n## 1. Intro\n\n## 📄 License\nMIT\n", encoding="utf-8")
            append_wild_audit_to_file(test_doc, md)
            res_text = test_doc.read_text(encoding="utf-8")
            self.assertIn("## 4. Experiment C:", res_text)
            self.assertIn("## 📄 License", res_text)

    def test_ai_repo_audit_configuration_and_formatter(self) -> None:
        from cordis.ai_repo_audit import (
            AI_REPOS,
            GATE1_TARGETS,
            GATE2_TARGETS,
            AICommitRecord,
            AIRepoConfig,
            AIRepoSummary,
            Gate1Finding,
            Gate1TestTarget,
            Gate2Finding,
            Gate2MutationTarget,
            append_ai_audit_to_file,
            format_ai_audit_markdown,
            scan_ai_commits,
        )
        from cordis.mutator import MutantResult, MutationGateReport

        # 1. Verify target lists
        self.assertEqual(len(AI_REPOS), 3)
        self.assertEqual({r.name for r in AI_REPOS}, {"fastmcp", "smolagents", "nao-mgs-workflow"})
        self.assertEqual(len(GATE1_TARGETS), 10)
        self.assertEqual(len(GATE2_TARGETS), 10)

        # 2. Test format_ai_audit_markdown with mock telemetry
        summary = AIRepoSummary(
            config=AI_REPOS[0],
            head_sha="588297e",
            py_files_count=1032,
            functions_indexed=16266,
            total_commits_scanned=30,
            ai_attributed_commits=15,
            commits=[
                AICommitRecord(
                    repo_name="fastmcp",
                    sha="588297e",
                    author="nate nowack",
                    subject="Let private triage sweeps run without the Sol reviewer (#6229)",
                    trailers="Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
                    attribution_tag="🤖 Claude-Authored (Co-Authored-By: Claude)",
                    touches_source_and_test=False,
                )
            ],
        )

        g1_find = Gate1Finding(
            target=GATE1_TARGETS[0],
            total_asserts=132,
            weak_asserts=31,
            mock_count=65,
            skip_count=0,
            tautological_count=0,
            weak_ratio=31 / 132,
            mock_ratio=65 / 132,
        )

        surv_m = MutantResult(
            mutant_id=1,
            description="Replace return expression with `None`",
            lineno=41,
            killed=False,
            mutated_code_snippet="return None",
        )
        rep = MutationGateReport(
            passed=False,
            total_mutants=5,
            killed_mutants=0,
            survived_mutants=5,
            results=[surv_m],
        )
        g2_find = Gate2Finding(
            target=GATE2_TARGETS[0],
            report=rep,
            surviving_mutants=[surv_m],
            latency_ms=135.0,
        )

        md = format_ai_audit_markdown([summary], [g1_find], [g2_find])
        self.assertIn("## 5. Experiment D: Wild AI-Agent & MCP Repository Audit", md)
        self.assertIn("fastmcp", md)
        self.assertIn("588297e", md)
        self.assertIn("Claude Opus 5.5", md)
        self.assertIn("Gate 1: Test-Tampering & Anti-Mock Audit", md)
        self.assertIn("Gate 2: In-Place AST Mutation Testing", md)
        self.assertIn("Head-to-Head Comparison: Classic Human vs. AI-Agent", md)
        self.assertIn(f"{g1_find.mock_count / g1_find.total_asserts * 100:.1f}%", md)
        self.assertIn(f"{rep.survived_mutants / rep.total_mutants * 100:.1f}%", md)

        # 3. Test appending to file
        with tempfile.TemporaryDirectory() as tmpdir:
            test_doc = Path(tmpdir) / "BENCH.md"
            test_doc.write_text("# Doc\n\n## 4. Experiment C\n\n## 📄 License\nMIT\n", encoding="utf-8")
            append_ai_audit_to_file(test_doc, md)
            res_text = test_doc.read_text(encoding="utf-8")
            self.assertIn("## 5. Experiment D:", res_text)
            self.assertIn("## 📄 License", res_text)

        # 4. Test git trailer parsing in a real git commit
        with tempfile.TemporaryDirectory() as tmp_git:
            subprocess.run(["git", "init"], cwd=tmp_git, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_git, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=tmp_git, check=True, capture_output=True)
            (Path(tmp_git) / "file.py").write_text("x = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=tmp_git, check=True, capture_output=True)
            commit_msg = "feat: add feature\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
            subprocess.run(["git", "commit", "-m", commit_msg], cwd=tmp_git, check=True, capture_output=True)
            scanned = scan_ai_commits(Path(tmp_git), "test-repo", count=5)
            self.assertEqual(len(scanned), 1)
            self.assertIn("Claude", scanned[0].attribution_tag)
            self.assertIn("Claude Opus 5.5", scanned[0].trailers)

    def test_coverage_probe_target_executed(self):
        """Verifies that run_repo_mutation_gate injects a coverage probe and detects whether target_function is executed."""
        from cordis.mutator import run_repo_mutation_gate, inject_coverage_probe

        # 1. Test inject_coverage_probe AST transformation
        sample_code = "def add(a, b):\n    '''Add two numbers.'''\n    return a + b\n"
        probed = inject_coverage_probe(sample_code, "add")
        self.assertIsNotNone(probed)
        self.assertIn("RuntimeError", probed)
        self.assertIn("__CORDIS_COVERAGE_PROBE__", probed)

        # 2. Test in a temporary repo layout
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = Path(tmpdir)
            src_dir = tmproot / "src" / "pkg"
            src_dir.mkdir(parents=True)
            (src_dir / "__init__.py").write_text("", encoding="utf-8")
            (src_dir / "math.py").write_text(
                "def called_fn():\n    return 42\n\ndef uncalled_fn():\n    return 99\n",
                encoding="utf-8",
            )
            tests_dir = tmproot / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / "__init__.py").write_text("", encoding="utf-8")
            (tests_dir / "test_math.py").write_text(
                "import unittest\nfrom pkg.math import called_fn\n\nclass TestMath(unittest.TestCase):\n    def test_call(self):\n        self.assertEqual(called_fn(), 42)\n",
                encoding="utf-8",
            )

            # Called target: target_executed must be True
            rep_called = run_repo_mutation_gate(
                repo_root=tmproot,
                source_rel_path="src/pkg/math.py",
                test_rel_path="tests/test_math.py",
                target_function="called_fn",
                max_mutants=2,
            )
            self.assertTrue(rep_called.target_executed)

            # Uncalled target: probe exits 0, so target_executed must be False
            rep_uncalled = run_repo_mutation_gate(
                repo_root=tmproot,
                source_rel_path="src/pkg/math.py",
                test_rel_path="tests/test_math.py",
                target_function="uncalled_fn",
                max_mutants=2,
            )
            self.assertFalse(rep_uncalled.target_executed)




if __name__ == "__main__":
    unittest.main()
