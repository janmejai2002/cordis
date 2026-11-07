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
from contextlib import redirect_stderr, redirect_stdout
import json
from pathlib import Path
from unittest.mock import patch

from cordis.ast_gate import (
    _is_tautological_assert,
    _is_unittest_assert_call,
    _is_weak_not_none_assert,
    audit_test_tampering,
    calculate_mock_to_assertion_ratio,
    index_ast_anchors,
    TestTamperingReport,
)
from cordis.ts_gate import (
    audit_ts_test_tampering,
    generate_ts_mutants,
    index_ts_ast_anchors,
    mask_ts_code,
    strip_ts_comments,
)
from cordis.policy_guard import audit_repository_policy, PolicyAuditReport
from cordis.benchmark_suite import format_benchmark_markdown_table, run_benchmark
from cordis.cli import (
    format_github_prosecutor_comment,
    main,
    run_benchmark_cli,
    run_demo,
    run_hooks_cli,
    run_verify_git,
    run_check_policy_cli,
    run_probe_cli,
)
from cordis.forge_guard import (
    audit_forge_guard,
    compute_diff_attestation_digest,
    is_bot_identity,
    verify_commit_attestation_trailer,
)
from cordis.hooks import (
    audit_pre_tool_use_command,
    install_harness_hooks,
    run_stop_hook_prosecutor,
    HookDecision,
)
from cordis.fuzzer import (
    BenchmarkGateReport,
    DifferentialFuzzReport,
    _generate_adversarial_values_for_type,
    harvest_ast_constants,
    run_differential_fuzz_gate,
    run_statistical_benchmark_gate,
)
from cordis.repair import synthesize_mutant_killing_test
from cordis.git_diff import GitDiffReport, ModifiedFunction, extract_git_diff, is_test_file, parse_git_diff_text
from cordis.html_report import generate_html_report, save_html_report, save_markdown_report
from cordis.memory import EpisodicMemoryLedger
from cordis.mutator import MutantResult, generate_ast_mutants, run_in_memory_mutation_gate, run_repo_mutation_gate
from examples.counterfeit_killer_demo import (
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
        self.assertEqual(id1, 1)
        self.assertEqual(id2, 1)
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

    def test_mutator_overload_stub_detection_and_bypass(self) -> None:
        from cordis.mutator import _is_overload_stub, _find_target_function_node
        import ast

        # 1. Direct unit verification of _is_overload_stub
        tree = ast.parse("""from typing import overload

@overload
def process(x: int) -> int: ...

@typing.overload
def process(x: str) -> str:
    ...

def process(x: int | str) -> int | str:
    return x
""")
        func_nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
        self.assertEqual(len(func_nodes), 3)
        self.assertTrue(_is_overload_stub(func_nodes[0]), "Expected @overload stub to be detected")
        self.assertTrue(_is_overload_stub(func_nodes[1]), "Expected @typing.overload stub to be detected")
        self.assertFalse(_is_overload_stub(func_nodes[2]), "Expected real implementation to NOT be classified as stub")

        # 2. Non-overload decorator (e.g. @property, @lru_cache) must NOT be classified as stub
        tree_decorated = ast.parse("""@property\ndef prop_val(self): return 42\n@lru_cache(maxsize=None)\ndef cached_val(x): return x * 2""")
        dec_nodes = [n for n in tree_decorated.body if isinstance(n, ast.FunctionDef)]
        self.assertFalse(_is_overload_stub(dec_nodes[0]), "Non-overload decorator @property must not be stub")
        self.assertFalse(_is_overload_stub(dec_nodes[1]), "Non-overload decorator @lru_cache must not be stub")

        # 3. Non-Expr single statements (e.g. `pass`, `return x`) and multi-statement functions
        tree_stmts = ast.parse("""def pass_fn(x): pass\ndef ret_fn(x): return x\ndef multi_with_ellipsis(x):\n    ...\n    return x + 1""")
        stmt_nodes = [n for n in tree_stmts.body if isinstance(n, ast.FunctionDef)]
        self.assertFalse(_is_overload_stub(stmt_nodes[0]), "Function with `pass` must not be stub")
        self.assertFalse(_is_overload_stub(stmt_nodes[1]), "Function with `return x` must not be stub")
        self.assertFalse(_is_overload_stub(stmt_nodes[2]), "Multi-statement function must not be stub")

        # 4. Ellipsis-only body without decorator
        tree_ellipsis = ast.parse("""def stub_only(a, b): ...\ndef real_fn(a, b): return a + b""")
        stubs = [n for n in tree_ellipsis.body if isinstance(n, ast.FunctionDef)]
        self.assertTrue(_is_overload_stub(stubs[0]))
        self.assertFalse(_is_overload_stub(stubs[1]))

        # 3. Target function resolution bypasses stubs to locate true runtime implementation
        target_node = _find_target_function_node(tree, "process")
        self.assertIsNotNone(target_node)
        self.assertEqual(target_node.lineno, func_nodes[2].lineno, "Should resolve to true implementation on line 10, not stubs")
        self.assertFalse(_is_overload_stub(target_node))

        # 4. Class-level overload bypass (e.g. Session.exec in sqlmodel)
        class_tree = ast.parse("""class Session:
    @overload
    def exec(self, statement: Select) -> Result: ...

    def exec(self, statement: Any) -> Any:
        return self._raw_exec(statement)
""")
        class_target = _find_target_function_node(class_tree, "Session.exec")
        self.assertIsNotNone(class_target)
        self.assertFalse(_is_overload_stub(class_target))
        self.assertIn("_raw_exec", ast.unparse(class_target))

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

            # Non-existent target function: target_executed must be False
            rep_missing = run_repo_mutation_gate(
                repo_root=tmproot,
                source_rel_path="src/pkg/math.py",
                test_rel_path="tests/test_math.py",
                target_function="does_not_exist_at_all",
                max_mutants=2,
            )
            self.assertFalse(rep_missing.target_executed)

            # Broken test suite with collection/import error: target_executed must be False
            (tests_dir / "test_broken.py").write_text(
                "import broken_import_nonexistent_xyz\ndef test_broken(): pass\n",
                encoding="utf-8",
            )
            rep_broken = run_repo_mutation_gate(
                repo_root=tmproot,
                source_rel_path="src/pkg/math.py",
                test_rel_path="tests/test_broken.py",
                target_function="called_fn",
                max_mutants=2,
            )
            self.assertFalse(rep_broken.target_executed)

    def test_reachability_filter_prunes_boundary_mutations(self) -> None:
        # 1. Chained guard where 0 <= delay <= MAX returns immediately
        guarded_source = """def clamp(delay, MAX):
    if math.isfinite(delay) and 0 <= delay <= MAX:
        return delay
    if delay > MAX:
        return MAX
    return 0.0
"""
        mutants = generate_ast_mutants(guarded_source, max_mutants=10)
        # Should prune 'Boundary shift `>` to `>=`' on line 4
        boundary_muts = [m for m in mutants if "Boundary shift `>` to `>=`" in m[0]]
        self.assertEqual(len(boundary_muts), 0, "Expected boundary shift `>` to `>=` to be pruned on guarded branch")
        # But polarity flip `>` to `<=` MUST be kept
        flip_muts = [m for m in mutants if "Flip `>` to `<=`" in m[0]]
        self.assertGreaterEqual(len(flip_muts), 1, "Expected polarity flip `>` to `<=` to be retained")

        # 2. Symmetric: if delay >= MIN returns, prune `<` to `<=` downstream
        guarded_min_source = """def check_min(delay, MIN):
    if delay >= MIN:
        return delay
    if delay < MIN:
        return MIN
    return 0
"""
        min_muts = generate_ast_mutants(guarded_min_source, max_mutants=10)
        min_boundary = [m for m in min_muts if "Boundary shift `<` to `<=`" in m[0]]
        self.assertEqual(len(min_boundary), 0, "Expected boundary shift `<` to `<=` to be pruned")
        min_flip = [m for m in min_muts if "Flip `<` to `>=`" in m[0]]
        self.assertGreaterEqual(len(min_flip), 1, "Expected polarity flip `<` to `>=` to be retained")

        # 3. Unguarded: boundary shift must be generated
        unguarded_source = """def check(delay, MAX):
    if delay > MAX:
        return MAX
    return delay
"""
        un_muts = generate_ast_mutants(unguarded_source, max_mutants=10)
        un_boundary = [m for m in un_muts if "Boundary shift `>` to `>=`" in m[0]]
        self.assertGreaterEqual(len(un_boundary), 1, "Expected boundary shift on unguarded branch")

        # 4. Non-terminal preceding branch: do not prune
        non_terminal_source = """def check(delay, MAX):
    if delay <= MAX:
        print("not terminal")
    if delay > MAX:
        return MAX
    return delay
"""
        nt_muts = generate_ast_mutants(non_terminal_source, max_mutants=10)
        nt_boundary = [m for m in nt_muts if "Boundary shift `>` to `>=`" in m[0]]
        self.assertGreaterEqual(len(nt_boundary), 1, "Expected boundary shift when preceding branch does not terminate")

        # 5. Variable reassigned between guard and check: do not prune
        reassigned_source = """def check(delay, MAX):
    if 0 <= delay <= MAX:
        return delay
    delay = delay + 1
    if delay > MAX:
        return MAX
    return 0.0
"""
        re_muts = generate_ast_mutants(reassigned_source, max_mutants=10)
        re_boundary = [m for m in re_muts if "Boundary shift `>` to `>=`" in m[0]]
        self.assertGreaterEqual(len(re_boundary), 1, "Expected boundary shift when variable is reassigned")

    def test_unaryop_mutations_invert_not_and_boolean(self) -> None:
        source = """def check_ready(ready, active):
    if not ready:
        return 0
    if active:
        return 1
    return 2
"""
        muts = generate_ast_mutants(source, max_mutants=10)
        has_not_removed = any("Remove unary `not` inversion" in m[0] for m in muts)
        has_not_added = any("Invert boolean condition with `not`" in m[0] for m in muts)
        self.assertTrue(has_not_removed, "Expected unary `not` removal mutant")
        self.assertTrue(has_not_added, "Expected unary `not` addition mutant")

        # Verify mutated code syntax
        not_removed_snippet = next(m[2] for m in muts if "Remove unary `not` inversion" in m[0])
        self.assertIn("if ready:", not_removed_snippet)
        not_added_snippet = next(m[2] for m in muts if "Invert boolean condition with `not`" in m[0])
        self.assertIn("if not active:", not_added_snippet)

    def test_compare_identity_and_membership_mutations(self) -> None:
        source = """def inspect_obj(val, container):
    if val is None:
        return -1
    if val is not 0:
        pass
    if val in container:
        return 1
    if val not in container:
        return 2
    return 0
"""
        muts = generate_ast_mutants(source, max_mutants=20)
        desc_set = {m[0] for m in muts}
        self.assertTrue(any("Flip `is` to `is not`" in d for d in desc_set))
        self.assertTrue(any("Flip `is not` to `is`" in d for d in desc_set))
        self.assertTrue(any("Flip `in` to `not in`" in d for d in desc_set))
        self.assertTrue(any("Flip `not in` to `in`" in d for d in desc_set))

        # Check snippets
        is_mut = next(m[2] for m in muts if "Flip `is` to `is not`" in m[0])
        self.assertIn("val is not None", is_mut)
        in_mut = next(m[2] for m in muts if "Flip `in` to `not in`" in m[0])
        self.assertIn("val not in container", in_mut)

    def test_container_subscript_perturbations(self) -> None:
        source = """def process_items(items):
    first = items[0]
    sub = items[0:]
    last = items[-1]
    items[0] = 99
    d = {"k": 0}
    val = d["k"]
    return first
"""
        muts = generate_ast_mutants(source, max_mutants=10)
        has_idx = any("Perturb container index `[0]` to `[1]`" in m[0] for m in muts)
        has_slice = any("Perturb container slice lower bound `[0:]` to `[1:]`" in m[0] for m in muts)
        self.assertTrue(has_idx, "Expected subscript index perturbation")
        self.assertTrue(has_slice, "Expected subscript slice perturbation")

        idx_mut = next(m[2] for m in muts if "Perturb container index `[0]` to `[1]`" in m[0])
        self.assertIn("items[1]", idx_mut)
        # Store context items[0] = 99 must NOT be mutated to items[1:] = 99
        self.assertNotIn("items[1:] = 99", idx_mut)
        # Negative index items[-1] must NOT be mutated
        self.assertNotIn("items[1:] = items[0]", idx_mut)

    def test_calculate_mock_to_assertion_ratio(self) -> None:
        # LOW risk: 25 asserts, 2 mocks -> MAR = 2 / 25 = 0.08 < 0.10
        low_src = """
def test_healthy():
    from unittest.mock import Mock
    m = Mock()
""" + "\n".join(f"    assert x_{i} == {i}" for i in range(25))
        r_low = calculate_mock_to_assertion_ratio(low_src)
        self.assertEqual(r_low["risk_level"], "LOW")
        self.assertFalse(r_low["is_high_risk"])
        self.assertLess(r_low["mar"], 0.10)

        # MODERATE risk: 10 asserts, 2 mocks -> MAR = 2 / 10 = 0.20
        mod_src = """
from unittest.mock import Mock
def test_mod():
    m = Mock()
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
"""
        r_mod = calculate_mock_to_assertion_ratio(mod_src)
        self.assertEqual(r_mod["risk_level"], "MODERATE")
        self.assertFalse(r_mod["is_high_risk"])
        self.assertGreaterEqual(r_mod["mar"], 0.10)
        self.assertLessEqual(r_mod["mar"], 0.25)

        # HIGH_RISK: 10 asserts, 4 mocks -> MAR = 4 / 10 = 0.40
        high_src = """
from unittest.mock import Mock, MagicMock, patch
@patch("module.fn")
def test_hollow(mock_fn):
    m1 = Mock()
    m2 = MagicMock()
    assert 1 == 1
    assert 2 == 2
"""
        r_high = calculate_mock_to_assertion_ratio(high_src)
        self.assertEqual(r_high["risk_level"], "HIGH_RISK")
        self.assertTrue(r_high["is_high_risk"])
        self.assertGreater(r_high["mar"], 0.25)

        # Zero assertions with mocks: 0 asserts, 2 mocks -> MAR = 2.0 (division by zero safe)
        zero_assert_src = """
from unittest.mock import Mock
def test_empty():
    m = Mock()
"""
        r_zero = calculate_mock_to_assertion_ratio(zero_assert_src)
        self.assertEqual(r_zero["risk_level"], "HIGH_RISK")
        self.assertEqual(r_zero["total_assertions"], 0)
        self.assertEqual(r_zero["mar"], 2.0)

        # Empty/whitespace string returns valid zeroed dictionary
        r_empty = calculate_mock_to_assertion_ratio("   \n\t  ")
        self.assertEqual(r_empty["total_assertions"], 0)
        self.assertEqual(r_empty["total_mocks"], 0)
        self.assertEqual(r_empty["mar"], 0.0)
        self.assertEqual(r_empty["risk_level"], "LOW")

        # Zero assertions zero mocks: MAR = 0.0 -> LOW
        empty_src = "def test_empty(): pass\n"
        r_empty = calculate_mock_to_assertion_ratio(empty_src)
        self.assertEqual(r_empty["risk_level"], "LOW")
        self.assertEqual(r_empty["mar"], 0.0)

        # with pytest.raises counts as assertion
        pytest_raises_src = """
import pytest
def test_raises():
    with pytest.raises(ValueError):
        raise ValueError("error")
"""
        r_raises = calculate_mock_to_assertion_ratio(pytest_raises_src)
        self.assertEqual(r_raises["total_assertions"], 1)

    def test_test_tampering_report_includes_mar(self) -> None:
        old_test = "def test_a(): assert f(1) == 2\n"
        new_test = """from unittest.mock import Mock
def test_a():
    m = Mock()
    assert f(1) == 2
"""
        rep = audit_test_tampering(old_test, new_test)
        self.assertTrue(hasattr(rep, "mar"))
        self.assertTrue(hasattr(rep, "total_mocks"))
        self.assertTrue(hasattr(rep, "risk_level"))
        self.assertTrue(hasattr(rep, "mar_risk_level"))
        self.assertGreater(rep.total_mocks, 0)
        self.assertGreater(rep.mar, 0.0)

    def test_policy_guard_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # 1. Pallets anti-AI ban in CONTRIBUTING.md
            (tmppath / "CONTRIBUTING.md").write_text(
                "# Contributing\nWe do not accept pull requests generated by AI or LLMs. See palletsprojects.com/contributing/llm-ai",
                encoding="utf-8",
            )
            rep_blocked = audit_repository_policy(tmppath)
            self.assertEqual(rep_blocked.status, "BLOCKED_POLICY")
            self.assertTrue(rep_blocked.ai_banned)
            self.assertGreater(len(rep_blocked.citations), 0)

            # 2. Mandatory issue requirement in .github/PULL_REQUEST_TEMPLATE.md
            (tmppath / "CONTRIBUTING.md").unlink()
            gh_dir = tmppath / ".github"
            gh_dir.mkdir(parents=True, exist_ok=True)
            (gh_dir / "PULL_REQUEST_TEMPLATE.md").write_text(
                "### Checklist\nAll pull requests must reference an existing issue. Open an issue first before submitting a PR.",
                encoding="utf-8",
            )
            rep_issue = audit_repository_policy(tmppath)
            self.assertEqual(rep_issue.status, "ISSUE_REQUIRED")
            self.assertTrue(rep_issue.issue_required)
            self.assertFalse(rep_issue.ai_banned)

            # 3. Permitted repository
            (gh_dir / "PULL_REQUEST_TEMPLATE.md").unlink()
            (tmppath / "README.md").write_text("# My Library\nWelcome to open source contributions!\n", encoding="utf-8")
            rep_perm = audit_repository_policy(tmppath)
            self.assertEqual(rep_perm.status, "PERMITTED")
            self.assertFalse(rep_perm.ai_banned)
            self.assertFalse(rep_perm.issue_required)

            # 4. Non-existent path or file path returns PERMITTED gracefully with explanatory advice
            rep_nonexistent = audit_repository_policy(tmppath / "does_not_exist_12345")
            self.assertEqual(rep_nonexistent.status, "PERMITTED")
            self.assertIn("does not exist or is not a directory", rep_nonexistent.advice)

            file_target = tmppath / "not_a_dir.txt"
            file_target.write_text("plain file", encoding="utf-8")
            rep_file = audit_repository_policy(file_target)
            self.assertEqual(rep_file.status, "PERMITTED")
            self.assertIn("does not exist or is not a directory", rep_file.advice)

    def test_cli_check_policy_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            json_out = tmppath / "policy_report.json"

            # Permitted repo
            (tmppath / "CONTRIBUTING.md").write_text("# Welcome\nPRs are warmly welcomed!\n", encoding="utf-8")
            ret = run_check_policy_cli(repo_dir=str(tmppath), output_json=str(json_out))
            self.assertEqual(ret, 0)
            self.assertTrue(json_out.is_file())
            data = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(data["status"], "PERMITTED")

            # Blocked repo
            (tmppath / "CONTRIBUTING.md").write_text("No AI-generated contributions allowed.", encoding="utf-8")
            ret_blocked = run_check_policy_cli(repo_dir=str(tmppath), output_json=str(json_out))
            self.assertEqual(ret_blocked, 1)
            data_blocked = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(data_blocked["status"], "BLOCKED_POLICY")

    def test_cli_probe_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            src_file = tmppath / "calc.py"
            test_file = tmppath / "test_calc.py"
            json_out = tmppath / "probe_findings.json"

            src_file.write_text("""def multiply(a, b):
    return a * b
""", encoding="utf-8")

            # Killer test kills binop_mult mutant
            test_file.write_text("""import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from calc import multiply

def test_mult():
    assert multiply(2, 3) == 6
    assert multiply(0, 5) == 0
    assert multiply(4, 2) == 8
""", encoding="utf-8")

            ret = run_probe_cli(
                repo=str(tmppath),
                target="calc.py",
                test="test_calc.py",
                function="multiply",
                max_mutants=2,
                output_json=str(json_out),
            )
            self.assertEqual(ret, 0, "Expected probe to pass when killer test kills mutant")
            self.assertTrue(json_out.is_file())
            findings = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertTrue(findings["passed"])
            self.assertEqual(findings["survived_mutants"], 0)
            self.assertEqual(findings["zero_token"], True)
            self.assertEqual(findings["llm_tokens_consumed"], 0)
            self.assertIn("mar", findings)

    def test_cli_probe_subcommand_with_pytest_args(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            src_file = tmppath / "math_ops.py"
            test_file = tmppath / "test_ops.py"
            json_out = tmppath / "probe_findings.json"

            src_file.write_text("def compute(a, b):\n    return a * b\n", encoding="utf-8")

            test_file.write_text("""import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from math_ops import compute

def test_fast_mult():
    assert compute(3, 4) == 12

def test_other():
    pass
""", encoding="utf-8")

            ret = run_probe_cli(
                repo=str(tmppath),
                target="math_ops.py",
                test="test_ops.py",
                function="compute",
                max_mutants=2,
                output_json=str(json_out),
                pytest_args="-k test_fast_mult",
            )
            self.assertEqual(ret, 0)
            self.assertTrue(json_out.is_file())
            data = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(data["pytest_args"], "-k test_fast_mult")
            self.assertTrue(data["passed"])

    def test_boolop_and_literal_mutations(self) -> None:
        src = """def check_auth(is_admin, is_owner, active=True):
    if is_admin and is_owner:
        return True
    if is_admin or active:
        return False
    return False
"""
        mutants = generate_ast_mutants(src, max_mutants=10)
        descriptions = [m[0] for m in mutants]
        self.assertTrue(any("Flip `and` to `or`" in d for d in descriptions))
        self.assertTrue(any("Flip `or` to `and`" in d for d in descriptions))
        self.assertTrue(any("Flip boolean literal `True` to `False`" in d for d in descriptions))

    def test_policy_guard_expanded_governance_files(self) -> None:
        from cordis.policy_guard import _discover_governance_files, audit_repository_policy
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            gh_dir = tmppath / ".github"
            gh_dir.mkdir(parents=True)
            ai_policy = gh_dir / "AI_POLICY.md"
            ai_policy.write_text("Strict policy: No AI generated pull requests or code.", encoding="utf-8")

            discovered = _discover_governance_files(tmppath)
            discovered_names = [p.name.lower() for p in discovered]
            self.assertIn("ai_policy.md", discovered_names)

            report = audit_repository_policy(tmppath)
            self.assertEqual(report.status, "BLOCKED_POLICY")
            self.assertTrue(report.ai_banned)

    def test_mutator_crash_recovery_bak_restoration(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            src_file = tmppath / "service.py"
            test_file = tmppath / "test_service.py"
            bak_file = tmppath / "service.py.cordis.bak"

            # Simulate an interrupted run: service.py is corrupted/mutated, but bak file has pristine source
            pristine_source = "def action(x):\n    return x + 10\n"
            corrupted_source = "def action(x):\n    return x - 9999\n"
            src_file.write_text(corrupted_source, encoding="utf-8")
            bak_file.write_text(pristine_source, encoding="utf-8")

            test_file.write_text("""import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from service import action

def test_action():
    assert action(5) == 15
""", encoding="utf-8")

            # run_repo_mutation_gate should detect service.py.cordis.bak, restore service.py, and delete bak
            report = run_repo_mutation_gate(
                repo_root=tmppath,
                source_rel_path="service.py",
                test_rel_path="test_service.py",
                target_function="action",
                max_mutants=1,
            )
            self.assertEqual(src_file.read_text(encoding="utf-8"), pristine_source)
            self.assertFalse(bak_file.exists())
            self.assertTrue(report.passed)

    def test_nan_canary_catches_wrapper_tautology(self) -> None:
        """Upgrade 3.1: Verifies IEEE-754 NaN canary mutant catches litellm-style wrapper tautologies."""
        source_code = """def target(x):
    return x * 2

def wrapper(x):
    return target(x)
"""
        test_code = """from __cordis_test__ import target, wrapper

def test_wrapper():
    assert wrapper(10) == target(10)
"""
        report = run_in_memory_mutation_gate(
            source_code=source_code,
            test_code=test_code,
            target_function="target",
            max_mutants=5,
            include_canary=True,
        )
        self.assertFalse(report.passed)
        self.assertTrue(report.wrapper_tautology_detected)
        descriptions = [r.description for r in report.results]
        self.assertTrue(any("[WRAPPER TAUTOLOGY DETECTED" in d for d in descriptions))

        # Real multi-file repo gate test
        with tempfile.TemporaryDirectory() as tmp:
            tmppath = Path(tmp)
            (tmppath / "pkg.py").write_text(source_code, encoding="utf-8")
            (tmppath / "test_pkg.py").write_text("from pkg import target, wrapper\ndef test_wrapper():\n    assert wrapper(10) == target(10)\n", encoding="utf-8")
            repo_report = run_repo_mutation_gate(
                repo_root=tmppath,
                source_rel_path="pkg.py",
                test_rel_path="test_pkg.py",
                target_function="target",
                max_mutants=5,
            )
            self.assertFalse(repo_report.passed)
            self.assertTrue(repo_report.wrapper_tautology_detected)
            repo_descs = [r.description for r in repo_report.results]
            self.assertTrue(any("[WRAPPER TAUTOLOGY DETECTED" in d for d in repo_descs))

    def test_arid_nodes_and_tie_boundary_equivalence(self) -> None:
        """Upgrade 3.2: Arid-node skipping on logging/print/warnings and tie-boundary equivalence filtering."""
        source_code = """import logging, warnings
logger = logging.getLogger(__name__)

def process(val):
    logger.info("Processing value %s", val)
    print("Debug:", val)
    warnings.warn("Deprecated call")
    return val + 1
"""
        mutants = generate_ast_mutants(source_code, max_mutants=10)
        for desc, lineno, src in mutants:
            self.assertNotIn("logger.info", desc)
            self.assertNotIn("print", desc)
            self.assertNotIn("warnings.warn", desc)

        # Tie-boundary equivalence filtering on min/max clamp (ternary)
        clamp_source = """def clamp_min(x, lo):
    return lo if x < lo else x
"""
        clamp_muts = generate_ast_mutants(clamp_source, max_mutants=10)
        clamp_descs = [m[0] for m in clamp_muts]
        self.assertNotIn("Boundary shift `<` to `<=`", clamp_descs)
        self.assertIn("Flip `<` to `>=`", clamp_descs)

        # Tie-boundary equivalence filtering on if/else alternate path
        clamp_else = """def clamp_min_else(x, lo):
    if x < lo:
        return lo
    else:
        return x
"""
        else_muts = generate_ast_mutants(clamp_else, max_mutants=10)
        else_descs = [m[0] for m in else_muts]
        self.assertNotIn("Boundary shift `<` to `<=`", else_descs)
        self.assertIn("Flip `<` to `>=`", else_descs)

        # Tie-boundary equivalence filtering on clamp_max with else
        clamp_max = """def clamp_max(x, hi):
    if x > hi:
        return hi
    else:
        return x
"""
        max_muts = generate_ast_mutants(clamp_max, max_mutants=10)
        max_descs = [m[0] for m in max_muts]
        self.assertNotIn("Boundary shift `>` to `>=`", max_descs)
        self.assertIn("Flip `>` to `<=`", max_descs)

    def test_security_kwarg_flip_and_resource_close_elision(self) -> None:
        """Upgrade 3.3: Wave 2 security kwarg flipping and resource .close()/.aclose() elision."""
        sec_source = """def request_data(client, url):
    resp = client.get(url, verify=True, trust_env=True)
    resp.close()
    return resp
"""
        muts = generate_ast_mutants(sec_source, max_mutants=10)
        descs = [m[0] for m in muts]
        self.assertTrue(any("verify=True" in d for d in descs))
        self.assertTrue(any("trust_env=True" in d for d in descs))
        self.assertTrue(any("resource teardown call `.close()`" in d for d in descs))

        # Check async aclose, release, and shutdown
        async_sec = """async def stream_data(client, url):
    resp = await client.get(url, verify=True)
    await resp.aclose()
    resp.release()
    resp.shutdown()
    return resp
"""
        async_muts = generate_ast_mutants(async_sec, max_mutants=10)
        async_descs = [m[0] for m in async_muts]
        self.assertTrue(any("resource teardown call `.aclose()`" in d for d in async_descs))
        self.assertTrue(any("resource teardown call `.release()`" in d for d in async_descs))
        self.assertTrue(any("resource teardown call `.shutdown()`" in d for d in async_descs))

        # Check function definition parameter defaults
        fn_defaults_src = """def secure_connect(host, port=443, *, verify=True, check_hostname=True):
    return host
"""
        fn_muts = generate_ast_mutants(fn_defaults_src, max_mutants=10)
        fn_descs = [m[0] for m in fn_muts]
        self.assertTrue(any("verify=True" in d for d in fn_descs))
        self.assertTrue(any("check_hostname=True" in d for d in fn_descs))

    def test_exception_swallowing_detection_gate1(self) -> None:
        """Upgrade 2.3: Broad and bare try-except-pass blocks wrapping target calls are flagged."""
        old_test = "def test_ok(): assert True\n"

        # Broad Exception
        broad_test = """def test_swallow():
    try:
        target(42)
    except Exception:
        pass
    assert True
"""
        rep1 = audit_test_tampering(old_test, broad_test, target_function_names=["target"])
        self.assertFalse(rep1.passed)
        self.assertTrue(any("swallows exceptions via bare/broad except pass" in v for v in rep1.violations))

        # Bare except
        bare_test = """def test_swallow_bare():
    try:
        target(42)
    except:
        pass
    assert True
"""
        rep2 = audit_test_tampering(old_test, bare_test, target_function_names=["target"])
        self.assertFalse(rep2.passed)
        self.assertTrue(any("swallows exceptions via bare/broad except pass" in v for v in rep2.violations))

        # Tuple with mixed exceptions: (ValueError, Exception)
        tuple_test = """def test_swallow_tuple():
    try:
        target(42)
    except (ValueError, Exception):
        pass
    assert target(42) == 42
"""
        rep3 = audit_test_tampering(old_test, tuple_test, target_function_names=["target"])
        self.assertFalse(rep3.passed)
        self.assertTrue(any("swallows exceptions via bare/broad except pass" in v for v in rep3.violations))

        # Specific exception should NOT be flagged as swallows broad exception
        specific_test = """def test_specific():
    try:
        target(42)
    except ValueError:
        pass
    assert target(42) == 42
"""
        rep4 = audit_test_tampering("", specific_test, target_function_names=["target"])
        self.assertTrue(rep4.passed)

    def test_alias_tautology_and_oracle_free_comparisons(self) -> None:
        """Upgrade 2.1: Dataflow alias tautology and oracle-free dynamic call comparison detection."""
        old_test = "def test_ok(): assert True\n"

        # Direct alias tautology: a = target(x); b = target(x); assert a == b
        alias_test = """def test_alias():
    a = target(10)
    b = target(10)
    assert a == b
"""
        rep_alias = audit_test_tampering(old_test, alias_test, target_function_names=["target"])
        self.assertFalse(rep_alias.passed)
        self.assertTrue(any("Direct alias tautology" in v for v in rep_alias.violations))

        # Nested alias tautology inside with block and AnnAssign
        nested_alias = """def test_nested_alias():
    with patch("sys.version"):
        a: int = target(10)
        b: int = target(10)
        assert a == b
"""
        rep_nested = audit_test_tampering(old_test, nested_alias, target_function_names=["target"])
        self.assertFalse(rep_nested.passed)
        self.assertTrue(any("Direct alias tautology" in v for v in rep_nested.violations))

        # Oracle-free dynamic call comparison: assert wrapper(x) == target(x) without literal oracles
        dynamic_test = """def test_dynamic():
    assert wrapper(10) == target(10)
"""
        rep_dyn = audit_test_tampering(old_test, dynamic_test, target_function_names=["target"])
        self.assertFalse(rep_dyn.passed)
        self.assertTrue(any("without concrete literal oracles" in v for v in rep_dyn.violations))

        # Dynamic call comparison through intermediate variables:
        vars_dyn = """def test_vars_dynamic():
    expected = wrapper(10)
    actual = target(10)
    assert actual == expected
"""
        rep_vars = audit_test_tampering(old_test, vars_dyn, target_function_names=["target"])
        self.assertFalse(rep_vars.passed)
        self.assertTrue(any("without concrete literal oracles" in v for v in rep_vars.violations))

        # Dynamic call comparison with concrete literal oracle present must PASS
        valid_with_oracle = """def test_with_oracle():
    assert wrapper(10) == target(10)
    assert target(10) == 20
"""
        rep_valid = audit_test_tampering("", valid_with_oracle, target_function_names=["target"])
        self.assertTrue(rep_valid.passed)

    def test_internal_vs_boundary_mock_classification(self) -> None:
        """Upgrade 2.2: Classify mocks into internal vs external boundary mocks and compute weighted_mar."""
        mock_source = """from unittest.mock import patch, MagicMock
import time

@patch("urllib.request.urlopen")
@patch(target="requests.get")
@patch.object(time, "sleep")
@patch("cordis.internal.service.do_work")
def test_boundaries(mock_internal, mock_sleep, mock_req, mock_boundary):
    mock_boundary.return_value = "ok"
    mock_internal.return_value = 42
    assert mock_boundary.called
    assert mock_internal.called
"""
        rep = audit_test_tampering("", mock_source)
        self.assertGreaterEqual(rep.boundary_mock_count, 3)
        self.assertGreaterEqual(rep.internal_mock_count, 1)
        self.assertGreater(rep.weighted_mar, 0.0)

    def test_co_consts_and_ast_constant_harvesting_differential_fuzzing(self) -> None:
        """Upgrade 4.1 & 4.2: co_consts + AST constant harvesting catches magic-number and string overfits in Gate 3A,
        and verifies GC-isolated benchmarking and IQR telemetry.
        """
        # 1. Bytecode co_consts harvesting on an exec()-compiled in-memory function
        env_int: dict[str, Any] = {}
        exec("""def f_cand_int(x):
    if x == 42857:
        return 999
    return x * 2
""", env_int)
        f_cand_int = env_int["f_cand_int"]

        # Ensure inspect.getsource fails on exec function to prove co_consts inspection is active
        try:
            inspect.getsource(f_cand_int)
            source_failed = False
        except (OSError, TypeError):
            source_failed = True
        self.assertTrue(source_failed, "inspect.getsource should fail on in-memory exec function")

        harvested_int = harvest_ast_constants([f_cand_int])
        self.assertIn(42857, harvested_int["int"])
        self.assertIn(42856, harvested_int["int"])
        self.assertIn(42858, harvested_int["int"])
        self.assertIn(42857.0, harvested_int["float"])

        # Gate 3A Differential Fuzzing against reference function catches magic-number overfit
        def f_ref_int(x):
            return x * 2

        fuzz_rep_int = run_differential_fuzz_gate(f_ref_int, f_cand_int)
        self.assertFalse(fuzz_rep_int.passed)
        self.assertTrue(
            any(cx.args == (42857,) for cx in fuzz_rep_int.counterexamples),
            "Gate 3A must catch magic number 42857 overfit via harvested constants",
        )

        # 2. String literal overfit in AST comparison / co_consts
        env_str: dict[str, Any] = {}
        exec("""def f_cand_str(mode):
    if mode == "secret_override":
        return True
    return False
""", env_str)
        f_cand_str = env_str["f_cand_str"]

        harvested_str = harvest_ast_constants([f_cand_str])
        self.assertIn("secret_override", harvested_str["str"])
        self.assertIn("secret_override_mut", harvested_str["str"])
        self.assertIn("SECRET_OVERRIDE", harvested_str["str"])

        def f_ref_str(mode):
            return False

        fuzz_rep_str = run_differential_fuzz_gate(f_ref_str, f_cand_str)
        self.assertFalse(fuzz_rep_str.passed)
        self.assertTrue(
            any(cx.args == ("secret_override",) for cx in fuzz_rep_str.counterexamples),
            "Gate 3A must catch string overfit 'secret_override' via harvested constants",
        )

        # 3. Upgrade 4.2: GC-Isolated Benchmarking & IQR Telemetry
        bench_rep = run_statistical_benchmark_gate(
            lambda: sum(range(100)),
            lambda: sum(range(100)),
            rounds=10,
            iterations_per_round=50,
        )
        self.assertTrue(hasattr(bench_rep, "iqr_baseline_us"))
        self.assertTrue(hasattr(bench_rep, "iqr_candidate_us"))
        self.assertGreaterEqual(bench_rep.iqr_baseline_us, 0.0)
        self.assertGreaterEqual(bench_rep.iqr_candidate_us, 0.0)

    def test_synthesize_mutant_killing_test_clamp(self) -> None:
        """Upgrade 6.2: synthesize_mutant_killing_test generates a valid test for a hollow test on clamp(x, low, high)
        that kills 100% of surviving mutants when passed back into run_in_memory_mutation_gate.
        """
        clamp_source = """def clamp(x: int, low: int, high: int) -> int:
    if x < low:
        return low
    if x > high:
        return high
    return x
"""
        hollow_test = """def test_clamp_hollow():
    assert clamp(5, 0, 10) is not None
"""
        gate = run_in_memory_mutation_gate(clamp_source, hollow_test, target_function="clamp")
        self.assertFalse(gate.passed)
        survived = [m for m in gate.results if not m.killed]
        self.assertGreater(len(survived), 0, "Hollow test must leave surviving mutants")

        generated_test = synthesize_mutant_killing_test(clamp_source, "clamp", survived)
        self.assertIn("def test_clamp_cordis_invariants():", generated_test)
        self.assertIn("assert clamp(", generated_test)

        # Run mutation gate with the generated test and verify 100% mutation kill rate
        re_gate = run_in_memory_mutation_gate(clamp_source, generated_test, target_function="clamp")
        self.assertEqual(re_gate.survived_mutants, 0, f"All mutants must be killed, but survived: {[m.description for m in re_gate.results if not m.killed]}")
        self.assertEqual(re_gate.kill_rate, 1.0)
        self.assertTrue(re_gate.passed)

    def test_probe_cli_with_suggest_test_flag(self) -> None:
        """Upgrade 6.2 CLI: Test that cordis probe with --suggest-test outputs suggested tests and writes to JSON."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            src_file = tmp_root / "math_clamp.py"
            src_file.write_text("""def clamp(x: int, low: int, high: int) -> int:
    if x < low:
        return low
    if x > high:
        return high
    return x
""", encoding="utf-8")
            t_file = tmp_root / "test_clamp.py"
            t_file.write_text("""def test_clamp_weak():
    assert clamp(5, 0, 10) is not None
""", encoding="utf-8")

            json_out = tmp_root / "probe_suggest.json"
            stdout_capture = io.StringIO()
            with redirect_stdout(stdout_capture):
                ret = run_probe_cli(
                    repo=str(tmp_root),
                    target="math_clamp.py",
                    test="test_clamp.py",
                    function="clamp",
                    max_mutants=5,
                    output_json=str(json_out),
                    suggest_test=True,
                )

            output_str = stdout_capture.getvalue()
            self.assertIn("CORDIS COUNTEREXAMPLE-GUIDED TEST REPAIR SKELETON", output_str)
            self.assertIn("def test_clamp_cordis_invariants():", output_str)
            self.assertTrue(json_out.is_file())
            findings = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertIn("suggested_test", findings)
            self.assertIn("def test_clamp_cordis_invariants():", findings["suggested_test"])

    def test_repair_synthesizes_for_unhashable_collections_and_bytes(self) -> None:
        """Upgrade 6.2 robustness: synthesize_mutant_killing_test handles unhashable collections (lists/dicts/sets),
        bytes arguments, inf/nan return values, and class method instance binding without runtime errors.
        """
        # 1. Unhashable list argument
        src_list = """def sum_items(items: list) -> int:
    return sum(items)
"""
        surv_list = [MutantResult(1, "return None", 2, False, "")]
        test_list = synthesize_mutant_killing_test(src_list, "sum_items", surv_list)
        self.assertIn("def test_sum_items_cordis_invariants():", test_list)
        env: dict[str, Any] = {}
        exec(src_list, env)
        exec(test_list, env)
        env["test_sum_items_cordis_invariants"]()

        # 2. Bytes argument
        src_bytes = """def parse_header(data: bytes) -> bool:
    if data.startswith(b"PNG"):
        return True
    return False
"""
        gate_bytes = run_in_memory_mutation_gate(
            src_bytes,
            "def test_h():\n    assert parse_header(b'PNG') is not None\n",
            target_function="parse_header",
        )
        test_bytes = synthesize_mutant_killing_test(
            src_bytes,
            "parse_header",
            [m for m in gate_bytes.results if not m.killed],
        )
        self.assertIn("def test_parse_header_cordis_invariants():", test_bytes)
        env_b: dict[str, Any] = {}
        exec(src_bytes, env_b)
        exec(test_bytes, env_b)
        env_b["test_parse_header_cordis_invariants"]()

        # 3. Float inf and nan without NameError
        src_inf = "def get_inf(x: float) -> float:\n    return float('inf')\n"
        test_inf = synthesize_mutant_killing_test(src_inf, "get_inf", [MutantResult(1, "return None", 2, False, "")])
        self.assertIn("float('inf')", test_inf)
        env_i: dict[str, Any] = {}
        exec(src_inf, env_i)
        exec(test_inf, env_i)
        env_i["test_get_inf_cordis_invariants"]()

        src_nan = "def get_nan(x: float) -> float:\n    return float('nan')\n"
        test_nan = synthesize_mutant_killing_test(src_nan, "get_nan", [MutantResult(1, "return None", 2, False, "")])
        self.assertIn("import math", test_nan)
        self.assertIn("math.isnan", test_nan)
        env_n: dict[str, Any] = {}
        exec(src_nan, env_n)
        exec(test_nan, env_n)
        env_n["test_get_nan_cordis_invariants"]()

        # 4. Class method instance binding
        src_calc = """class Calculator:
    def add(self, a: int, b: int) -> int:
        return a + b
"""
        test_calc = synthesize_mutant_killing_test(src_calc, "Calculator.add", [MutantResult(1, "return None", 3, False, "")])
        self.assertIn("Calculator().add(", test_calc)
        env_c: dict[str, Any] = {}
        exec(src_calc, env_c)
        exec(test_calc, env_c)
        env_c["test_Calculator_add_cordis_invariants"]()

        # 5. Deduced target_function when empty
        test_deduced = synthesize_mutant_killing_test(src_list, "", surv_list)
        self.assertIn("def test_sum_items_cordis_invariants():", test_deduced)

    def test_differential_fuzzer_handles_nan_in_nested_collections_and_arity_4(self) -> None:
        """Upgrade 4.1: differential fuzzer compares nested collections with IEEE-754 NaN awareness
        and exercises arity >= 4 combinatorial parameter exploration.
        """
        # 1. NaN in collections: identical functions must PASS without false positive
        def f_ref_nan(x):
            return [x, float("nan"), {"key": float("nan")}]

        def f_cand_nan(x):
            return [x, float("nan"), {"key": float("nan")}]

        rep_nan = run_differential_fuzz_gate(f_ref_nan, f_cand_nan, num_samples=50)
        self.assertTrue(rep_nan.passed, f"Differential fuzzer must pass on identical collections with NaN, got {rep_nan.counterexamples}")

        # 2. Arity 4 combinatorial pairing catches multi-parameter conditional overfit
        def f_ref_arity4(a: int, b: int, c: int, d: int) -> int:
            return a + b + c + d

        def f_cand_arity4(a: int, b: int, c: int, d: int) -> int:
            if a == 1 and b == 2:
                return 9999
            return a + b + c + d

        rep_arity4 = run_differential_fuzz_gate(f_ref_arity4, f_cand_arity4, num_samples=100)
        self.assertFalse(rep_arity4.passed, "Differential fuzzer must catch arity=4 conditional overfit")
        self.assertTrue(any(cx.args[:2] == (1, 2) for cx in rep_arity4.counterexamples))

    def test_harvest_ast_constants_unwraps_partials_and_callable_objects(self) -> None:
        """Upgrade 4.1: harvest_ast_constants correctly unrolls functools.partial, callable objects,
        and generates multi-hop buffer string/bytes constants.
        """
        import functools

        def base_fn(x):
            if x == 42857:
                return 999
            return x

        part_fn = functools.partial(base_fn)
        h_part = harvest_ast_constants([part_fn])
        self.assertIn(42857, h_part["int"])

        # Callable class instance
        class CallableModel:
            def __call__(self, x):
                if x == 98765:
                    return 0
                return x

        m = CallableModel()
        h_model = harvest_ast_constants([m])
        self.assertIn(98765, h_model["int"])

        # Buffer constants multi-hop boundary seeding
        def buffer_fn(buf):
            if len(buf) > 1024:
                return True
            return False

        h_buf = harvest_ast_constants([buffer_fn])
        self.assertIn(1024, h_buf["int"])
        self.assertIn("a" * 1024, h_buf["str"])
        self.assertIn("a" * 2049, h_buf["str"])  # 2 * 1024 + 1 multi-hop probing
        self.assertIn(b"a" * 1024, h_buf["bytes"])


class TestCordisHookGuards(unittest.TestCase):
    """Engine 1 Upgrade 1.1 and Engine 6 Upgrade 6.1:
    Deterministic Hook Guards, Conseca Pre-Tool Firewall, Stop Hook Prosecutor,
    Attestation Receipts, and Policy Enforcement.
    """

    def test_pre_tool_audit_blocks_all_6_bypass_vectors(self) -> None:
        """Verifies audit_pre_tool_use_command catches all 6 bypass vectors from anthropics/claude-code#40117."""
        # Vector 1: --no-verify flag
        v1_commands = [
            'git commit -m "bypass" --no-verify',
            'git commit --no-verify -m "bypass"',
            'git commit -a --no-verify -m "bypass"',
            'git commit --no-ver -m "bypass"',
            'git -C . commit -m "x" --no-verify',
            'git commit --NO-VERIFY -m "x"',
        ]
        for cmd in v1_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertFalse(dec.allowed, f"Expected '{cmd}' to be blocked")
            self.assertEqual(dec.exit_code, 2)
            self.assertEqual(dec.vector, "NO_VERIFY")
            self.assertTrue(bool(dec.reason))

        # Vector 2: short -n flag and bundled flag variants
        v2_commands = [
            'git commit -nm "bypass"',
            'git commit -mn "bypass"',
            'git commit -m "bypass" -n',
            'git commit -n -m "bypass"',
            'git commit -am "bypass" -n',
            'git commit -anm "bypass"',
            'git commit -man "bypass"',
            '"git" commit -n',
            'git commit -m"bypass" -n',
        ]
        for cmd in v2_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertFalse(dec.allowed, f"Expected '{cmd}' to be blocked")
            self.assertEqual(dec.exit_code, 2)
            self.assertEqual(dec.vector, "NO_VERIFY")
            self.assertTrue(bool(dec.reason))

        # Vector 3: core.hooksPath override / redirection
        v3_commands = [
            'git -c core.hooksPath=/dev/null commit',
            'git -c core.hooksPath=/dev/null commit -m "bypass"',
            'git -c core.hooksPath="" commit -m "bypass"',
            'git -c "core.hooksPath=/dev/null" commit -m "bypass"',
            'git config core.hooksPath /dev/null',
            'git config core.hooksPath ""',
            'git config --local core.hooksPath /dev/null',
        ]
        for cmd in v3_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertFalse(dec.allowed, f"Expected '{cmd}' to be blocked")
            self.assertEqual(dec.exit_code, 2)
            self.assertEqual(dec.vector, "HOOKS_PATH_OVERRIDE")
            self.assertTrue(bool(dec.reason))

        # Vector 4: Deleting, modifying or stripping executable permissions on hooks
        v4_commands = [
            'rm -f .git/hooks/pre-commit',
            'rm .git/hooks/pre-commit',
            'rm -rf .git/hooks',
            'del .git\\hooks\\pre-commit',
            'del /f .git\\hooks\\pre-commit',
            'del /f /q .git\\hooks\\*',
            'chmod -x .git/hooks/pre-commit',
            'rm -rf .claude/hooks',
        ]
        for cmd in v4_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertFalse(dec.allowed, f"Expected '{cmd}' to be blocked")
            self.assertEqual(dec.exit_code, 2)
            self.assertEqual(dec.vector, "HOOKS_TAMPERING")
            self.assertTrue(bool(dec.reason))

        # Vector 5: Subshell / embedded execution wrappers
        v5_commands = [
            'python -c "import os; os.system(\'git commit -n -m x\')"',
            'python3 -c "import subprocess; subprocess.run([\'git\', \'commit\', \'--no-verify\'])"',
            'powershell -Command "git commit -n -m x"',
            'powershell -Command "git commit --no-verify -m \'msg\'"',
            'powershell.exe -Command "git commit --no-verify"',
            'bash -c "git commit -nm bypass"',
        ]
        for cmd in v5_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertFalse(dec.allowed, f"Expected embedded wrapper '{cmd}' to be blocked")
            self.assertEqual(dec.exit_code, 2)
            self.assertEqual(dec.vector, "EMBEDDED_SUBVERSION")
            self.assertTrue(bool(dec.reason))

        # Vector 6: git stash --keep-index hiding modifications
        v6_commands = [
            'git stash --keep-index',
            'git stash push --keep-index',
            'git stash push -k -m "hide"',
            'git stash -k',
            'git stash push -k',
            'git stash --KEEP-INDEX',
        ]
        for cmd in v6_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertFalse(dec.allowed, f"Expected '{cmd}' to be blocked")
            self.assertEqual(dec.exit_code, 2)
            self.assertEqual(dec.vector, "STASH_KEEP_INDEX")
            self.assertTrue(bool(dec.reason))

        # Chained / pipeline circumvention
        chained_commands = [
            'git add . && git commit -m "x" --no-verify',
            'git add . && git commit -m "x" --no-verify -q',
        ]
        for cmd in chained_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertFalse(dec.allowed, f"Expected chained pipeline '{cmd}' to be blocked")
            self.assertEqual(dec.exit_code, 2)

    def test_pre_tool_audit_permits_legitimate_commands(self) -> None:
        """Verifies audit_pre_tool_use_command allows clean development commands."""
        legit_commands = [
            'git commit -m "feat: add parser"',
            'git commit -m "fix: resolve -n parameter in test"',
            'git commit -am "feat: improve test coverage"',
            'git commit -m "docs: core.hooksPath guide"',
            'git commit -m"feat: clean attached message"',
            'git log -n 5',
            'head -n 10 file.txt',
            'git diff',
            'git diff HEAD~1',
            'git add .',
            'git status',
            'git stash',
            'git stash pop',
            'python -m unittest discover -s tests -v',
            'pytest tests/',
            'python -c "import sys; print(sys.version)"',
            '',
            '   ',
        ]
        for cmd in legit_commands:
            dec = audit_pre_tool_use_command(cmd)
            self.assertTrue(dec.allowed, f"Expected legitimate command '{cmd}' to be allowed, got blocked: {dec.reason}")
            self.assertEqual(dec.exit_code, 0)
            self.assertIsNone(dec.vector)

    def test_stop_hook_clean_tree_fast_path_latency(self) -> None:
        """Verifies clean working tree exits 0 in <10ms."""
        import time

        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Verify in-memory clean diff report completes in <10ms
            with patch("cordis.hooks.extract_git_diff") as mock_diff:
                mock_diff.return_value = GitDiffReport(
                    base_ref="HEAD",
                    target_ref=None,
                    source_files=[],
                    test_files=[],
                    modified_functions=[],
                    raw_diff="",
                )
                t0 = time.perf_counter()
                rc = run_stop_hook_prosecutor(repo_dir=tmp_dir)
                elapsed = time.perf_counter() - t0

                self.assertEqual(rc, 0)
                self.assertLess(elapsed, 0.010, f"Expected clean working tree to finish in <10ms, took {elapsed*1000:.2f}ms")

            # 2. Verify with real initialized clean git repository
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            (Path(tmp_dir) / "app.py").write_text("def fn(): return 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            rc_clean = run_stop_hook_prosecutor(repo_dir=tmp_dir)
            self.assertEqual(rc_clean, 0)

    def test_stop_hook_circuit_breaker_and_bounded_remediation(self) -> None:
        """Verifies 3-strike circuit breaker and bounded <25-line stderr remediation block."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            src = p / "calc.py"
            src.write_text("def clamp(x: int, low: int, high: int) -> int:\n    if x < low:\n        return low\n    if x > high:\n        return high\n    return x\n", encoding="utf-8")
            t_file = p / "test_calc.py"
            t_file.write_text("from calc import clamp\ndef test_clamp():\n    assert clamp(5, 0, 10) == 5\n    assert clamp(-5, 0, 10) == 0\n    assert clamp(15, 0, 10) == 10\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "baseline"], cwd=tmp_dir, check=True, capture_output=True)

            # Uncommitted modification with a weakened test causing Gate 1 failure
            t_file.write_text("from calc import clamp\ndef test_clamp():\n    assert clamp(5, 0, 10) is not None\n", encoding="utf-8")

            # Strikes 1 and 2: Bounded remediation block
            for strike in (1, 2):
                err_buf = io.StringIO()
                with redirect_stderr(err_buf):
                    rc = run_stop_hook_prosecutor(repo_dir=tmp_dir, max_retries=3)
                err_text = err_buf.getvalue()
                lines = [l for l in err_text.strip().splitlines() if l.strip()]

                self.assertEqual(rc, 2)
                self.assertLessEqual(len(lines), 25, f"Remediation block exceeded 25 lines (got {len(lines)})")
                self.assertIn("🛑 [Cordis Stop Hook Blocked]", err_text)
                self.assertIn(f"Strike {strike}/3", err_text)

            # Strike 3: Circuit breaker tripped with NEEDS_HUMAN_ARBITRATION
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                rc_tripped = run_stop_hook_prosecutor(repo_dir=tmp_dir, max_retries=3)
            tripped_text = err_buf.getvalue()
            tripped_lines = [l for l in tripped_text.strip().splitlines() if l.strip()]

            self.assertEqual(rc_tripped, 2)
            self.assertLessEqual(len(tripped_lines), 25, f"Tripped block exceeded 25 lines (got {len(tripped_lines)})")
            self.assertIn("CIRCUIT BREAKER TRIGGERED", tripped_text)
            self.assertIn("NEEDS_HUMAN_ARBITRATION", tripped_text)

    def test_stop_hook_successful_attestation_receipt(self) -> None:
        """Verifies .cordis_attestation.json creation with 64-bit BLAKE2b digest on passing gates."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            src = p / "calc.py"
            src.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
            t_file = p / "test_calc.py"
            t_file.write_text("from calc import add\ndef test_add():\n    assert add(1, 2) == 3\n    assert add(0, 0) == 0\n    assert add(-1, 1) == 0\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Uncommitted genuine modification with strong tests that kill all mutants
            src.write_text("def add(a: int, b: int) -> int:\n    return (a + b) * 1\n", encoding="utf-8")
            t_file.write_text("from calc import add\ndef test_add():\n    assert add(1, 2) == 3\n    assert add(0, 0) == 0\n    assert add(-1, 1) == 0\n    assert add(2, 3) == 5\n", encoding="utf-8")

            rc = run_stop_hook_prosecutor(repo_dir=tmp_dir)
            self.assertEqual(rc, 0)

            att_file = p / ".cordis_attestation.json"
            self.assertTrue(att_file.is_file(), "Expected .cordis_attestation.json to be created")
            data = json.loads(att_file.read_text(encoding="utf-8"))

            self.assertEqual(data["status"], "PASSED")
            self.assertEqual(data["gate2_kill_rate"], 1.0)
            self.assertIn("digest", data)
            self.assertEqual(len(data["digest"]), 16)
            self.assertIn("calc.py::add", data["modified_anchors"])

            expected_digest = compute_diff_attestation_digest(data["modified_anchors"], 1.0)
            self.assertEqual(data["digest"], expected_digest)

    def test_diff_attestation_digest_and_commit_trailer(self) -> None:
        """Verifies deterministic 64-bit BLAKE2b digest and trailer verification."""
        import hashlib

        # Empty diff digest matches BLAKE2b over EMPTY_DIFF:1.0000
        d_empty = compute_diff_attestation_digest({})
        self.assertEqual(len(d_empty), 16)
        expected_empty = hashlib.blake2b(b"EMPTY_DIFF:1.0000", digest_size=8).hexdigest()
        self.assertEqual(d_empty, expected_empty)

        # Lexicographical sort invariance
        anchors_a = {
            "cordis/mutator.py::mutate": "¶cordis/mutator.py#1122334455667788",
            "cordis/ast_gate.py::audit": "¶cordis/ast_gate.py#99aabbccddeeff00",
        }
        anchors_b = {
            "cordis/ast_gate.py::audit": "¶cordis/ast_gate.py#99aabbccddeeff00",
            "cordis/mutator.py::mutate": "¶cordis/mutator.py#1122334455667788",
        }
        self.assertEqual(compute_diff_attestation_digest(anchors_a), compute_diff_attestation_digest(anchors_b))

        digest = "4a7b9c2d1e0f3a5b"
        # Standard format with pilcrow
        self.assertTrue(verify_commit_attestation_trailer(f"feat: update\n\nCordis-Attestation: ¶{digest}", digest))
        # Format without pilcrow
        self.assertTrue(verify_commit_attestation_trailer(f"feat: update\n\nCordis-Attestation: {digest}", digest))
        # Case insensitivity
        self.assertTrue(verify_commit_attestation_trailer(f"feat: update\n\nCordis-Attestation: ¶{digest.upper()}", digest))
        # Trailer key case-insensitivity (lowercase and uppercase key)
        self.assertTrue(verify_commit_attestation_trailer("feat: update\n\ncordis-attestation: ¶3f8a9b2c1d0e4f5a", "3f8a9b2c1d0e4f5a"))
        self.assertTrue(verify_commit_attestation_trailer("feat: update\n\nCORDIS-ATTESTATION: ¶3f8a9b2c1d0e4f5a", "3f8a9b2c1d0e4f5a"))
        # Overlong trailer length boundary (>16 hex)
        self.assertFalse(verify_commit_attestation_trailer("feat: update\n\nCordis-Attestation: ¶3f8a9b2c1d0e4f5adeadbeef", "3f8a9b2c1d0e4f5a"))
        # Mismatched digest
        self.assertFalse(verify_commit_attestation_trailer(f"feat: update\n\nCordis-Attestation: ¶0000000000000000", digest))
        # No trailer
        self.assertFalse(verify_commit_attestation_trailer("feat: update without trailer", digest))

    def test_policy_guard_detects_hook_tampering_and_overrides(self) -> None:
        """Verifies audit_repository_policy flags disabled pre-commit and core.hooksPath overrides."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / ".git").mkdir()

            # 1. Overridden core.hooksPath = /dev/null
            (p / ".git" / "config").write_text("[core]\n\thooksPath = /dev/null\n", encoding="utf-8")
            rep1 = audit_repository_policy(p)
            self.assertEqual(rep1.status, "BLOCKED_POLICY")
            self.assertTrue(any("[HOOK_TAMPERING]: git core.hooksPath" in c for c in rep1.citations))

            # 2. Reset config and test empty pre-commit
            (p / ".git" / "config").write_text("[core]\n", encoding="utf-8")
            hooks_dir = p / ".git" / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            pre_commit = hooks_dir / "pre-commit"
            pre_commit.write_text("", encoding="utf-8")

            rep2 = audit_repository_policy(p)
            self.assertEqual(rep2.status, "BLOCKED_POLICY")
            self.assertTrue(any("[HOOK_TAMPERING]: .git/hooks/pre-commit" in c for c in rep2.citations))

            # 3. Non-git directory gracefully skips hook check
            with tempfile.TemporaryDirectory() as plain_dir:
                rep3 = audit_repository_policy(plain_dir)
                self.assertEqual(rep3.status, "PERMITTED")

    def test_cli_hooks_subcommand_dispatch(self) -> None:
        """Verifies CLI properly dispatches cordis hooks check-cmd, stop-gate, and install."""
        # 1. check-cmd blocking bypass
        with patch.object(sys, "argv", ["cordis", "hooks", "check-cmd", "--command", "git commit -m 'x' --no-verify"]):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                self.assertEqual(main(), 2)
            self.assertIn("🛑 [Cordis Pre-Tool Guard]: BLOCKED", err_buf.getvalue())

        # 2. check-cmd permitting legitimate command
        with patch.object(sys, "argv", ["cordis", "hooks", "check-cmd", "--command", "git commit -m 'feat: clean'"]):
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                self.assertEqual(main(), 0)
            self.assertIn("✅ [Cordis Pre-Tool Guard]: PERMITTED", out_buf.getvalue())

        # 3. install hooks creates pre-commit and claude settings
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            with patch.object(sys, "argv", ["cordis", "hooks", "install", "--repo-dir", tmp_dir, "--targets", "git", "claude"]):
                out_buf = io.StringIO()
                with redirect_stdout(out_buf):
                    self.assertEqual(main(), 0)
            self.assertIn("✅ [Cordis Hooks Installed]: 2 hook target(s) configured.", out_buf.getvalue())
            self.assertTrue((Path(tmp_dir) / ".git" / "hooks" / "pre-commit").is_file())
            self.assertTrue((Path(tmp_dir) / ".claude" / "settings.local.json").is_file())

        # 4. stop-gate exits 0 on clean repo
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)
            with patch.object(sys, "argv", ["cordis", "hooks", "stop-gate", "--repo-dir", tmp_dir]):
                self.assertEqual(main(), 0)

        # 5. Argument isolation test: ensure --command did not clobber args.command
        import argparse
        test_parser = argparse.ArgumentParser()
        test_sub = test_parser.add_subparsers(dest="command")
        h_p = test_sub.add_parser("hooks")
        h_sub = h_p.add_subparsers(dest="hooks_command")
        c_p = h_sub.add_parser("check-cmd")
        c_p.add_argument("--command", "-c", dest="command_to_check", required=True)

        parsed = test_parser.parse_args(["hooks", "check-cmd", "--command", "git commit -m x --no-verify"])
        self.assertEqual(parsed.command, "hooks")
        self.assertEqual(parsed.hooks_command, "check-cmd")
        self.assertEqual(parsed.command_to_check, "git commit -m x --no-verify")

        # 6. hooks without subcommand prints help and returns 1
        with patch.object(sys, "argv", ["cordis", "hooks"]):
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                self.assertEqual(main(), 1)


class TestTypeScriptASTGate(unittest.TestCase):
    """Engine 7: Zero-Dependency TypeScript / JavaScript / Jest / Vitest AST Gate Tests."""

    def test_ts_ast_anchor_indexing(self) -> None:
        code = """
        function calculateTotal(items: number[]): number {
            return items.reduce((a, b) => a + b, 0);
        }

        export const parseDiscount = async (tier: string): Promise<number> => {
            if (tier === "VIP") return 0.20;
            return 0.05;
        };

        class Calculator {
            multiply(x: number, y: number): number {
                return x * y;
            }
        }
        """
        anchors = index_ts_ast_anchors(code, file_path="service.ts")
        self.assertIn("calculateTotal", anchors)
        self.assertIn("parseDiscount", anchors)
        self.assertIn("Calculator.multiply", anchors)
        self.assertEqual(len(anchors["calculateTotal"].hash_tag), 16)
        self.assertTrue(anchors["calculateTotal"].tag.startswith("¶service.ts#"))
        self.assertNotEqual(anchors["calculateTotal"].hash_tag, anchors["parseDiscount"].hash_tag)
        self.assertIn(anchors["calculateTotal"].tag, anchors)
        self.assertEqual(anchors[anchors["calculateTotal"].tag].identifier, "calculateTotal")

    def test_ts_test_tampering_catches_weakened_asserts(self) -> None:
        old_test = """
        test("calculates fee", () => {
            expect(computeFee(100)).toBe(15);
            expect(computeFee(0)).toEqual(0);
        });
        """
        tampered_test = """
        test("calculates fee", () => {
            expect(computeFee(100)).toBeDefined();
            expect(computeFee(0)).not.toBeNull();
        });
        """
        report = audit_ts_test_tampering(old_test, tampered_test, target_function_names=["computeFee"])
        self.assertFalse(report.passed)
        self.assertTrue(any("weakened" in v.lower() for v in report.violations))

    def test_ts_test_tampering_catches_tautologies(self) -> None:
        old_test = "test('foo', () => { expect(foo()).toBe(42); });"
        tampered_test = "test('foo', () => { expect(true).toBe(true); });"
        report = audit_ts_test_tampering(old_test, tampered_test)
        self.assertFalse(report.passed)
        self.assertTrue(any("tautological" in v.lower() for v in report.violations))

        # Also verify self-comparison tautology expect(x).toBe(x)
        tampered_test2 = "test('foo', () => { const x = foo(); expect(x).toBe(x); });"
        report2 = audit_ts_test_tampering(old_test, tampered_test2)
        self.assertFalse(report2.passed)
        self.assertTrue(any("tautological" in v.lower() for v in report2.violations))

    def test_ts_test_tampering_catches_mocks_and_skips(self) -> None:
        old_test = """
        test("process order", () => {
            expect(processOrder("123")).toBe(true);
        });
        """
        tampered_test = """
        import { vi } from "vitest";
        vi.mock("./orderService", () => ({ processOrder: vi.fn() }));

        test.skip("process order", () => {
            expect(processOrder("123")).toBe(true);
        });
        """
        report = audit_ts_test_tampering(old_test, tampered_test, target_function_names=["processOrder"])
        self.assertFalse(report.passed)
        self.assertTrue(any("mock" in v.lower() for v in report.violations))
        self.assertTrue(any("skip" in v.lower() for v in report.violations))

    def test_ts_mar_calculation_and_boundary_classification(self) -> None:
        test_code = """
        import { vi } from "vitest";
        vi.mock("axios");
        vi.mock("node:fs");
        vi.mock("./internalService");

        test("demo", () => {
            expect(1).toBe(1);
            expect(2).toBe(2);
        });
        """
        report = audit_ts_test_tampering("", test_code)
        self.assertEqual(report.total_mocks, 3)
        self.assertEqual(report.boundary_mock_count, 2)  # axios, node:fs
        self.assertEqual(report.internal_mock_count, 1)  # ./internalService
        self.assertGreater(report.mar, 0)
        self.assertGreater(report.weighted_mar, 0)

    def test_generate_ts_mutants(self) -> None:
        code = """
        function isValid(a: number, b: number): boolean {
            if (a === b && a >= 0) {
                return true;
            }
            return false;
        }
        """
        mutants = generate_ts_mutants(code, target_function="isValid", max_mutants=5)
        self.assertGreater(len(mutants), 0)
        descriptions = [m[0] for m in mutants]
        mutated_snippets = [m[2] for m in mutants]
        self.assertTrue(
            any("!==" in snip for snip in mutated_snippets)
            or any("||" in snip for snip in mutated_snippets)
            or any("null" in snip for snip in mutated_snippets)
        )

    def test_git_diff_supports_ts_files(self) -> None:
        self.assertTrue(is_test_file("src/service.test.ts"))
        self.assertTrue(is_test_file("tests/service.spec.tsx"))
        self.assertFalse(is_test_file("src/service.ts"))

        diff = """diff --git a/src/math.ts b/src/math.ts
--- a/src/math.ts
+++ b/src/math.ts
@@ -1,3 +1,3 @@
-function add(a: number, b: number): number { return a + b; }
+function add(a: number, b: number): number { return a + b + 1; }
"""
        report = parse_git_diff_text(
            diff,
            file_reader=lambda _: "function add(a: number, b: number): number { return a + b + 1; }"
        )
        self.assertEqual(report.source_files, ["src/math.ts"])
        self.assertIn("add", report.target_function_names)

    def test_ts_lexical_scanner_handles_escapes_and_nested_templates(self) -> None:
        ts_code = 'const msg = `hello ${"escaped \\` quotes" + ` nested ${count}`} world`; // comment with "quotes"'
        masked = mask_ts_code(ts_code, mask_strings=True)
        self.assertEqual(len(masked), len(ts_code))
        self.assertNotIn("comment", masked)
        self.assertNotIn("hello", masked)
        # Verify newline count preserved
        multi_line = "/* line 1\nline 2\nline 3 */\nconst x = 1;"
        masked_multi = mask_ts_code(multi_line)
        self.assertEqual(masked_multi.count("\n"), multi_line.count("\n"))
        self.assertTrue(masked_multi.endswith("const x = 1;"))

    def test_cli_verify_git_with_ts_tampered_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            # Base commit with strong TS test
            t_file = Path(tmp_dir) / "service.test.ts"
            t_file.write_text("test('fee', () => { expect(computeFee(10)).toBe(1); });", encoding="utf-8")
            subprocess.run(["git", "add", "service.test.ts"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_dir, check=True, capture_output=True)

            # Working tree has tampered test (weakened)
            t_file.write_text("test('fee', () => { expect(computeFee(10)).toBeDefined(); });", encoding="utf-8")

            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                exit_code = run_verify_git(repo_dir=tmp_dir)
            self.assertEqual(exit_code, 1)
            self.assertIn("Gate 1 Test-Tampering", out_buf.getvalue())
            self.assertIn("FAIL", out_buf.getvalue())

    def test_ts_test_tampering_catches_relational_tautologies(self) -> None:
        old_test = "test('foo', () => { expect(compute(10)).toBe(20); });"
        cases = [
            "expect(res.status === res.status).toBe(true)",
            "expect(a == a).toBe(true)",
            "expect(a <= a).toBe(true)",
            "expect(x !== x).toBe(false)",
            "expect(x != x).toBe(false)",
            "expect(res.getStatus() === res.getStatus()).toBe(true)",
            "expect(a === a).toBeTruthy()",
            "expect(a !== a).toBeFalsy()",
        ]
        for c in cases:
            tampered_test = f"test('taut', () => {{ {c}; }});"
            report = audit_ts_test_tampering(old_test, tampered_test)
            self.assertFalse(report.passed, f"Failed to block tautology: {c}")
            self.assertTrue(
                any("tautological" in v.lower() for v in report.violations),
                f"Missing tautological violation for: {c}",
            )

    def test_ts_test_tampering_semicolon_less_mock_isolation(self) -> None:
        code = """
        it('calculates with mock', () => {
            vi.spyOn(service, 'otherHelper')
            expect(calculateDiscount(100)).toBe(10)
        })
        """
        report = audit_ts_test_tampering("", code, target_function_names=["calculateDiscount"])
        self.assertTrue(report.passed, f"False positive mock abuse reported: {report.violations}")
        self.assertEqual(len(report.violations), 0)

    def test_cli_verify_git_fallback_base_ref_single_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            # Single commit repository (HEAD~1 does not exist)
            t_file = Path(tmp_dir) / "calc.test.ts"
            t_file.write_text("test('fee', () => {\n  expect(calc(10)).toBe(1);\n  expect(calc(20)).toBe(2);\n});", encoding="utf-8")
            subprocess.run(["git", "add", "calc.test.ts"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_dir, check=True, capture_output=True)

            # Working tree has tampered test: 1 strong assert dropped
            t_file.write_text("test('fee', () => {\n  expect(calc(10)).toBe(1);\n  expect(calc(20)).toBeDefined();\n});", encoding="utf-8")

            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                exit_code = run_verify_git(repo_dir=tmp_dir)
            self.assertEqual(exit_code, 1)
            self.assertIn("Gate 1 Test-Tampering", out_buf.getvalue())
            self.assertIn("FAIL", out_buf.getvalue())


if __name__ == "__main__":
    unittest.main()



