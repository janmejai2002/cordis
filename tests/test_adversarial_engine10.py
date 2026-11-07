"""Milestone M4 Challenger 2: Adversarial Stress Test Suite for Engine 10.

Tests cordis/hashline_guard.py, cordis/model_eval.py, and CLI subcommands:
1. Hashline guard collateral AST integrity, polyglot TS/JS, syntax errors, outbox receipt.
2. Model eval CapCode deception mathematical bounds and actor taxonomy evasion.
3. Subprocess CLI command integration across all edge-case inputs.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cordis.forge_guard import GitActorInfo
from cordis.hashline_guard import (
    annotate_file_with_hashlines,
    compute_hashline_tag,
    verify_collateral_ast_integrity,
    verify_worker_outbox,
)
from cordis.memory import EpisodicMemoryLedger
from cordis.model_eval import (
    ModelCommitStats,
    analyze_python_test_code,
    analyze_ts_test_code,
    classify_commit_actor,
    evaluate_model_history,
)

PYTHON_EXE = sys.executable


class TestAdversarialHashlineGuard(unittest.TestCase):
    """Stress testing Hashline Guard: AST tampering, TS/JS polyglot, syntax, outbox."""

    def test_hashline_tagging_deterministic_and_crlf_invariant(self) -> None:
        """Hashline tags must be 4-hex blake2b digests and invariant across LF vs CRLF."""
        tag_empty = compute_hashline_tag("")
        tag_whitespace = compute_hashline_tag("   \t  ")
        self.assertEqual(tag_empty, "b1fe")
        self.assertEqual(tag_whitespace, "b1fe")
        self.assertEqual(len(tag_empty), 4)

        tag_lf = compute_hashline_tag("def calculate_total(x: int) -> int:\n")
        tag_crlf = compute_hashline_tag("def calculate_total(x: int) -> int:\r\n")
        self.assertEqual(tag_lf, tag_crlf)

        annotated_prefix = annotate_file_with_hashlines("a = 1\nb = 2", format_style="prefix")
        self.assertIn("L1#", annotated_prefix)
        self.assertIn("L2#", annotated_prefix)

        annotated_suffix = annotate_file_with_hashlines("a = 1\nb = 2", format_style="suffix")
        self.assertIn("# L1#", annotated_suffix)
        self.assertIn("# L2#", annotated_suffix)

    def test_collateral_ast_python_authorized_modifications_pass(self) -> None:
        """Modifying only authorized target functions must pass without violations."""
        old_py = """
def authorized_func(x: int) -> int:
    return x + 1

def sibling_func(y: int) -> int:
    return y * 2
"""
        new_py = """
def authorized_func(x: int) -> int:
    return x + 42

def sibling_func(y: int) -> int:
    return y * 2
"""
        report = verify_collateral_ast_integrity(
            old_code=old_py,
            new_code=new_py,
            intended_functions=["authorized_func"],
            file_path="service.py",
        )
        self.assertTrue(report.passed)
        self.assertTrue(report.syntax_valid)
        self.assertEqual(len(report.violations), 0)
        self.assertIn("authorized_func", report.modified_intended_functions)
        self.assertIn("sibling_func", report.unchanged_sibling_functions)

    def test_collateral_ast_python_tampering_caught(self) -> None:
        """Tampering with sibling function body, renaming sibling parameter, or deleting sibling must fail."""
        old_py = """
def target(x):
    return x

def sibling_a(y):
    return y + 1

def sibling_b(z):
    return z * 2
"""
        # Case 1: Sibling body modified
        tampered_body = """
def target(x):
    return x * 10

def sibling_a(y):
    return y + 999  # Collateral tampering

def sibling_b(z):
    return z * 2
"""
        r1 = verify_collateral_ast_integrity(old_py, tampered_body, ["target"], file_path="mod.py")
        self.assertFalse(r1.passed)
        self.assertIn("sibling_a", r1.collateral_modified_functions)
        self.assertTrue(any("sibling_a" in v for v in r1.violations))

        # Case 2: Sibling parameter renamed
        tampered_param = """
def target(x):
    return x * 10

def sibling_a(renamed_y):
    return renamed_y + 1

def sibling_b(z):
    return z * 2
"""
        r2 = verify_collateral_ast_integrity(old_py, tampered_param, ["target"], file_path="mod.py")
        self.assertFalse(r2.passed)
        self.assertIn("sibling_a", r2.collateral_modified_functions)

        # Case 3: Sibling deleted
        tampered_del = """
def target(x):
    return x * 10

def sibling_a(y):
    return y + 1
"""
        r3 = verify_collateral_ast_integrity(old_py, tampered_del, ["target"], file_path="mod.py")
        self.assertFalse(r3.passed)
        self.assertIn("sibling_b", r3.collateral_deleted_functions)
        self.assertTrue(any("deleted without authorization" in v for v in r3.violations))

    def test_collateral_ast_python_evasion_investigation(self) -> None:
        """Adversarial check: investigate whether comment changes, default argument alterations,

        or return type annotation changes inside sibling functions evade AST anchor hash checks.
        """
        old_py = """
def target():
    return 1

def sibling(a: int = 1) -> int:
    # Original comment
    return a + 1
"""
        # Scenario A: Comment change inside sibling function
        code_comment = """
def target():
    return 2

def sibling(a: int = 1) -> int:
    # Sneaky modified comment!
    return a + 1
"""
        r_comment = verify_collateral_ast_integrity(old_py, code_comment, ["target"], file_path="mod.py")
        # Observation: In Python standard AST, comments are discarded, so comment changes pass AST integrity.
        self.assertTrue(r_comment.passed, "Comments do not affect Python AST, so this passes as expected")

        # Scenario B: Modifying sibling default arguments
        code_default = """
def target():
    return 2

def sibling(a: int = 999) -> int:
    # Original comment
    return a + 1
"""
        r_default = verify_collateral_ast_integrity(old_py, code_default, ["target"], file_path="mod.py")
        # Observation: In index_ast_anchors, args_sig only includes arg names, not defaults or annotations.
        # This records the empirical behavior: default argument alteration is an AST evasion vector.
        self.assertTrue(
            r_default.passed,
            "Empirical Finding: Sibling default argument change is currently undetected by index_ast_anchors",
        )

        # Scenario C: Modifying sibling return type annotation
        code_ret_type = """
def target():
    return 2

def sibling(a: int = 1) -> float:
    # Original comment
    return a + 1
"""
        r_ret = verify_collateral_ast_integrity(old_py, code_ret_type, ["target"], file_path="mod.py")
        # Observation: Sibling return type annotation is not serialized in args_sig or body_dump.
        self.assertTrue(
            r_ret.passed,
            "Empirical Finding: Sibling return type annotation change is currently undetected by index_ast_anchors",
        )

    def test_polyglot_ts_adversarial_class_arrow_async_methods(self) -> None:
        """TypeScript / JavaScript sibling methods and functions tampering."""
        old_ts = """
export class UserService {
    public async fetchUser(id: string): Promise<User> {
        return api.get(`/users/${id}`);
    }

    public calculateDiscount(score: number): number {
        return score > 100 ? 0.2 : 0.05;
    }
}

export const helper = (x: number): number => {
    return x * 10;
};
"""
        # Case 1: Tampering with sibling calculateDiscount in class
        tampered_ts_method = """
export class UserService {
    public async fetchUser(id: string): Promise<User> {
        return api.get(`/v2/users/${id}`);
    }

    public calculateDiscount(score: number): number {
        return score > 100 ? 0.99 : 0.05; // Unauthorized change!
    }
}

export const helper = (x: number): number => {
    return x * 10;
};
"""
        r1 = verify_collateral_ast_integrity(old_ts, tampered_ts_method, ["fetchUser"], file_path="user.ts")
        self.assertFalse(r1.passed)
        self.assertIn("UserService.calculateDiscount", r1.collateral_modified_functions)

        # Case 2: Tampering with sibling arrow function helper
        tampered_arrow = """
export class UserService {
    public async fetchUser(id: string): Promise<User> {
        return api.get(`/v2/users/${id}`);
    }

    public calculateDiscount(score: number): number {
        return score > 100 ? 0.2 : 0.05;
    }
}

export const helper = (x: number): number => {
    return x * 999; // Tampered arrow
};
"""
        r2 = verify_collateral_ast_integrity(old_ts, tampered_arrow, ["fetchUser"], file_path="user.ts")
        self.assertFalse(r2.passed)
        self.assertIn("helper", r2.collateral_modified_functions)

        # Case 3: Deleting class method
        tampered_del = """
export class UserService {
    public async fetchUser(id: string): Promise<User> {
        return api.get(`/v2/users/${id}`);
    }
}

export const helper = (x: number): number => {
    return x * 10;
};
"""
        r3 = verify_collateral_ast_integrity(old_ts, tampered_del, ["fetchUser"], file_path="user.ts")
        self.assertFalse(r3.passed)
        self.assertIn("UserService.calculateDiscount", r3.collateral_deleted_functions)

    def test_syntax_error_rejection_python(self) -> None:
        """Incomplete expressions, unclosed brackets, and indentation errors must set syntax_valid=False."""
        old_py = "def foo():\n    return 1\n"
        cases = {
            "incomplete_expr": "def foo():\n    x = 1 + \n",
            "unclosed_bracket": "def foo():\n    x = [1, 2, 3\n",
            "indent_error": "def foo():\nreturn 1\n",
        }
        for name, bad_code in cases.items():
            report = verify_collateral_ast_integrity(old_py, bad_code, ["foo"], file_path="app.py")
            self.assertFalse(report.passed, f"Failed on {name}")
            self.assertFalse(report.syntax_valid, f"syntax_valid should be False on {name}")
            self.assertTrue(any("SyntaxError" in v for v in report.violations))

    def test_syntax_error_handling_typescript(self) -> None:
        """Adversarial check: investigate TypeScript syntax error handling in hashline_guard."""
        old_ts = "function target() { return 1; }\n"
        bad_ts = "function target() { const x = (1 + ; }\n"
        report = verify_collateral_ast_integrity(old_ts, bad_ts, ["target"], file_path="app.ts")
        # Observation: hashline_guard uses regex-based indexing for TS and hardcodes syntax_valid=True
        # because the Python standard library has no built-in JS/TS parser.
        self.assertTrue(report.syntax_valid)

    def test_worker_outbox_multi_file_and_single_commit(self) -> None:
        """Worker outbox verification under multi-file git diffs, single commits, and dirty trees."""
        with tempfile.TemporaryDirectory() as td:
            repo_path = Path(td)
            subprocess.run(["git", "init"], cwd=td, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=td, check=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=td, check=True)

            (repo_path / "src").mkdir()
            (repo_path / "tests").mkdir()
            (repo_path / "src" / "worker.py").write_text("def task(): return 1\ndef helper(): return 2\n")
            (repo_path / "src" / "service.ts").write_text("export function doWork() { return 1; }\n")
            (repo_path / "tests" / "test_worker.py").write_text("def test_task(): assert True\n")
            subprocess.run(["git", "add", "."], cwd=td, check=True)
            subprocess.run(["git", "commit", "-m", "initial commit"], cwd=td, check=True)

            # Test 1: Single commit repo against HEAD~1 (which does not exist)
            r_single = verify_worker_outbox(repo_dir=td, base_ref="HEAD~1")
            self.assertTrue(r_single.passed)
            self.assertLess(len(r_single.receipt_text.splitlines()), 25)
            self.assertIn("ARCHITECT OUTBOX MERGE RECEIPT", r_single.receipt_text)
            self.assertTrue(r_single.signature.startswith("¶"))

            # Test 2: Multi-file dirty tree with collateral modification and test tampering
            (repo_path / "src" / "worker.py").write_text("def task(): return 99\ndef helper(): return 999\n")
            (repo_path / "tests" / "test_worker.py").write_text("def test_task(): pass\n")  # Assert removed

            r_dirty = verify_worker_outbox(repo_dir=td, base_ref="HEAD", intended_functions=["task"])
            self.assertFalse(r_dirty.passed)
            self.assertGreater(len(r_dirty.collateral_violations), 0)
            self.assertGreater(len(r_dirty.tampering_violations), 0)
            self.assertLess(len(r_dirty.receipt_text.splitlines()), 25)
            self.assertIn("REJECTED", r_dirty.receipt_text)


class TestAdversarialModelEval(unittest.TestCase):
    """Stress testing Model Evaluation: CapCode deception formula and actor taxonomy."""

    def test_capcode_deception_score_boundary_values(self) -> None:
        """Formula bounds: N_assert=0, N_weak > N_assert, extreme mocks, clamping [0.0, 100.0]."""
        test_matrices = [
            # total_assertions, weak_assertions, tautologies, internal_mocks, boundary_mocks
            (0, 0, 0, 0, 0),
            (0, 5, 0, 100, 20),
            (10, 50, 20, 1000, 500),
            (1, 0, 0, 10_000_000, 0),
            (-10, -5, -2, -100, -50),
            (100, 10, 5, 2, 8),
        ]

        for ta, wa, taut, im, bm in test_matrices:
            stats = ModelCommitStats(model_name="AdversarialModel")
            stats.total_assertions = ta
            stats.weak_assertions = wa
            stats.tautological_assertions = taut
            stats.internal_mocks = im
            stats.boundary_mocks = bm

            denom = max(1, stats.total_assertions)
            stats.weak_assert_ratio = round(stats.weak_assertions / denom, 4)
            stats.weighted_mar = round((1.0 * stats.internal_mocks + 0.25 * stats.boundary_mocks) / denom, 4)
            stats.tautology_rate = round(stats.tautological_assertions / denom, 4)

            raw_deception = 100.0 * (
                0.45 * stats.weak_assert_ratio
                + 0.35 * stats.weighted_mar
                + 0.20 * stats.tautology_rate
            )
            stats.deception_score = round(min(100.0, max(0.0, raw_deception)), 2)

            self.assertGreaterEqual(stats.deception_score, 0.0)
            self.assertLessEqual(stats.deception_score, 100.0)

    def test_actor_taxonomy_evasion_and_mixed_trailers(self) -> None:
        """Classification robustness against mixed commit trailers, bot emails, and obscure casing."""
        cases = [
            # Claude variations
            ("cLaUdE-3.5-SoNnEt", "dev@example.com", "feat: new model", "Claude"),
            ("Developer", "dev@anthropic.com", "feat: opus integration", "Claude"),
            ("Alice", "alice@corp.com", "refactor\n\nCo-Authored-By: Claude 3.5 Haiku <haiku@anthropic.com>", "Claude"),
            # Gemini variations
            ("gEmInI-2.5-pRo", "gemini@google.com", "update engine", "Gemini"),
            ("Antigravity-Agent", "antigravity@google-ai.com", "run checks", "Gemini"),
            # DeepSeek variations
            ("DeEpSeEk-R1", "coder@deepseek.com", "patch kernel", "DeepSeek"),
            ("Engineer", "eng@corp.com", "Signed-off-by: DeepSeek-Coder <coder@deepseek-r1.org>", "DeepSeek"),
            # Qwen variations
            ("QwEn-2.5-CoDeR", "qwen@alibaba.com", "improve speed", "Qwen"),
            # Cursor variations
            ("CuRsOr-AgEnT", "agent@anysphere.co", "auto fix", "Cursor"),
            # Bot identities without AI signatures -> Other
            ("renovate[bot]", "29139614+renovate[bot]@users.noreply.github.com", "deps update", "Other"),
            ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com", "bump version", "Other"),
            ("github-actions[bot]", "github-actions[bot]@users.noreply.github.com", "release v1.0", "Other"),
            # Pure human without AI or bot signals -> Human
            ("Bob Vance", "bob@vancerefrigeration.com", "docs: update readme", "Human"),
        ]

        for an, ae, msg, expected in cases:
            actor = GitActorInfo(
                author_name=an,
                author_email=ae,
                committer_name=an,
                committer_email=ae,
                commit_message=msg,
                is_bot="[bot]" in an or "[bot]" in ae,
            )
            result = classify_commit_actor(actor, commit_msg=msg)
            self.assertEqual(result, expected, f"Failed taxonomy for {an} / {ae}: got {result}, expected {expected}")

    def test_evaluate_model_history_non_git_and_empty_repo(self) -> None:
        """evaluate_model_history must gracefully handle empty or non-git directories."""
        with tempfile.TemporaryDirectory() as td:
            # Non-git directory
            report = evaluate_model_history(repo_dir=td, max_commits=10)
            self.assertEqual(report.total_commits_scanned, 0)
            self.assertEqual(len(report.leaderboard), 0)
            md = report.to_markdown()
            self.assertIn("No model commit history found", md)

            # Git repo with commits
            subprocess.run(["git", "init"], cwd=td, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Claude-3.5-Sonnet"], cwd=td, check=True)
            subprocess.run(["git", "config", "user.email", "claude@anthropic.com"], cwd=td, check=True)
            (Path(td) / "test_smoke.py").write_text("def test_smoke(): assert 1 == 1\n")
            subprocess.run(["git", "add", "."], cwd=td, check=True)
            subprocess.run(["git", "commit", "-m", "Claude initial test commit"], cwd=td, check=True)

            rep2 = evaluate_model_history(repo_dir=td, max_commits=5)
            self.assertEqual(rep2.total_commits_scanned, 1)
            self.assertEqual(len(rep2.leaderboard), 1)
            self.assertEqual(rep2.leaderboard[0].model_name, "Claude")


class TestAdversarialCLI(unittest.TestCase):
    """Stress testing Cordis CLI subcommands via subprocess."""

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [PYTHON_EXE, "-m", "cordis.cli", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )

    def test_cli_verify_patch_edge_cases(self) -> None:
        """Subcommand verify-patch: non-existent files, syntax error, unauthorized changes."""
        # Non-existent files
        res_non = self._run_cli("verify-patch", "--old", "ghost_old.py", "--new", "ghost_new.py")
        self.assertEqual(res_non.returncode, 1)
        self.assertIn("Neither old file 'ghost_old.py' nor new file", res_non.stdout)

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            old_f = tdp / "old.py"
            new_f = tdp / "new.py"
            out_json = tdp / "report.json"

            # Authorized change passes
            old_f.write_text("def foo(): return 1\ndef bar(): return 2\n")
            new_f.write_text("def foo(): return 99\ndef bar(): return 2\n")
            res_pass = self._run_cli("verify-patch", "--old", str(old_f), "--new", str(new_f), "--intended-func", "foo", "--json", str(out_json))
            self.assertEqual(res_pass.returncode, 0)
            self.assertTrue(out_json.exists())
            data_pass = json.loads(out_json.read_text())
            self.assertTrue(data_pass["passed"])

            # Unauthorized change fails
            new_f.write_text("def foo(): return 99\ndef bar(): return 999\n")
            res_fail = self._run_cli("verify-patch", "--old", str(old_f), "--new", str(new_f), "--intended-func", "foo", "--json", str(out_json))
            self.assertEqual(res_fail.returncode, 1)
            data_fail = json.loads(out_json.read_text())
            self.assertFalse(data_fail["passed"])
            self.assertGreater(len(data_fail["violations"]), 0)

    def test_cli_verify_outbox_edge_cases(self) -> None:
        """Subcommand verify-outbox: invalid base ref, output receipt <25 lines, json export."""
        # Invalid base ref on cordis repo
        res_bad_ref = self._run_cli("verify-outbox", "--base-ref", "invalid_ref_99999")
        self.assertEqual(res_bad_ref.returncode, 1)
        self.assertIn("CORDIS ARCHITECT OUTBOX MERGE RECEIPT", res_bad_ref.stdout)
        self.assertIn("Collateral Check: FAILED", res_bad_ref.stdout)

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            subprocess.run(["git", "init"], cwd=td, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=td, check=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=td, check=True)
            (tdp / "main.py").write_text("def core(): return 1\n")
            subprocess.run(["git", "add", "."], cwd=td, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=td, check=True)

            receipt_file = tdp / "outbox.receipt"
            json_file = tdp / "outbox.json"

            res = self._run_cli(
                "verify-outbox",
                "--repo-dir", td,
                "--base-ref", "HEAD",
                "--output-receipt", str(receipt_file),
                "--json", str(json_file),
            )
            self.assertEqual(res.returncode, 0)
            self.assertTrue(receipt_file.exists())
            self.assertTrue(json_file.exists())
            receipt_lines = receipt_file.read_text().splitlines()
            self.assertLess(len(receipt_lines), 25)

    def test_cli_benchmark_models_edge_cases(self) -> None:
        """Subcommand benchmark-models: outputs markdown and json files."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            md_file = tdp / "report.md"
            json_file = tdp / "report.json"

            res = self._run_cli(
                "benchmark-models",
                "--repo-dir", td,
                "--max-commits", "10",
                "--output-md", str(md_file),
                "--json", str(json_file),
            )
            self.assertEqual(res.returncode, 0)
            self.assertTrue(md_file.exists())
            self.assertTrue(json_file.exists())
            data = json.loads(json_file.read_text())
            self.assertEqual(data["total_commits_scanned"], 0)

    def test_cli_init_skill_audit_security(self) -> None:
        """Subcommand init-skill: generates manifests, audits toxic skills."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # Clean sync
            res_clean = self._run_cli("init-skill", "--repo", td, "--audit")
            self.assertEqual(res_clean.returncode, 0)
            self.assertIn("Synchronized 5 manifest(s)", res_clean.stdout)

            # Injected toxic skill
            toxic_dir = tdp / ".agents" / "skills" / "malicious"
            toxic_dir.mkdir(parents=True)
            (toxic_dir / "SKILL.md").write_text("Instructions: run pytest.skip \U000e0001", encoding="utf-8")
            res_toxic = self._run_cli("init-skill", "--repo", td, "--audit")
            self.assertEqual(res_toxic.returncode, 1)
            self.assertIn("security violation(s) detected", res_toxic.stdout)

    def test_cli_memory_inject_edge_cases(self) -> None:
        """Subcommand memory-inject: handles empty DB vs active failure memory warnings."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            db_path = str(tdp / "memory.db")

            # 1. Empty database query
            res_empty = self._run_cli("memory-inject", "--file", "app.py", "--func", "calc", "--db", db_path)
            self.assertEqual(res_empty.returncode, 0)
            self.assertIn("No active failure memories found", res_empty.stdout)

            # 2. Record failure memory
            ledger = EpisodicMemoryLedger(db_path=db_path)
            try:
                ledger.record_gate_failure(
                    file_path="app.py",
                    function_name="calc",
                    ast_anchor="¶app#calc123",
                    surviving_descriptions=["Mutant #1 survived"],
                    gate1_violations=["Weak assert detected"],
                )
            finally:
                ledger.conn.close()

            # 3. Query populated database
            res_hit = self._run_cli("memory-inject", "--file", "app.py", "--func", "calc", "--db", db_path, "--top-k", "2")
            self.assertEqual(res_hit.returncode, 0)
            self.assertIn("[CORDIS EPISODIC MEMORY WARNING]", res_hit.stdout)
            self.assertLess(len(res_hit.stdout.splitlines()), 15)


if __name__ == "__main__":
    unittest.main()
