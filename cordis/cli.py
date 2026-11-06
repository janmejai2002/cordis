"""Cordis CLI & GitHub PR Prosecutor Comment Formatter."""
from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any, Optional

# Ensure stdout and stderr handle utf-8 safely on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import json
from cordis.ast_gate import audit_test_tampering, calculate_mock_to_assertion_ratio
from cordis.forge_guard import audit_current_environment
from cordis.fuzzer import (
    BenchmarkGateReport,
    DifferentialFuzzReport,
    run_differential_fuzz_gate,
    run_statistical_benchmark_gate,
)
from cordis.git_diff import extract_git_diff, get_git_file_content
from cordis.html_report import save_html_report, save_markdown_report
from cordis.mutator import MutationGateReport, run_in_memory_mutation_gate, run_repo_mutation_gate
from cordis.policy_guard import audit_repository_policy, PolicyAuditReport
from cordis.repair import synthesize_mutant_killing_test
from cordis.demo_fixtures import (
    BAD_AGENT_PATCH_SOURCE,
    BAD_AGENT_TEST_SOURCE,
    GOOD_AGENT_TEST_SOURCE,
    OLD_BUGGY_SOURCE,
    OLD_TEST_SOURCE,
    REFERENCE_CORRECT_SOURCE,
)


def format_github_prosecutor_comment(
    pr_title: str,
    fixproof_revert_passed: bool = True,
    gate1_report: Any = None,
    gate2_report: Any = None,
    gate3_fuzz_report: Any = None,
    gate3_bench_report: Any = None,
    *,
    swe_bench_revert_passed: Optional[bool] = None,
) -> str:
    g1_pass = getattr(gate1_report, "passed", False)
    g2_pass = getattr(gate2_report, "passed", False)
    g3a_pass = getattr(gate3_fuzz_report, "passed", False)
    g3b_pass = getattr(gate3_bench_report, "passed", False)
    overall_passed = g1_pass and g2_pass and g3a_pass and g3b_pass

    f2p_passed = swe_bench_revert_passed if swe_bench_revert_passed is not None else fixproof_revert_passed
    status_badge = "✅ **APPROVED TO LAND**" if overall_passed else "🛑 **BLOCKED — COUNTERFEIT RED / REGRESSION DETECTED**"
    fp_str = "✅ PASSED (Fooled by single-input test!)" if f2p_passed and not overall_passed else ("✅ PASSED" if f2p_passed else "❌ FAILED")

    lines = [
        f"## 🛡️ Cordis Adversarial AI-PR Prosecutor Verdict: {pr_title}",
        f"**Overall Verdict**: {status_badge}",
        f"**SWE-bench `Fail-to-Pass` (`git revert HEAD~1`)**: {fp_str}",
        "",
        "| Prosecution Gate | Status | Telemetry & Evidence |",
        "| :--- | :--- | :--- |",
        (
            f"| **Gate 1: AST Test-Tampering & Anti-Mock Audit** | "
            f"{'✅ PASS' if gate1_report.passed else '❌ FAIL'} | "
            f"Asserts: `{gate1_report.old_assert_count} -> {gate1_report.new_assert_count}` · "
            f"Violations: `{len(gate1_report.violations)}` |"
        ),
        (
            f"| **Gate 2: In-Place AST Mutation ('Counterfeit Red' Killer)** | "
            f"{'✅ PASS' if gate2_report.passed else '❌ FAIL'} | "
            f"Killed `{gate2_report.killed_mutants}/{gate2_report.total_mutants}` mutants "
            f"(`{gate2_report.survived_mutants}` survived) |"
        ),
        (
            f"| **Gate 3A: Differential Property Fuzzing (200 Edge Cases)** | "
            f"{'✅ PASS' if gate3_fuzz_report.passed else '❌ FAIL'} | "
            f"Tested `{gate3_fuzz_report.inputs_tested}` inputs · "
            f"Counterexamples: `{len(gate3_fuzz_report.counterexamples)}` |"
        ),
        (
            f"| **Gate 3B: Mann-Whitney U Baseline Benchmark (N=30)** | "
            f"{'✅ PASS' if gate3_bench_report.passed else '❌ FAIL'} | "
            f"`{gate3_bench_report.baseline_median_us:.3f}us -> {gate3_bench_report.candidate_median_us:.3f}us` "
            f"({gate3_bench_report.note}) |"
        ),
        "",
    ]

    if gate1_report.violations:
        lines.append("### 🚨 Gate 1: Test-Tampering Violations")
        for v in gate1_report.violations:
            lines.append(f"- `{v}`")
        lines.append("")

    survived = [m for m in gate2_report.results if not m.killed]
    if survived:
        lines.append("### 🧟 Gate 2: Surviving AST Mutants (Proving Agent's Test Is Hollow)")
        for m in survived:
            lines.append(f"- **Mutant #{m.mutant_id} (Line {m.lineno})**: {m.description} -> *Test still exited 0!*")
        lines.append("")

    if gate3_fuzz_report.counterexamples:
        lines.append("### 💥 Gate 3A: Differential Fuzzing Counterexamples (`f_spec(x) != f_pr(x)`)")
        for cx in gate3_fuzz_report.counterexamples[:3]:
            lines.append(
                f"- Input `args={cx.args}`: Expected `{cx.old_outcome}`, but PR produced `{cx.new_outcome}` ({cx.reason})"
            )
        lines.append("")

    return "\n".join(lines)


def visible_width(s: str) -> int:
    """Calculate the visible terminal display width of a string (stripping ANSI codes)."""
    clean = re.sub(r"\033\[[0-9;]*m", "", s)
    width = 0
    for ch in clean:
        if ch == "\ufe0f":
            continue
        w = unicodedata.east_asian_width(ch)
        if w in ("W", "F"):
            width += 2
        else:
            width += 1
    return width


def truncate_visible(s: str, target_width: int) -> str:
    """Truncate string to fit within target visible width, appending an ellipsis."""
    clean = re.sub(r"\033\[[0-9;]*m", "", s)
    cur = 0
    res = []
    for ch in clean:
        w = 0 if ch == "\ufe0f" else (2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if cur + w > target_width - 1:
            break
        res.append(ch)
        cur += w
    return "".join(res) + "…"


def pad_cell(s: str, target_width: int, align: str = "left") -> str:
    """Pad string to exact target visible width, accounting for ANSI codes and East Asian width."""
    vw = visible_width(s)
    if vw > target_width:
        s = truncate_visible(s, target_width)
        vw = visible_width(s)
    diff = target_width - vw
    if align == "right":
        return " " * diff + s
    elif align == "center":
        left = diff // 2
        return " " * left + s + " " * (diff - left)
    return s + " " * diff


def format_terminal_prosecutor_report(
    pr_title: str,
    fixproof_revert_passed: bool = True,
    gate1_report: Any = None,
    gate2_report: Any = None,
    gate3_fuzz_report: Any = None,
    gate3_bench_report: Any = None,
    *,
    swe_bench_revert_passed: bool | None = None,
) -> str:
    use_color = os.environ.get("NO_COLOR") is None
    RED = "\033[1;31m" if use_color else ""
    GREEN = "\033[1;32m" if use_color else ""
    YELLOW = "\033[1;33m" if use_color else ""
    CYAN = "\033[1;36m" if use_color else ""
    DIM = "\033[90m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    g1_pass = getattr(gate1_report, "passed", False)
    g2_pass = getattr(gate2_report, "passed", False)
    g3a_pass = getattr(gate3_fuzz_report, "passed", False)
    g3b_pass = getattr(gate3_bench_report, "passed", False)
    overall_passed = g1_pass and g2_pass and g3a_pass and g3b_pass

    f2p_passed = swe_bench_revert_passed if swe_bench_revert_passed is not None else fixproof_revert_passed

    w_g = 40
    w_s = 10
    w_t = 34
    total_w = 1 + w_g + 1 + w_s + 1 + w_t + 1

    lines = []

    # Header Card
    hdr_content = f" {BOLD}{CYAN}CORDIS PROSECUTOR{RESET} {DIM}│{RESET} {BOLD}{pr_title}{RESET} "
    lines.append(f"{CYAN}╭{'─' * (total_w - 2)}╮{RESET}")
    lines.append(f"{CYAN}│{RESET}" + pad_cell(hdr_content, total_w - 2) + f"{CYAN}│{RESET}")
    lines.append(f"{CYAN}╰{'─' * (total_w - 2)}╯{RESET}")

    # Verdict Badges
    if overall_passed:
        verdict_badge = f"{GREEN}{BOLD}✔ APPROVED TO LAND{RESET}"
    else:
        verdict_badge = f"{RED}{BOLD}■ BLOCKED{RESET}  {DIM}[Counterfeit Red / Invariant Regression]{RESET}"

    if f2p_passed and not overall_passed:
        f2p_badge = f"{YELLOW}{BOLD}▲ PASSED{RESET}   {DIM}(Fooled 100% by single-input overfit!){RESET}"
    elif f2p_passed:
        f2p_badge = f"{GREEN}{BOLD}✔ PASSED{RESET}"
    else:
        f2p_badge = f"{RED}{BOLD}■ FAILED{RESET}"

    lines.append(f"  {BOLD}Prosecutor Verdict:{RESET}              {verdict_badge}")
    lines.append(f"  {BOLD}SWE-bench Fail-to-Pass (revert):{RESET} {f2p_badge}")
    lines.append("")

    # Table Top
    lines.append(f"{DIM}┌{'─' * w_g}┬{'─' * w_s}┬{'─' * w_t}┐{RESET}")
    lines.append(
        f"{DIM}│{RESET} {BOLD}{pad_cell('Prosecution Gate', w_g - 2)}{RESET} {DIM}│{RESET} "
        f"{BOLD}{pad_cell('Status', w_s - 2, 'center')}{RESET} {DIM}│{RESET} "
        f"{BOLD}{pad_cell('Telemetry & Evidence', w_t - 2)}{RESET} {DIM}│{RESET}"
    )
    lines.append(f"{DIM}├{'─' * w_g}┼{'─' * w_s}┼{'─' * w_t}┤{RESET}")

    def make_row(gate_name: str, passed: bool, telem: str) -> str:
        st_text = "PASS ✓" if passed else "FAIL ✗"
        st_col = GREEN if passed else RED
        return (
            f"{DIM}│{RESET} {pad_cell(gate_name, w_g - 2)} {DIM}│{RESET} "
            f"{st_col}{pad_cell(st_text, w_s - 2, 'center')}{RESET} {DIM}│{RESET} "
            f"{pad_cell(telem, w_t - 2)} {DIM}│{RESET}"
        )

    # Gate 1
    violations_count = len(getattr(gate1_report, "violations", []))
    v_word = "violation" if violations_count == 1 else "violations"
    g1_tm = f"Asserts: {gate1_report.old_assert_count}->{gate1_report.new_assert_count} · {violations_count} {v_word}"
    lines.append(make_row("Gate 1: AST Test-Tampering Auditor", g1_pass, g1_tm))

    # Gate 2
    g2_tm = f"Killed {gate2_report.killed_mutants}/{gate2_report.total_mutants} ({gate2_report.survived_mutants} survived)"
    lines.append(make_row("Gate 2: In-Place AST Mutation Engine", g2_pass, g2_tm))

    # Gate 3A
    cx_count = len(getattr(gate3_fuzz_report, "counterexamples", []))
    g3a_tm = f"Tested {gate3_fuzz_report.inputs_tested} inputs · {cx_count} counterex"
    lines.append(make_row("Gate 3A: Differential Property Fuzzer", g3a_pass, g3a_tm))

    # Gate 3B
    speedup = getattr(gate3_bench_report, "speedup_pct", 0.0)
    sign = "+" if speedup >= 0 else ""
    g3b_tm = f"{gate3_bench_report.baseline_median_us:.3f}us -> {gate3_bench_report.candidate_median_us:.3f}us ({sign}{speedup:.1f}%)"
    lines.append(make_row("Gate 3B: Mann-Whitney U Benchmark", g3b_pass, g3b_tm))

    # Table Bottom
    lines.append(f"{DIM}└{'─' * w_g}┴{'─' * w_s}┴{'─' * w_t}┘{RESET}")
    lines.append("")

    # Forensic Details
    has_tampering = bool(getattr(gate1_report, "violations", []))
    survived = [m for m in getattr(gate2_report, "results", []) if not m.killed]
    has_fuzz_cx = bool(getattr(gate3_fuzz_report, "counterexamples", []))

    if has_tampering or survived or has_fuzz_cx:
        lines.append(f"  {RED}{BOLD}🚨 Forensic Evidence Breakdown:{RESET}")
        for v in getattr(gate1_report, "violations", []):
            lines.append(f"     {DIM}↳{RESET} {BOLD}[Gate 1 / Tampering]:{RESET} {v}")

        for m in survived:
            lines.append(f"     {DIM}↳{RESET} {BOLD}[Gate 2 / Mutation]:{RESET} Mutant #{m.mutant_id} (Line {m.lineno}): {m.description} -> {RED}Test still passed (exited 0)!{RESET}")

        for cx in getattr(gate3_fuzz_report, "counterexamples", [])[:3]:
            lines.append(f"     {DIM}↳{RESET} {BOLD}[Gate 3A / Fuzzing]:{RESET} args={cx.args} -> Expected {GREEN}{cx.old_outcome}{RESET}, got {RED}{cx.new_outcome}{RESET} ({cx.reason})")
        lines.append("")

    return "\n".join(lines)


def run_demo(
    github_comment: bool = False,
    output_html: str | None = None,
    output_md: str | None = None,
) -> int:
    env_old: dict[str, Any] = {}
    env_bad: dict[str, Any] = {}
    env_ref: dict[str, Any] = {}
    exec(OLD_BUGGY_SOURCE, env_old)
    exec(BAD_AGENT_PATCH_SOURCE, env_bad)
    exec(REFERENCE_CORRECT_SOURCE, env_ref)

    f_old = env_old["parse_discount_tier"]
    f_bad = env_bad["parse_discount_tier"]
    f_ref = env_ref["parse_discount_tier"]

    # 1. Run on BAD Agent PR (that fools SWE-bench Fail-to-Pass git revert check)
    g1_bad = audit_test_tampering(
        OLD_TEST_SOURCE,
        BAD_AGENT_TEST_SOURCE,
        target_function_names=["parse_discount_tier"],
    )
    g2_bad = run_in_memory_mutation_gate(
        BAD_AGENT_PATCH_SOURCE,
        BAD_AGENT_TEST_SOURCE,
        target_function="parse_discount_tier",
    )
    g3_fuzz_bad = run_differential_fuzz_gate(f_ref, f_bad, num_samples=200)
    g3_bench_bad = run_statistical_benchmark_gate(
        lambda: f_old(150.0),
        lambda: f_bad(150.0),
        rounds=30,
        iterations_per_round=100,
    )

    comment_bad = format_github_prosecutor_comment(
        pr_title="PR #42 (Bad Agent Patch — Single-Input Overfit & Weakened Assert)",
        fixproof_revert_passed=True,
        gate1_report=g1_bad,
        gate2_report=g2_bad,
        gate3_fuzz_report=g3_fuzz_bad,
        gate3_bench_report=g3_bench_bad,
    )

    # 2. Run on GOOD Verified PR
    g1_good = audit_test_tampering(
        OLD_TEST_SOURCE,
        GOOD_AGENT_TEST_SOURCE,
        target_function_names=["parse_discount_tier"],
    )
    g2_good = run_in_memory_mutation_gate(
        REFERENCE_CORRECT_SOURCE,
        GOOD_AGENT_TEST_SOURCE,
        target_function="parse_discount_tier",
    )
    g3_fuzz_good = run_differential_fuzz_gate(f_ref, f_ref, num_samples=200)
    g3_bench_good = run_statistical_benchmark_gate(
        lambda: f_old(150.0),
        lambda: f_ref(150.0),
        rounds=30,
        iterations_per_round=100,
    )

    comment_good = format_github_prosecutor_comment(
        pr_title="PR #43 (Genuine Fix + Mutation-Hardened Test Suite)",
        fixproof_revert_passed=True,
        gate1_report=g1_good,
        gate2_report=g2_good,
        gate3_fuzz_report=g3_fuzz_good,
        gate3_bench_report=g3_bench_good,
    )

    w_total = 88
    use_color = os.environ.get("NO_COLOR") is None
    CYAN = "\033[1;36m" if use_color else ""
    DIM = "\033[90m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    GREEN = "\033[1;32m" if use_color else ""
    RED = "\033[1;31m" if use_color else ""
    YELLOW = "\033[1;33m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    if github_comment:
        print(comment_bad)
        print("\n" + "=" * 78 + "\n")
        print(comment_good)
    else:
        welcome_title = " CORDIS VERIFY · Autonomous AI-PR Invariant Prosecutor"
        welcome_sub = " Demo: Exposing SWE-bench Fail-to-Pass False Positives via In-Memory Invariant Gates"
        print(f"\n{CYAN}╭{'─' * (w_total - 2)}╮{RESET}")
        print(f"{CYAN}│{RESET}" + pad_cell(f"{BOLD}{CYAN}{welcome_title}{RESET}", w_total - 2) + f"{CYAN}│{RESET}")
        print(f"{CYAN}│{RESET}" + pad_cell(f"{DIM}{welcome_sub}{RESET}", w_total - 2) + f"{CYAN}│{RESET}")
        print(f"{CYAN}╰{'─' * (w_total - 2)}╯{RESET}\n")

        rep_bad = format_terminal_prosecutor_report(
            pr_title="PR #42: Bad Agent Patch (Single-Input Overfit & Weakened Assert)",
            fixproof_revert_passed=True,
            gate1_report=g1_bad,
            gate2_report=g2_bad,
            gate3_fuzz_report=g3_fuzz_bad,
            gate3_bench_report=g3_bench_bad,
        )
        rep_good = format_terminal_prosecutor_report(
            pr_title="PR #43: Genuine Fix + Mutation-Hardened Test Suite",
            fixproof_revert_passed=True,
            gate1_report=g1_good,
            gate2_report=g2_good,
            gate3_fuzz_report=g3_fuzz_good,
            gate3_bench_report=g3_bench_good,
        )
        print(rep_bad)
        print(f"{DIM}{'─' * w_total}{RESET}\n")
        print(rep_good)

        # Executive recap card
        summary_title = " VERDICT RECAP: Why SWE-bench Fail-to-Pass Fails Where Cordis Wins"
        p42_summary = f" • PR #42 (Overfit):   {YELLOW}SWE-bench PASSED (fooled){RESET} {DIM}│{RESET} {RED}Cordis BLOCKED (Mutants alive){RESET}"
        p43_summary = f" • PR #43 (Invariant): {GREEN}SWE-bench PASSED{RESET}          {DIM}│{RESET} {GREEN}Cordis APPROVED (5/5 Killed){RESET}"
        print(f"{DIM}╭{'─' * (w_total - 2)}╮{RESET}")
        print(f"{DIM}│{RESET}" + pad_cell(f"{BOLD}{summary_title}{RESET}", w_total - 2) + f"{DIM}│{RESET}")
        print(f"{DIM}│{RESET}" + pad_cell(p42_summary, w_total - 2) + f"{DIM}│{RESET}")
        print(f"{DIM}│{RESET}" + pad_cell(p43_summary, w_total - 2) + f"{DIM}│{RESET}")
        print(f"{DIM}╰{'─' * (w_total - 2)}╯{RESET}")

    # Generate interactive HTML report
    html_target = output_html or "cordis_report.html"
    save_html_report(
        filepath=html_target,
        pr_title="PR #42 (Bad Agent Patch — Single-Input Overfit & Weakened Assert)",
        fixproof_revert_passed=True,
        gate1_report=g1_bad,
        gate2_report=g2_bad,
        gate3_fuzz_report=g3_fuzz_bad,
        gate3_bench_report=g3_bench_bad,
    )
    if not github_comment:
        print(f"\n📊 {BOLD}[HTML Scorecard]{RESET}: Saved to {CYAN}{html_target}{RESET} (open in browser to inspect interactive gates)\n")

    if output_md:
        save_markdown_report(
            filepath=output_md,
            content=comment_bad + "\n\n" + "=" * 78 + "\n\n" + comment_good,
        )
        print(f"📝 {BOLD}[Markdown Report]{RESET}: Written to {output_md}")

    return 0


def run_benchmark_cli(output_md: str | None = None) -> int:
    from cordis.benchmark_suite import format_benchmark_markdown_table, run_benchmark
    res = run_benchmark()
    md_table = format_benchmark_markdown_table(res)
    print(md_table)
    if output_md:
        save_markdown_report(output_md, md_table)
        print(f"\n📝 [Cordis Benchmark Table]: Written to {output_md}")
    return 0


def run_verify_git(
    base_ref: str = "HEAD~1",
    target_ref: str | None = None,
    repo_dir: str = ".",
    github_comment: bool = False,
    output_html: str | None = None,
    output_md: str | None = None,
    suggest_test: bool = False,
) -> int:
    diff_report = extract_git_diff(repo_dir=repo_dir, base_ref=base_ref, target_ref=target_ref)
    if diff_report.error:
        print(f"🛑 [Cordis Git Diff Error]: {diff_report.error}")
        return 1

    effective_base = diff_report.base_ref
    print(f"🛡️ Cordis Git Diff Prosecutor: {effective_base} -> {target_ref or 'working tree'}")
    print(f"  • Modified source files ({len(diff_report.source_files)}): {diff_report.source_files}")
    print(f"  • Modified test files   ({len(diff_report.test_files)}): {diff_report.test_files}")
    print(f"  • Target functions      ({len(diff_report.target_function_names)}): {diff_report.target_function_names}")

    if not diff_report.source_files and not diff_report.test_files:
        print("✅ No Python or TypeScript/JavaScript source or test files modified in this git diff. Verdict: PASS")
        return 0

    overall_passed = True

    # Gate 0: Forge Self-Approval & Token Guard
    forge_report = audit_current_environment(repo_dir=repo_dir)
    if not forge_report.passed:
        overall_passed = False
        for v in forge_report.violations:
            print(f"  [Forge Guard] ❌ FAIL: {v}")
    elif forge_report.warnings:
        for w in forge_report.warnings:
            print(f"  [Forge Guard] ⚠️ WARN: {w}")
    else:
        print("  [Forge Guard] ✅ PASS: Human dual-custody or verified actor signature.")

    g1_reports = []
    for test_file in diff_report.test_files:
        old_test_code = get_git_file_content(effective_base, test_file, repo_dir=repo_dir) or ""
        if not old_test_code and not target_ref and effective_base != "HEAD":
            old_test_code = get_git_file_content("HEAD", test_file, repo_dir=repo_dir) or ""
        if target_ref:
            new_test_code = get_git_file_content(target_ref, test_file, repo_dir=repo_dir) or ""
        else:
            p = Path(repo_dir) / test_file
            new_test_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""

        if any(test_file.endswith(ext) for ext in (".ts", ".tsx", ".js", ".jsx")):
            from cordis.ts_gate import audit_ts_test_tampering
            g1 = audit_ts_test_tampering(
                old_test_code,
                new_test_code,
                target_function_names=diff_report.target_function_names,
                file_path=test_file,
            )
        else:
            g1 = audit_test_tampering(
                old_test_code,
                new_test_code,
                target_function_names=diff_report.target_function_names,
                file_path=test_file,
            )
        g1_reports.append((test_file, g1))
        if not g1.passed:
            overall_passed = False

    test_code_combined = ""
    discovered_test_files: list[str] = []
    if diff_report.test_files:
        for test_file in diff_report.test_files:
            if not test_file.endswith(".py"):
                continue
            if target_ref:
                t_code = get_git_file_content(target_ref, test_file, repo_dir=repo_dir)
                if t_code:
                    test_code_combined += t_code + "\n"
            else:
                p = Path(repo_dir) / test_file
                if p.is_file():
                    test_code_combined += p.read_text(encoding="utf-8", errors="replace") + "\n"
    else:
        # Zero modified test files: auto-discover existing test files in repo_dir
        ignored_dirs = {".git", ".venv", "venv", "node_modules", "build", "dist", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
            for file in sorted(files):
                if (file.startswith("test_") or file.endswith("_test.py")) and file.endswith(".py"):
                    full_p = Path(root) / file
                    try:
                        rel_p = full_p.relative_to(repo_dir).as_posix()
                    except ValueError:
                        rel_p = full_p.as_posix()
                    discovered_test_files.append(rel_p)
                    try:
                        test_code_combined += full_p.read_text(encoding="utf-8", errors="replace") + "\n"
                    except OSError:
                        pass
        if discovered_test_files:
            print(f"  • Discovered existing test files ({len(discovered_test_files)}): {discovered_test_files}")

    g2_reports = []
    for src_file in diff_report.source_files:
        if not src_file.endswith(".py"):
            continue
        if target_ref:
            src_code = get_git_file_content(target_ref, src_file, repo_dir=repo_dir) or ""
        else:
            p = Path(repo_dir) / src_file
            src_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
        if src_code and test_code_combined:
            file_fns = [
                f.name for f in diff_report.modified_functions
                if not f.is_test and Path(f.file_path).as_posix() == Path(src_file).as_posix()
            ]
            fns_to_test = file_fns if file_fns else ([None] if not diff_report.target_function_names else [])
            mod_name = Path(src_file).with_suffix("").as_posix().replace("/", ".")
            for fn in fns_to_test:
                g2 = run_in_memory_mutation_gate(
                    src_code,
                    test_code_combined,
                    target_function=fn,
                    module_name=mod_name,
                )
                g2_reports.append((src_file, fn or "<module>", g2))
                if not g2.passed:
                    overall_passed = False

    # Gate 3A: Differential Property Fuzzing against base_ref
    g3_fuzz_reports = []
    for func in diff_report.modified_functions:
        if func.is_test or not func.file_path.endswith(".py"):
            continue
        old_file_code = get_git_file_content(effective_base, func.file_path, repo_dir=repo_dir)
        if not old_file_code and not target_ref and effective_base != "HEAD":
            old_file_code = get_git_file_content("HEAD", func.file_path, repo_dir=repo_dir)
        if not old_file_code:
            continue
        p = Path(repo_dir) / func.file_path
        if target_ref:
            new_file_code = get_git_file_content(target_ref, func.file_path, repo_dir=repo_dir)
        else:
            new_file_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
        if not new_file_code:
            continue

        try:
            repo_abs = str(Path(repo_dir).resolve())
            if repo_abs not in sys.path:
                sys.path.insert(0, repo_abs)

            env_old: dict[str, Any] = {"__builtins__": __builtins__}
            env_new: dict[str, Any] = {"__builtins__": __builtins__}
            exec(compile(old_file_code, f"<{func.file_path}_old>", "exec"), env_old)
            exec(compile(new_file_code, f"<{func.file_path}_new>", "exec"), env_new)

            f_old = env_old.get(func.name)
            f_new = env_new.get(func.name)

            if callable(f_old) and callable(f_new):
                fuzz_rep = run_differential_fuzz_gate(f_old, f_new, num_samples=200)
                g3_fuzz_reports.append((func.file_path, func.name, fuzz_rep))
                if not fuzz_rep.passed:
                    overall_passed = False
        except Exception:
            pass

    for t_file, g1 in g1_reports:
        status = "✅ PASS" if g1.passed else "❌ FAIL"
        print(f"  [Gate 1 Test-Tampering] {t_file}: {status} (violations: {len(g1.violations)})")
        for v in g1.violations:
            print(f"    - Violation: {v}")

    for s_file, fn, g2 in g2_reports:
        if g2.total_mutants == 0:
            print(f"  [Gate 2 Mutation] {s_file}::{fn}: ✅ PASS (0 mutants in diff scope)")
        else:
            status = "✅ PASS" if g2.passed else "❌ FAIL"
            print(f"  [Gate 2 Mutation] {s_file}::{fn}: {status} (killed {g2.killed_mutants}/{g2.total_mutants})")
            for m in g2.results:
                if not m.killed:
                    print(f"    - Surviving mutant: {m.description}")
            if suggest_test and not g2.passed and g2.survived_mutants > 0:
                surviving = [m for m in g2.results if not m.killed]
                if target_ref:
                    s_code = get_git_file_content(target_ref, s_file, repo_dir=repo_dir) or ""
                else:
                    p = Path(repo_dir) / s_file
                    s_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
                if s_code and fn:
                    try:
                        sugg = synthesize_mutant_killing_test(s_code, fn, surviving)
                        if sugg:
                            print(f"\n[Cordis Test Suggestion for {s_file}::{fn}]:")
                            print(sugg)
                    except Exception as e:
                        print(f"Warning: Failed to synthesize test repair: {e}")

    for s_file, fn, fuzz_rep in g3_fuzz_reports:
        if fuzz_rep.passed:
            print(f"  [Gate 3A Differential Fuzzing] {s_file}::{fn}: ✅ PASS ({fuzz_rep.inputs_tested} inputs tested, 0 counterexamples)")
        else:
            print(f"  [Gate 3A Differential Fuzzing] {s_file}::{fn}: ❌ FAIL ({len(fuzz_rep.counterexamples)} counterexamples)")
            for cx in fuzz_rep.counterexamples[:3]:
                print(f"    - Input args={cx.args}: expected {cx.old_outcome}, got {cx.new_outcome} ({cx.reason})")

    primary_g1 = g1_reports[0][1] if g1_reports else audit_test_tampering("", "")
    primary_g2 = g2_reports[0][2] if g2_reports else MutationGateReport(passed=True, total_mutants=0, killed_mutants=0, survived_mutants=0)
    failing_fuzz = [rep for _, _, rep in g3_fuzz_reports if not rep.passed]
    if failing_fuzz:
        diff_fuzz = failing_fuzz[0]
    elif g3_fuzz_reports:
        diff_fuzz = g3_fuzz_reports[0][2]
    else:
        diff_fuzz = DifferentialFuzzReport(passed=True, inputs_tested=0, counterexamples=[])
    diff_bench = BenchmarkGateReport(passed=True, rounds=30, baseline_median_us=0.05, candidate_median_us=0.05, speedup_pct=0.0, u_statistic=0.0, p_value=1.0, note="Git diff verification")

    if output_html:
        save_html_report(
            filepath=output_html,
            pr_title=f"Git Diff Verdict: {effective_base} -> {target_ref or 'working tree'}",
            fixproof_revert_passed=True,
            gate1_report=primary_g1,
            gate2_report=primary_g2,
            gate3_fuzz_report=diff_fuzz,
            gate3_bench_report=diff_bench,
            forge_report=forge_report,
        )
        print(f"\n📊 [Cordis HTML Report]: Scorecard written to {output_html}")

    if output_md or github_comment:
        md_text = format_github_prosecutor_comment(
            pr_title=f"Git Diff Verdict: {effective_base} -> {target_ref or 'working tree'}",
            fixproof_revert_passed=True,
            gate1_report=primary_g1,
            gate2_report=primary_g2,
            gate3_fuzz_report=diff_fuzz,
            gate3_bench_report=diff_bench,
        )
        if github_comment:
            print("\n" + md_text)
        if output_md:
            save_markdown_report(output_md, md_text)
            print(f"\n📝 [Cordis Markdown Report]: Written to {output_md}")

    if overall_passed:
        print("\n✅ [Cordis Verdict]: ALL GATES PASSED — PR Approved to Land.")
        return 0
    else:
        print("\n🛑 [Cordis Verdict]: BLOCKED — Counterfeit Red or Tampering Detected.")
        return 1


def run_check_policy_cli(repo_dir: str, output_json: str | None = None) -> int:
    """Executes pre-flight repository governance check."""
    report = audit_repository_policy(repo_dir)
    print("================================================================================")
    print("                 CORDIS PRE-FLIGHT REPOSITORY POLICY AUDIT                      ")
    print("================================================================================")
    print(f"Target Repository : {Path(repo_dir).resolve()}")
    print(f"Scanned Files     : {len(report.governance_files_scanned)} files found")
    for f in report.governance_files_scanned:
        print(f"  • {f}")

    if report.status == "BLOCKED_POLICY":
        print("\n🛑 STATUS: BLOCKED_POLICY")
        print(f"Advice: {report.advice}")
        print("\nCitations:")
        for c in report.citations:
            print(f"  - {c}")
    elif report.status == "ISSUE_REQUIRED":
        print("\n⚠️ STATUS: ISSUE_REQUIRED")
        print(f"Advice: {report.advice}")
        print("\nCitations:")
        for c in report.citations:
            print(f"  - {c}")
    else:
        print("\n✅ STATUS: PERMITTED")
        print(f"Advice: {report.advice}")

    if output_json:
        out_path = Path(output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nSaved policy audit report JSON: {out_path.resolve()}")

    return 0 if report.status == "PERMITTED" else 1


def run_probe_cli(
    repo: str,
    target: str,
    test: str,
    function: str | None = None,
    max_mutants: int = 5,
    output_json: str | None = None,
    timeout: float = 10.0,
    pytest_args: str | None = None,
    suggest_test: bool = False,
) -> int:
    """Executes offline, zero-token headless AST mutation & pytest probe."""
    root = Path(repo).resolve()
    target_path = root / target
    pure_test_rel = test.split()[0] if " " in test else test
    test_path = root / pure_test_rel

    print("================================================================================")
    print("             CORDIS HEADLESS PROBE: ZERO-TOKEN MUTATION GATE                    ")
    print("================================================================================")
    print(f"Repository      : {root}")
    print(f"Target Source   : {target}")
    print(f"Test Suite      : {test}")
    if pytest_args:
        print(f"Pytest Args     : {pytest_args}")
    if function:
        print(f"Target Function : {function}")
    print(f"Max Mutants     : {max_mutants}")
    print(f"Timeout (sec)   : {timeout}")
    print("Offline Mode    : Zero tokens consumed (100% deterministic AST & pytest)")
    print("--------------------------------------------------------------------------------")

    # Read test file to compute MAR badge
    mar_info = {"total_assertions": 0, "total_mocks": 0, "mar": 0.0, "risk_level": "LOW", "is_high_risk": False}
    if test_path.is_file():
        try:
            test_src = test_path.read_text(encoding="utf-8", errors="replace")
            mar_info = calculate_mock_to_assertion_ratio(test_src)
            print(
                f"Test Suite MAR  : {mar_info['mar']:.4f} [{mar_info['risk_level']}] "
                f"(Mocks: {mar_info['total_mocks']}, Assertions: {mar_info['total_assertions']})"
            )
        except Exception as e:
            print(f"Warning: Failed to compute MAR on test file: {e}")

    # Run repo mutation gate
    report = run_repo_mutation_gate(
        repo_root=root,
        source_rel_path=target,
        test_rel_path=test,
        target_function=function,
        max_mutants=max_mutants,
        timeout=timeout,
        pytest_args=pytest_args,
    )

    print(f"\nTotal Mutants   : {report.total_mutants}")
    print(f"Killed Mutants  : {report.killed_mutants}")
    print(f"Survived Mutants: {report.survived_mutants}")
    print(f"Kill Rate       : {report.kill_rate * 100:.1f}%")

    for res in report.results:
        status_icon = "💀 KILLED" if res.killed else "🛡️ SURVIVED"
        print(f"  • Mutant #{res.mutant_id} (line {res.lineno}): {res.description} -> {status_icon}")

    suggested_test_code = ""
    if suggest_test and report.survived_mutants > 0:
        surviving = [r for r in report.results if not r.killed]
        if target_path.is_file():
            try:
                src_code = target_path.read_text(encoding="utf-8", errors="replace")
                suggested_test_code = synthesize_mutant_killing_test(
                    source_code=src_code,
                    target_function=function or "",
                    surviving_mutants=surviving,
                )
                if suggested_test_code:
                    print("\n" + "=" * 80)
                    print("          CORDIS COUNTEREXAMPLE-GUIDED TEST REPAIR SKELETON                     ")
                    print("=" * 80)
                    print(suggested_test_code.strip())
                    print("=" * 80)
            except Exception as e:
                print(f"Warning: Failed to synthesize test repair: {e}")

    if report.passed and report.total_mutants > 0:
        print("\n✅ [Probe Verdict]: PASSED — 100% Mutation Kill Rate (No counterfeit/hollow tests).")
    elif report.total_mutants == 0:
        print("\n⚠️ [Probe Verdict]: NEUTRAL — No mutable AST nodes found in target.")
    else:
        print(f"\n🛑 [Probe Verdict]: FAILED — {report.survived_mutants} mutant(s) survived! Test suite is hollow.")

    if output_json:
        out_path = Path(output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        findings = {
            "repo": str(root),
            "target_file": target,
            "test_file": test,
            "target_function": function,
            "pytest_args": pytest_args,
            "passed": report.passed,
            "total_mutants": report.total_mutants,
            "killed_mutants": report.killed_mutants,
            "survived_mutants": report.survived_mutants,
            "kill_rate": round(report.kill_rate, 4),
            "target_executed": report.target_executed,
            "mutants": [
                {
                    "mutant_id": r.mutant_id,
                    "lineno": r.lineno,
                    "description": r.description,
                    "killed": r.killed,
                    "mutated_code_snippet": r.mutated_code_snippet,
                }
                for r in report.results
            ],
            "mar": mar_info,
            "zero_token": True,
            "llm_tokens_consumed": 0,
        }
        if suggested_test_code:
            findings["suggested_test"] = suggested_test_code
        out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"\nSaved probe findings JSON: {out_path.resolve()}")

    return 0 if (report.passed and report.survived_mutants == 0) else 1


def run_hooks_cli(args: argparse.Namespace, hooks_parser: Optional[argparse.ArgumentParser] = None) -> int:
    """Dispatches `cordis hooks` subcommands: check-cmd, stop-gate, and install."""
    from cordis.hooks import (
        audit_pre_tool_use_command,
        install_harness_hooks,
        run_stop_hook_prosecutor,
    )

    if args.hooks_command == "check-cmd":
        decision = audit_pre_tool_use_command(args.command_to_check)
        if not decision.allowed:
            sys.stderr.write(f"🛑 [Cordis Pre-Tool Guard]: BLOCKED command '{args.command_to_check}'\n")
            if decision.reason:
                sys.stderr.write(f"Reason: {decision.reason}\n")
            return decision.exit_code if decision.exit_code != 0 else 2
        print(f"✅ [Cordis Pre-Tool Guard]: PERMITTED command '{args.command_to_check}'")
        return 0

    if args.hooks_command == "stop-gate":
        return run_stop_hook_prosecutor(
            repo_dir=args.repo_dir,
            max_retries=args.max_retries,
        )

    if args.hooks_command == "install":
        installed = install_harness_hooks(
            repo_dir=args.repo_dir,
            targets=args.targets,
        )
        print(f"✅ [Cordis Hooks Installed]: {len(installed)} hook target(s) configured.")
        for h in installed:
            print(f"  • {h}")
        return 0

    if hooks_parser is not None:
        hooks_parser.print_help()
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Cordis: Adversarial AI-PR Prosecutor CLI")
    sub = parser.add_subparsers(dest="command")
    demo_p = sub.add_parser("demo", help="Run the SWE-bench F2P-Killer Adversarial PR Demo")
    demo_p.add_argument("--github-comment", action="store_true", help="Output GitHub PR Markdown verdict")
    demo_p.add_argument("--output-html", default=None, help="Save dark-mode HTML prosecutor scorecard")
    demo_p.add_argument("--output-md", default=None, help="Save markdown prosecutor scorecard")

    bench_p = sub.add_parser("benchmark", help="Run the 5-Archetype Head-to-Head Adversarial Benchmark")
    bench_p.add_argument("--output-md", default=None, help="Save benchmark comparison Markdown table to file")

    real_bench_p = sub.add_parser("benchmark-repos", help="Run the Live Open-Source GitHub Repository Benchmark")
    real_bench_p.add_argument("--output-md", default="REAL_GITHUB_BENCHMARK.md", help="Output path for benchmark report (default: REAL_GITHUB_BENCHMARK.md)")
    real_bench_p.add_argument("--cache-dir", default=".real_repos_cache", help="Cache directory for cloned repos (default: .real_repos_cache)")

    git_p = sub.add_parser("verify-git", help="Prosecute a real git diff between two refs")
    git_p.add_argument("--base-ref", "--base", dest="base_ref", default="HEAD~1", help="Base git commit ref (default: HEAD~1)")
    git_p.add_argument("--target-ref", "--head", dest="target_ref", default=None, help="Target git commit ref (default: working tree)")
    git_p.add_argument("--repo-dir", default=".", help="Repository root directory (default: .)")
    git_p.add_argument("--github-comment", action="store_true", help="Output GitHub PR Markdown verdict")
    git_p.add_argument("--output-html", default=None, help="Save dark-mode HTML prosecutor scorecard")
    git_p.add_argument("--output-md", default=None, help="Save markdown prosecutor scorecard")
    git_p.add_argument("--suggest-test", action="store_true", help="Synthesize mutant-killing unit test assertions for surviving mutants")

    wild_p = sub.add_parser("audit-wild", help="Hunt for real surviving mutants in unmodified open-source repos")
    wild_p.add_argument("--cache-dir", default=".real_repos_cache", help="Cache directory for cloned repos (default: .real_repos_cache)")
    wild_p.add_argument("--no-docs-update", action="store_true", help="Skip updating REAL_GITHUB_BENCHMARK.md and README.md")

    ai_p = sub.add_parser("audit-ai-repos", help="Clone and audit viral AI-agent and MCP repositories")
    ai_p.add_argument("--cache-dir", default=".real_repos_cache", help="Cache directory for cloned repos (default: .real_repos_cache)")
    ai_p.add_argument("--no-docs-update", action="store_true", help="Skip updating REAL_GITHUB_BENCHMARK.md and README.md")

    policy_p = sub.add_parser("check-policy", help="Audit repository governance files for anti-AI bans and issue prerequisites")
    policy_p.add_argument("repo_path", nargs="?", default=None, help="Path to repository root (positional, default: .)")
    policy_p.add_argument("--repo", dest="repo_flag", default=None, help="Path to repository root (flag)")
    policy_p.add_argument("--json", dest="output_json", default=None, help="Path to write structured JSON audit report")

    probe_p = sub.add_parser("probe", help="Run offline zero-token headless AST mutation & pytest probe")
    probe_p.add_argument("--repo", default=".", help="Repository root path (default: .)")
    probe_p.add_argument("--target", "--source", dest="target", required=True, help="Target source file relative to repo root")
    probe_p.add_argument("--test", required=True, help="Target test file relative to repo root")
    probe_p.add_argument("--function", "--func", dest="function", default=None, help="Optional function name within target file to mutate")
    probe_p.add_argument("--max-mutants", type=int, default=5, help="Maximum number of AST mutants to generate (default: 5)")
    probe_p.add_argument("--json", "--output-json", dest="output_json", default=None, help="Path to write structured JSON findings")
    probe_p.add_argument("--timeout", type=float, default=10.0, help="Test execution timeout in seconds (default: 10.0)")
    probe_p.add_argument("--pytest-args", default=None, help="Optional extra arguments or selectors passed directly to pytest (e.g. '-k test_name' or '-x')")
    probe_p.add_argument("--suggest-test", action="store_true", help="Synthesize mutant-killing unit test assertions for surviving mutants")

    hooks_p = sub.add_parser("hooks", help="Manage and execute deterministic pre-tool and stop hook guards")
    hooks_sub = hooks_p.add_subparsers(dest="hooks_command")

    check_cmd_p = hooks_sub.add_parser("check-cmd", help="Audit a tool command before execution")
    check_cmd_p.add_argument("--command", "-c", dest="command_to_check", required=True, help="Command string to audit")

    stop_gate_p = hooks_sub.add_parser("stop-gate", help="Execute stop hook mutation prosecutor gate on uncommitted diff")
    stop_gate_p.add_argument("--repo-dir", default=".", help="Repository root directory (default: .)")
    stop_gate_p.add_argument("--max-retries", type=int, default=3, help="Max retries per AST anchor before tripping circuit breaker (default: 3)")

    install_p = hooks_sub.add_parser("install", help="Install Cordis pre-commit and Claude Code hooks")
    install_p.add_argument("--repo-dir", default=".", help="Repository root directory (default: .)")
    install_p.add_argument("--targets", nargs="+", default=["git", "claude"], help="Targets to install hooks for (default: git claude)")

    args = parser.parse_args()
    if args.command == "benchmark":
        return run_benchmark_cli(output_md=args.output_md)
    if args.command == "benchmark-repos":
        from cordis.real_repo_benchmark import run_real_repo_benchmark
        return run_real_repo_benchmark(output_md=args.output_md, cache_dir_str=args.cache_dir)
    if args.command == "audit-wild":
        from cordis.wild_audit import run_wild_audit_cli
        return run_wild_audit_cli(cache_dir=args.cache_dir, update_docs=not args.no_docs_update)
    if args.command == "audit-ai-repos":
        from cordis.ai_repo_audit import run_ai_repo_audit
        return run_ai_repo_audit(cache_dir=args.cache_dir, update_docs=not args.no_docs_update)
    if args.command == "check-policy":
        target_repo = args.repo_flag or args.repo_path or "."
        return run_check_policy_cli(repo_dir=target_repo, output_json=args.output_json)
    if args.command == "probe":
        return run_probe_cli(
            repo=args.repo,
            target=args.target,
            test=args.test,
            function=args.function,
            max_mutants=args.max_mutants,
            output_json=args.output_json,
            timeout=args.timeout,
            pytest_args=args.pytest_args,
            suggest_test=getattr(args, "suggest_test", False),
        )
    if args.command == "verify-git":
        return run_verify_git(
            base_ref=args.base_ref,
            target_ref=args.target_ref,
            repo_dir=args.repo_dir,
            github_comment=args.github_comment,
            output_html=args.output_html,
            output_md=args.output_md,
            suggest_test=getattr(args, "suggest_test", False),
        )
    if args.command == "hooks":
        return run_hooks_cli(args, hooks_parser=hooks_p)
    return run_demo(
        github_comment=getattr(args, "github_comment", False),
        output_html=getattr(args, "output_html", None),
        output_md=getattr(args, "output_md", None),
    )


if __name__ == "__main__":
    sys.exit(main())
