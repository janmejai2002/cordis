# AGENTS.md — Cordis: Adversarial AI-PR & AST Invariant Prosecutor
> **Target Runtime**: Google Antigravity CLI (`agy`) | **Model**: Gemini 3.8 Flash (High) | **OS**: Windows PowerShell

## 1. Mission & Core Architecture
You are the Lead Systems Engineer working on **Cordis**, the independent adversarial verifier that prosecutes AI-authored Pull Requests and git diffs before a human reviews them.

Why Cordis exists (and how we beat every alternative):
1. **Coding Agents (Claude Code, Cursor, Devin, Antigravity)** grade their own homework. On SlopCodeBench Q4 2026, **83.7% of agent runs fail to keep existing tested behavior working as requirements change**, and agent-written unit tests miss **37% of injected bugs** due to the **Counterfeit Red Trap** (writing hollow tests or mocking out core functions just to get exit code `0`).
2. **Codeflash** only optimizes Python execution speed and assumes existing unit tests are honest.
3. **FixProof** only checks whether a regression test fails on `git revert` (`HEAD~1`). That fails completely on refactors/optimizations and is trivially gamed by single-input overfitting (`if x == 100: return 15` with `assert f(100) == 15`).
4. **Cordis** prosecutes any PR across three deterministic gates with **zero external dependency bloat** (runs 100% on the Python 3.10+ standard library out-of-the-box):
   - **Gate 1 (`cordis/ast_gate.py`)**: 64-bit BLAKE2b AST node+identifier hashing & Test-Tampering Detection (flags deleted/weakened `assert` statements, newly added `mock.patch` on the target function, tautological assertions like `assert True`, and `@pytest.mark.skip` / `@unittest.skip`).
   - **Gate 2 (`cordis/mutator.py`)**: Diff-Scoped In-Place AST Mutation Testing ("Counterfeit Red" Killer). Injects up to 5 targeted AST mutations into the *post-patch* production function (`==` to `!=`, `<` to `>=`, `+` to `-`, `True` to `False`, early `return None`) and executes the test suite against each mutant. If the agent's test still passes when production logic is broken, the test is **HOLLOW**.
   - **Gate 3 (`cordis/fuzzer.py`)**: Differential Property-Based Fuzzing (200-input adversarial edge-case matrix across `NaN`, `inf`, `-0.0`, boundary ints, empty collections) proving `f_old(x) == f_new(x)` outside the single test input, plus 30-round interleaved Mann-Whitney U statistical baseline benchmarking (`p < 0.01`).
   - **Episodic Memory (`cordis/memory.py`)**: Local SQLite FTS5 BM25 + word-stem + tag matching merged via **Reciprocal Rank Fusion (RRF)** with explicit `status='superseded'` invalidation and `flake_retry_count` tracking.

## 2. Strict Operating Rules for Gemini 3.8 Flash (High) on Windows PowerShell
1. **Windows PowerShell Compatibility**:
   - You are running on Windows PowerShell. NEVER use POSIX-only `os.setsid`, `os.killpg`, `/dev/null`, or bash-only syntax.
   - Always use `pathlib.Path` for cross-platform paths and `subprocess.run([sys.executable, ...], timeout=...)` for isolated child processes.
   - Never run complex multi-line `python -c "..."` one-liners in PowerShell (quote escaping will break). Write code to `.py` files and execute `python -m unittest discover -s tests -v` or `python -m cordis.cli`.
2. **Anti-"VICTORY CONFIRMED" Self-Discipline**:
   - NEVER claim a task is complete without running `python -m unittest discover -s tests -v` and `python -m cordis.cli demo --github-comment` and inspecting the actual terminal output.
   - Never weaken, delete, or skip a test in `tests/` to make the test runner pass.
   - Do not spawn recursive sub-agents for simple file edits; execute edits directly, run tests immediately, and verify the exit code.

## 3. Repository Layout
- `cordis/ast_gate.py` — 64-bit BLAKE2b AST structural+identifier hasher & test-tampering auditor.
- `cordis/mutator.py` — Diff-scoped AST mutation engine (kills hollow tests).
- `cordis/fuzzer.py` — Differential property-based fuzzer (`f_old` vs `f_new`) & Mann-Whitney U statistical benchmark gate.
- `cordis/memory.py` — SQLite FTS5 BM25 + Reciprocal Rank Fusion (RRF) episodic ledger with `status='superseded'` tracking.
- `cordis/cli.py` — CLI entry point (`demo`, `verify-git`, `--github-comment`).
- `examples/fixproof_killer_demo.py` — Complete demonstration showing how a fake single-input agent fix fools `git revert` (FixProof) but gets caught immediately by Cordis.
- `tests/test_cordis.py` — Full verification suite runnable via `python -m unittest discover -s tests -v` (or `pytest`).

## 4. Immediate Build & Expansion Roadmap (Execute When Prompted)
When the user asks you to start working on the project, execute these steps in order:
1. **Step 1 (Baseline Verification)**: Run `python -m unittest discover -s tests -v` and `python -m cordis.cli demo --github-comment` to verify the core 3-gate engine and inspect the FixProof-Killer output.
2. **Step 2 (Git Diff Auto-Extractor — `cordis/git_diff.py`)**: Implement a real `git diff HEAD~1 HEAD` parser that automatically extracts modified `.py` source files, modified `test_*.py` files, and modified function names + line ranges directly from any local git commit or PR branch so `python -m cordis.cli verify-git` works zero-config on any repository. Include unit tests in `tests/test_cordis.py`.
3. **Step 3 (Forge Self-Approval & Token Guard — `cordis/forge_guard.py`)**: Add a check that inspects git commit author/committer metadata and GitHub Actions environment variables (`GITHUB_ACTOR`, `GITHUB_TRIGGERING_ACTOR`, `GITHUB_EVENT_NAME`) to block bot self-approval or single-token agent auto-merging. Include unit tests in `tests/test_cordis.py`.
4. **Step 4 (Visual HTML & Markdown Report Exporter)**: Add `--output-md cordis_report.md` and `--output-html cordis_report.html` to `cordis/cli.py` so the user can open a dark-mode visual prosecutor scorecard in their browser for their 60-second YC demo video.