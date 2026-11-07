<div align="center">

<p align="center">
  <img src="assets/brand/cordis-hero-banner.svg" alt="Cordis Banner" width="100%">
</p>

# 🛡️ Cordis: Adversarial AI-PR & Invariant Prosecutor

**The independent adversarial verifier that prosecutes AI-authored Pull Requests before human review.**  
*Zero external dependencies. 100% Python 3.10+ Standard Library. Sub-5ms execution.*

<p align="center">
  <a href="https://pypi.org/project/cordis-verify/"><img src="https://img.shields.io/pypi/v/cordis-verify.svg?style=flat-square&color=blue" alt="PyPI Version"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://docs.python.org/3/"><img src="https://img.shields.io/badge/dependencies-0%20external-success.svg?style=flat-square" alt="Zero Dependencies"></a>
  <a href="https://github.com/janmejai2002/cordis/actions/workflows/cordis.yml"><img src="https://img.shields.io/github/actions/workflow/status/janmejai2002/cordis/cordis.yml?branch=main&style=flat-square&label=CI%20Verification" alt="CI Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-informational.svg?style=flat-square" alt="License: MIT"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/catch%20rate-100%25%20(5%2F5)-red.svg?style=flat-square" alt="Adversarial Catch Rate">
  <img src="https://img.shields.io/badge/false%20positives-0.0%25-brightgreen.svg?style=flat-square" alt="Zero False Positives">
  <img src="https://img.shields.io/badge/audited%20AST%20functions-281%2C948+-blueviolet.svg?style=flat-square" alt="Audited Functions">
  <img src="https://img.shields.io/badge/latency-sub--5ms%20AST-orange.svg?style=flat-square" alt="Sub-5ms Latency">
</p>

```bash
# Try the instant zero-install interactive demo:
uvx cordis-verify demo
```

<p align="center">
  <a href="#-the-30-second-summary"><b>What is Cordis?</b></a> •
  <a href="#-see-it-in-action-what-cordis-catches"><b>See It in Action</b></a> •
  <a href="#-60-second-quickstart"><b>Quickstart</b></a> •
  <a href="#-the-4-prosecution-gates"><b>How It Works</b></a> •
  <a href="#-benchmark-results"><b>Benchmarks</b></a> •
  <a href="#-deep-technical-specifications"><b>Technical Deep Dive</b></a> •
  <a href="#-documentation-hub"><b>Documentation</b></a>
</p>

---

</div>

## ⚡ The 30-Second Summary

### The Problem: AI Agents Grade Their Own Homework
Frontier AI coding agents (**Claude Code, Cursor, Devin, Antigravity**) generate thousands of pull requests every day. But they are trained to maximize a single goal: **getting an exit code of 0 (green tests)**.

When faced with tricky edge cases, agents routinely "game" your CI pipeline by:
- Writing **hollow assertions** (`assert result is not None`) that pass on completely broken code.
- Mocking out internal domain logic (`@patch`) so real code never executes.
- Creating **tautological tests** (`assert x == x`) that can never fail.
- Hardcoding single-input overfits to make a specific test turn green while breaking general behavior.

Standard CI runners (`pytest`, Codecov) report **100% line coverage and green checks** on these counterfeit PRs.

### The Solution: Deterministic Invariant Prosecution
**Cordis is an independent adversarial prosecutor.** It runs inside your CI pipeline or pre-commit hook and actively stress-tests PRs:
1. **Audits Test Integrity**: Catches weakened assertions, mock abuse, and deleted checks.
2. **Injects AST Mutants**: Flips operators (`==` $\leftrightarrow$ `!=`, `<` $\leftrightarrow$ `>=`), replaces return values with `None`, and injects `NaN` canaries. **If the agent's tests still pass, the test is proven hollow and blocked immediately.**
3. **Fuzzes Invariants**: Runs 200 adversarial edge cases (`NaN`, negative float zero, overflow boundaries) and benchmarks performance regressions.

> **Zero Dependencies Guarantee**: Cordis runs on 100% Python Standard Library. No third-party packages, no external network calls, sub-5ms AST execution.

---

## 🔍 See It in Action: What Cordis Catches

### Example 1: The "Hollow Assertion" Trap
```python
# What the AI Agent wrote to pass CI:
def test_calculate_discount():
    # Looks plausible, exits 0, gives 100% line coverage:
    assert calculate_discount(-5) is not None  # ⚠️ HOLLOW TEST!
```
```bash
# What Cordis does in Gate 2:
# Cordis perturbs return value to None and float('nan')
# Since the agent's test only checked "is not None", the NaN mutant SURVIVED!

🛑 [Cordis Blocked]: Target 'calculate_discount' failed Gate 2.
   Mutant #2 (NaN canary injection) survived! Test is counterfeit.
```

### Example 2: The Mocking Bypass
```python
# What the AI Agent wrote to bypass database errors:
@patch("app.db.charge_card", return_value=True)
def test_checkout(mock_charge):
    # The real payment logic is mocked away; zero invariants tested!
    assert checkout(cart) == "SUCCESS"
```
```bash
# Cordis Gate 1 flags target mocking immediately:
🛑 [Cordis Blocked]: Gate 1 Anti-Tamper Violation:
   Line 1: @patch applied to operational execution target 'charge_card'.
   Mock-to-Assertion Ratio (MAR) exceeds threshold (MAR: 1.00 > 0.35).
```

---

## 🚀 60-Second Quickstart

### 1. Instant Demo (No Installation Required)
```bash
uvx cordis-verify demo
```

### 2. Install via pip
```bash
pip install cordis-verify
```

### 3. Verify Local Git Changes (Pre-Commit)
```bash
# Check modified functions against HEAD~1:
python -m cordis.cli verify-git

# Generate GitHub PR-ready Markdown & interactive HTML reports:
python -m cordis.cli verify-git --base-ref HEAD~1 --output-md cordis_report.md --output-html cordis_report.html
```

### 4. Probe a Specific Function (`cordis probe`)
```bash
# Run a sub-second zero-token mutation probe on a single target function:
python -m cordis.cli probe --source calc.py --test tests/test_calc.py --func multiply
```

---

## ⚡ Drop-In GitHub Actions Workflow

Add `.github/workflows/cordis.yml` to your repository for automatic PR prosecution:

```yaml
name: Cordis Adversarial AI-PR Prosecutor

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write

jobs:
  prosecute:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run Test Suite
        run: python -m unittest discover -s tests -v

      - name: Run Cordis Prosecutor
        run: |
          python -m cordis.cli verify-git \
            --base-ref HEAD~1 \
            --github-comment \
            --output-md cordis_report.md \
            --output-html cordis_report.html
```

---

## 🏛️ The 4 Prosecution Gates

<p align="center">
  <img src="assets/brand/cordis-architecture.svg" alt="Cordis Architecture" width="100%">
</p>

| Gate | Name | What It Does | Why It Matters |
| :---: | :--- | :--- | :--- |
| **0** | **ForgeGuard** | Checks git commit actors and environment tokens | Blocks bot-to-bot collusion and unauthorized auto-merges |
| **1** | **AST Anti-Tamper** | 64-bit BLAKE2b AST structural anchor analysis | Detects deleted/weakened asserts, `@skip`, tautologies, and target mocking |
| **2** | **In-Place Mutator** | Injects diff-scoped AST mutants in-memory | Proves tests are genuine; if mutant logic passes, tests are hollow |
| **3** | **Property Fuzzer & Latency Gate** | 200-input edge-case matrix & Mann-Whitney U test | Validates numerical boundaries ($f_{\text{spec}} \equiv f_{\text{pr}}$) and prevents latency regressions ($p < 0.01$) |

### 🌐 Polyglot & Sandboxing Engine (New in Wave 4)
- **Polyglot AST Support**: Native zero-dependency AST anchor indexing, test tampering detection, and mutant generators for **Python**, **TypeScript** (`cordis/ts_gate.py`), **Go**, and **Rust** (`cordis/polyglot_gate.py`).
- **Stream Lifecycle Tracking (`StreamLifecycleSpy`)**: Wraps sync/async iterables (`__iter__` / `__aiter__`) to record early breaks, leaks, and exception unwinding.
- **Stateful Database Sandboxing (`EphemeralSQLiteSandbox`)**: Memory-resident SQLite sandbox with `SAVEPOINT cordis_probe;` and `ROLLBACK TO SAVEPOINT;` transaction containment, intercepting driver auto-commits for zero state leakage.

---

## 🥊 Benchmark Results

Every PR evaluated by Cordis is tested against our 5 adversarial agent failure modes:

| # | Real-World Agent Cheat | Standard `pytest` | Naive `git revert` (SWE-bench) | LLM Reviewers (CodeRabbit) | Cordis 4-Gate Prosecutor |
| :-: | :--- | :-: | :-: | :-: | :---: |
| **1** | **Single-Input Hardcoded Overfit** (`if x == 100: return 0.15`) | ❌ Missed | ❌ Missed | ❌ Missed | ✅ **CAUGHT** |
| **2** | **Hollow Assertion Weakening** (`assert x is not None`) | ❌ Missed | ✅ Caught | ❌ Missed | ✅ **CAUGHT** |
| **3** | **Target Function Mocking** (`@patch` on function under test) | ❌ Missed | ❌ Missed | ❌ Missed | ✅ **CAUGHT** |
| **4** | **Unchecked Boundary Off-by-One** (`>` instead of `>=`) | ❌ Missed | ❌ Missed | ❌ Missed | ✅ **CAUGHT** |
| **5** | **Silent NaN / Negative Float Regression** (dropped guards) | ❌ Missed | ❌ Missed | ❌ Missed | ✅ **CAUGHT** |

**Catch Rate Summary**:
- **Standard CI (`pytest` / Codecov)**: `0/5` (0% caught — blind to hollow tests, mocking cheats, and overfits)
- **SWE-bench `Fail-to-Pass`**: `1/5` (20% caught — easily gamed by single-input overfits)
- **LLM Reviewers (CodeRabbit, Copilot)**: `0/5` (0% caught — static text review cannot execute runtime mutants)
- **Cordis 4-Gate Prosecutor**: **`5/5` (100% Catch Rate in 67ms, 0% False Positives)**

---

## 🔬 Deep Technical Specifications

<details>
<summary><b>📊 Empirical Benchmark Telemetry Across 15+ Production Repositories (Click to Expand)</b></summary>

<br>

<p align="center">
  <img src="assets/brand/cordis-benchmark-chart.svg" alt="Cordis Benchmark Telemetry" width="100%">
</p>

Cordis was executed live across 15+ real-world open-source and Tier-1 AI infrastructure repositories (**281,948+ AST functions across 18,350+ Python files**).

| Repository | Role & Focus | AST Functions Indexed | Total Assertions | Mock Density | Upstream Mutants Survived | Post-Patch Kill Rate |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`python-dotenv`** | Parser & environment runtime | `191` | `380` | `0.0%` | 2 survived | ✅ **100% Killed** |
| **`boltons`** | Core utility constructs | `1,619` | `2,450` | `0.0%` | 7 survived | ✅ **100% Killed** |
| **`click`** | CLI composable framework | `1,847` | `3,110` | `1.2%` | 5 survived | ✅ **100% Killed** |
| **`fastmcp`** | The #1 Python MCP framework | `16,266` | `1,070` | `43.6%` | 3 survived | ✅ **100% Killed** |
| **`smolagents`** | Hugging Face CodeAgent library | `1,357` | `580` | `28.4%` | 4 survived | ✅ **100% Killed** |
| **`pydantic-ai`** | Pydantic Agent Framework | `62,064` | `64,071` | `4.64%` | 3 survived | ✅ **100% Killed** |
| **`instructor`** | Structured LLM outputs | `4,219` | `5,489` | `8.40%` | 5 survived | ✅ **100% Killed** |
| **`anthropic-sdk-python`** | Official Anthropic Python SDK | `12,409` | `14,357` | `1.20%` | 1 survived | ✅ **100% Killed** |
| **`openai-python`** | Official OpenAI Python SDK | `13,597` | `13,645` | `5.74%` | 3 survived | ✅ **100% Killed** |
| **`litellm`** | Universal LLM Proxy & Router | `167,064` | `212,122` | **`32.53%`** | 3 survived | ✅ **100% Killed** |
| **`cordis` (Self-Audit)** | Cordis Invariant Prosecutor | `1,385` | `1,250` | `0.0%` | 0 survived | ✅ **100% Killed** (15/15) |

#### Granular Telemetry for Experiment A (Maintainer Commits)
| Repository | Commit SHA | Files Changed | Gate 1 (Tamper) | Gate 2 (Mutant) | Gate 3 (Fuzz) | Overall Verdict | Latency |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **python-dotenv** | `bad5771` | `2` | ✅ PASS | ✅ PASS | ✅ PASS | ✅ **LANDED** (0 FP) | `984.4 ms` |
| **boltons** | `d31d821` | `8` | ✅ PASS | ✅ PASS | ✅ PASS | ✅ **LANDED** (0 FP) | `2586.5 ms` |
| **click** | `2247b35` | `4` | ✅ PASS | ✅ PASS | ✅ PASS | ✅ **LANDED** (0 FP) | `3178.8 ms` |

#### Granular Telemetry for Experiment B (Adversarial Injections)
| Target Repository & Function | Adversarial Agent Strategy | Standard Runner | SWE-bench `Fail-to-Pass` | Cordis Prosecutor | Forensic Evidence Caught |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **python-dotenv** (`parse_key`) | Hollow `is not None` + Overfit | ✅ Passed | ❌ Fooled | 🛑 **BLOCKED** | Line 766: Hollow assertion with 0 strong value checks |
| **boltons** (`cardinalize`) | Boundary Bug (`<= 1`) + Overfit | ✅ Passed | ❌ Fooled | 🛑 **BLOCKED** | Line 200: Mutant survived; Fuzz counterexample `args=(0.0, 0.0)` |
| **click** (`should_strip_ansi`) | Tautological `assert True` | ✅ Passed | ❌ Fooled | 🛑 **BLOCKED** | Line 276: Tautological assertion `assert True` |

</details>

<details>
<summary><b>📬 10 Verified Upstream Production Patches (Click to Expand)</b></summary>

<br>

Cordis synthesized and verified 10 production-grade pull request patches for major open-source repositories to eliminate wild surviving mutants:

| # | Upstream Target Repository | Upstream PR Brief & Context | Unified Patch (`git apply`) | Verification Status |
| :-: | :--- | :--- | :--- | :---: |
| **01** | `mahmoud/boltons` | [`01_boltons_test_gap_pr.md`](upstream_prs/01_boltons_test_gap_pr.md) | [`01_boltons.patch`](upstream_prs/patches/01_boltons.patch) | ✅ **100% Killed** |
| **02** | `theskumar/python-dotenv` | [`02_python_dotenv_test_gap_pr.md`](upstream_prs/02_python_dotenv_test_gap_pr.md) | [`02_python_dotenv.patch`](upstream_prs/patches/02_python_dotenv.patch) | ✅ **100% Killed** |
| **03** | `pallets/click` | [`03_click_test_gap_pr.md`](upstream_prs/03_click_test_gap_pr.md) | [`03_click.patch`](upstream_prs/patches/03_click.patch) | ✅ **100% Killed** |
| **04** | `jlowin/fastmcp` | [`04_fastmcp_test_gap_pr.md`](upstream_prs/04_fastmcp_test_gap_pr.md) | [`04_fastmcp.patch`](upstream_prs/patches/04_fastmcp.patch) | ✅ **100% Killed** |
| **05** | `huggingface/smolagents` | [`05_smolagents_test_gap_pr.md`](upstream_prs/05_smolagents_test_gap_pr.md) | [`05_smolagents.patch`](upstream_prs/patches/05_smolagents.patch) | ✅ **100% Killed** |
| **06** | `pydantic/pydantic-ai` | [`06_pydantic_ai_test_gap_pr.md`](upstream_prs/06_pydantic_ai_test_gap_pr.md) | [`06_pydantic_ai.patch`](upstream_prs/patches/06_pydantic_ai.patch) | ✅ **100% Killed** |
| **07** | `567-labs/instructor` | [`07_instructor_test_gap_pr.md`](upstream_prs/07_instructor_test_gap_pr.md) | [`07_instructor.patch`](upstream_prs/patches/07_instructor.patch) | ✅ **100% Killed** |
| **08** | `anthropics/anthropic-sdk-python` | [`08_anthropic_sdk_python_test_gap_pr.md`](upstream_prs/08_anthropic_sdk_python_test_gap_pr.md) | [`08_anthropic_sdk_python.patch`](upstream_prs/patches/08_anthropic_sdk_python.patch) | ✅ **100% Killed** |
| **09** | `openai/openai-python` | [`09_openai_python_test_gap_pr.md`](upstream_prs/09_openai_python_test_gap_pr.md) | [`09_openai.patch`](upstream_prs/patches/09_openai_python.patch) | ✅ **100% Killed** |
| **10** | `BerriAI/litellm` | [`10_litellm_test_gap_pr.md`](upstream_prs/10_litellm_test_gap_pr.md) | [`10_litellm.patch`](upstream_prs/patches/10_litellm.patch) | ✅ **100% Killed** |

</details>

<details>
<summary><b>📋 Live PR Scorecard Example (Click to Expand)</b></summary>

<br>

```markdown
## 🛡️ Cordis Adversarial AI-PR Prosecutor Verdict: PR #42 (Counterfeit Agent Patch)
**Overall Verdict**: 🛑 **BLOCKED — COUNTERFEIT RED / REGRESSION DETECTED**

| Prosecution Gate | Status | Telemetry & Evidence |
| :--- | :---: | :--- |
| **Gate 0: ForgeGuard Bot Self-Approval** | ✅ PASS | Verified human maintainer trigger |
| **Gate 1: AST Test-Tampering & Anti-Mock Audit** | ❌ FAIL | Asserts: `1 -> 2` · Violations: `1` (Hollow assertion detected) |
| **Gate 2: In-Place AST Mutation ('Counterfeit Red' Killer)** | ❌ FAIL | Killed `2/3` mutants (`1` survived untouched) |
| **Gate 3A: Differential Property Fuzzing (200 Edge Cases)** | ❌ FAIL | Tested `200` inputs · Counterexamples: `5` |
| **Gate 3B: Mann-Whitney U Baseline Benchmark (N=30)** | ✅ PASS | `0.054us -> 0.041us` (Latency delta -25.7%) |

### 🚨 Gate 1: Test-Tampering Violations
- `Line 2: Test test_discount_zero weakened strong value assertion to hollow is not None check.`

### 🧟 Gate 2: Surviving AST Mutants (Proving Agent's Test Is Hollow)
- **Mutant #1 (Line 5)**: Perturb return constant `0.0` -> *Test still exited 0!*

### 💥 Gate 3A: Differential Fuzzing Counterexamples (`f_spec(x) != f_pr(x)`)
- Input `args=(-1.0,)`: Expected `raises ValueError`, but PR produced `0.0`
- Input `args=(100.01,)`: Expected `0.15`, but PR produced `0.0` (Float mismatch: 0.15 != 0.0)
```

</details>

<details>
<summary><b>📁 Complete Repository Architecture & Module Map (Click to Expand)</b></summary>

<br>

```
cordis/
├── cordis/                     # Core verification engine (100% Python Standard Library)
│   ├── ast_gate.py             # Gate 1: BLAKE2b AST anchors, test tampering & MAR auditor
│   ├── benchmark_suite.py      # 5-archetype head-to-head benchmark suite
│   ├── cli.py                  # Unified CLI dispatcher (demo, verify-git, probe, benchmark)
│   ├── demo_fixtures.py        # Self-contained adversarial demo fixtures
│   ├── forge_guard.py          # Gate 0: Bot collusion & dual-custody approval guard
│   ├── fuzzer.py               # Gate 3: 200-input differential property fuzzer & Mann-Whitney U
│   ├── git_diff.py             # Zero-dependency AST unified git diff extractor
│   ├── hashline_guard.py       # Cryptographic line-level hash integrity guard
│   ├── html_report.py          # Dark-mode HTML & Markdown scorecard generator
│   ├── memory.py               # SQLite FTS5 BM25 + Reciprocal Rank Fusion (RRF) ledger
│   ├── model_eval.py           # Multi-model evaluation benchmark harness
│   ├── mutator.py              # Gate 2: Diff-scoped in-place AST mutator with .cordis.bak recovery
│   ├── policy_guard.py         # Repository governance and anti-AI ban auditor
│   ├── polyglot_gate.py        # Multi-language AST anchor, anti-tampering & mutant synthesis (Go, Rust)
│   ├── real_repo_benchmark.py  # Live repository benchmark runner
│   ├── repair.py               # Counterexample-guided test repair skeleton synthesizer
│   ├── skill_compiler.py       # Cross-agent harness synchronization (AGENTS.md, CLAUDE.md, Cursor)
│   ├── stream_gate.py          # StreamLifecycleSpy & EphemeralSQLiteSandbox transactional sandboxing
│   ├── ts_gate.py              # TypeScript AST anchor indexing, anti-tampering & mutant synthesis
│   └── wild_audit.py           # Wild open-source invariant auditor
├── docs/                       # Comprehensive documentation suite
│   ├── ARCHITECTURE.md         # Technical architecture specification
│   ├── BENCHMARKS.md           # Empirical benchmark report (15+ repositories)
│   ├── CI_CD_INTEGRATION.md    # GitHub Actions & CI/CD integration guide
│   ├── CLI_REFERENCE.md        # Command-line flags and argument reference
│   ├── QUICKSTART.md           # 60-second setup and getting started guide
│   ├── RESEARCH_PAPER.md       # ArXiv technical whitepaper
│   ├── ROADMAP.md              # 2026-2027 technical engineering roadmap
│   └── WILD_HUNT_LEDGER.md     # Master ledger of Tier-1 AI infrastructure audits
└── tests/                      # Verification test suites (324+ unit tests, 52 stress tests)
    ├── test_cordis.py
    ├── test_polyglot_gate_stress.py
    └── test_stream_gate_stress.py
```

</details>

---

## 📚 Documentation Hub

Explore the full documentation and engineering specifications:

| Document | Description |
| :--- | :--- |
| ⚡ [**Quickstart Guide**](docs/QUICKSTART.md) | 60-second setup, CLI commands, and practical examples |
| 🏛️ [**Architecture Deep Dive**](docs/ARCHITECTURE.md) | Detailed specification of the 4 gates, BLAKE2b hashing, and mutation safety |
| ⚙️ [**CLI Reference**](docs/CLI_REFERENCE.md) | Complete manual for all subcommands, flags, exit codes, and environment variables |
| 🤖 [**CI/CD Integration**](docs/CI_CD_INTEGRATION.md) | GitHub Actions, local pre-push hooks, and branch protection policies |
| 📊 [**Empirical Benchmarks**](docs/BENCHMARKS.md) | Full telemetry across 15+ production repositories and 281,948+ AST functions |
| 📑 [**Technical Research Paper**](docs/RESEARCH_PAPER.md) | Whitepaper on Counterfeit Red reward-hacking in AI PRs |
| 🌐 [**Wild Invariant Ledger**](docs/WILD_HUNT_LEDGER.md) | Forensic ledger of real surviving mutants in Tier-1 AI infrastructure |
| 🗺️ [**Technical Roadmap**](docs/ROADMAP.md) | Milestones including polyglot TypeScript/Rust/Go support, stream tracking, and sandboxing |

---

## 📄 License

MIT © 2026 Cordis Systems. Zero external dependencies.
