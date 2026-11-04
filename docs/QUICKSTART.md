<div align="center">

# ⚡ Cordis Quickstart Guide

**Get up and running with adversarial AI-PR verification in under 60 seconds.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/cordis-verify.svg?style=flat-square&color=blue)](https://pypi.org/project/cordis-verify/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-success.svg?style=flat-square)](https://docs.python.org/3/)
[![License: MIT](https://img.shields.io/badge/license-MIT-informational.svg?style=flat-square)](../LICENSE)

---

</div>

## 📦 1. Installation

Cordis requires **Python 3.10+** and has **zero external runtime dependencies** — it runs entirely on the Python Standard Library (`ast`, `dis`, `sqlite3`, `unittest`, `dataclasses`, `difflib`).

### Option A: Instant Run with `uvx` (Recommended — Zero Installation)
Run the interactive adversarial demo instantly without modifying your environment:
```bash
uvx cordis-verify demo
```

### Option B: Install via `pip` or `uv`
```bash
# With uv (recommended)
uv tool install cordis-verify

# With pip
pip install cordis-verify
```

Verify your installation:
```bash
cordis --help
```

---

## 🚀 2. Core Workflows in 60 Seconds

### A. Run the Interactive Counterfeit Red Demo
Simulate a live pull request where an AI agent attempts to pass CI using a **single-input overfit** and a **weakened hollow assertion** (`assert x is not None`). Watch Cordis's 4 gates intercept and block it in ~67ms:

```bash
cordis demo
```

To generate a full dark-mode HTML forensic scorecard:
```bash
cordis demo --github-comment --output-html cordis_report.html
```

### B. Prosecute a Local Git Branch or Pull Request
Audit the diff between your current branch and a base reference (`main` or `HEAD~1`):

```bash
# Prosecute the latest commit against HEAD~1
cordis verify-git --base-ref HEAD~1

# Prosecute a feature branch against main with a markdown summary
cordis verify-git --base-ref origin/main --output-md cordis_verdict.md
```

### C. Headless Zero-Token Mutation Probe (`cordis probe`)
Test any single Python function and its associated unit test file to ensure test assertions are mathematically rigorous and not hollow:

```bash
cordis probe --source calc.py --test tests/test_calc.py --func parse_discount
```

Pass custom pytest flags (e.g. scoping to a specific test or marker) for sub-second execution:
```bash
cordis probe --source cordis/policy_guard.py --test tests/test_cordis.py --func audit_repository_policy --pytest-args "-k test_policy_guard_allowed"
```

### D. Run the Head-to-Head Synthetic Benchmark Suite
Compare Cordis head-to-head against standard `pytest`, SWE-bench `Fail-to-Pass` (`git revert`), and LLM diff reviewers across the 5 canonical agent cheat archetypes:

```bash
cordis benchmark
```

### E. Run the Live Production Repository Benchmark
Execute Cordis against 6 real production codebases (`click`, `boltons`, `python-dotenv`, `fastmcp`, `smolagents`, `nao-mgs-workflow`):

```bash
cordis benchmark-repos
```

---

## 🤖 3. Drop-In GitHub Actions CI Workflow

Add automated adversarial prosecution to your repository in under 2 minutes. Create `.github/workflows/cordis.yml`:

```yaml
name: Cordis Adversarial AI-PR Prosecutor

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  prosecute:
    name: Cordis 4-Gate Invariant Verification
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 2 # Required for diff extraction against HEAD~1

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run Test Suite
        run: |
          python -m unittest discover -s tests -v

      - name: Run Cordis Invariant Prosecutor
        run: |
          python -m cordis.cli verify-git \
            --base-ref HEAD~1 \
            --github-comment \
            --output-html cordis_report.html \
            --output-md cordis_report.md
        env:
          GITHUB_ACTOR: ${{ github.actor }}
          GITHUB_TRIGGERING_ACTOR: ${{ github.triggering_actor }}
          GITHUB_EVENT_NAME: ${{ github.event_name }}

      - name: Publish Step Summary
        if: always()
        run: |
          if [ -f cordis_report.md ]; then
            cat cordis_report.md >> $GITHUB_STEP_SUMMARY
          fi

      - name: Upload Forensic Scorecard
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cordis-scorecard
          path: cordis_report.html
```

---

## 🔍 4. Understanding Cordis Verdicts

When Cordis evaluates a Pull Request, it outputs one of two deterministic states:

| Verdict | Meaning | Action Taken |
| :--- | :--- | :--- |
| 🟢 **APPROVED TO LAND** | 100% of modified AST invariants preserved; zero test tampering; all mutants killed; zero fuzz regressions. | PR marked as clean; CI passes with exit code `0`. |
| 🛑 **BLOCKED** | Counterfeit Red detected (weakened assertions, target function mocked, surviving mutant, or differential counterexample). | PR blocked with exit code `1`; forensic markdown scorecard posted. |

---

## 📚 5. Next Steps

- 🏛️ [**Architecture Deep Dive**](ARCHITECTURE.md) — How the 4 deterministic gates work under the hood.
- ⚙️ [**CLI Reference**](CLI_REFERENCE.md) — Comprehensive reference for all flags, options, and commands.
- 🤖 [**CI/CD Integration Guide**](CI_CD_INTEGRATION.md) — Enterprise GitHub Actions and pre-commit setup.
- 📊 [**Empirical Benchmarks**](BENCHMARKS.md) — Telemetry across 281,948 AST functions.
