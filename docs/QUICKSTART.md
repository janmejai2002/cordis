# Cordis Quickstart Guide

Cordis is an independent adversarial verifier designed to prosecute AI-authored code and Pull Requests before human review. It operates on pure Python standard library with zero runtime dependencies and sub-5ms AST execution.

---

## ⚡ 60-Second Setup

### 1. Installation

Install via `pip` or `uv`:

```bash
pip install cordis-verify
```

Or run directly without installing using `uvx`:

```bash
uvx cordis-verify demo
```

---

## 🚀 Key Commands

### 1. Run the SWE-bench F2P-Killer Adversarial PR Demo

Simulate a live pull request where an AI agent attempts to pass CI using a single-input overfit and a weakened assertion (`assert x is not None`):

```bash
cordis demo
```

### 2. Prosecute a Local Git Branch or PR

Verify code changes between the current branch and a base reference (e.g. `main` or `HEAD~1`):

```bash
cordis verify-git --base-ref HEAD~1 --github-comment --output-html cordis_report.html
```

### 3. Run the Live Production Repository Benchmark

Run Cordis against the 6 production open-source repositories (`click`, `boltons`, `python-dotenv`, `fastmcp`, `smolagents`, `nao-mgs-workflow`):

```bash
cordis benchmark-repos
```

### 4. Audit Untouched Code for Surviving Mutants

Audit any local Python module to find test suite blind spots:

```bash
cordis audit-wild
```

---

## 🤖 GitHub Actions CI/CD Integration

Add Cordis directly to your `.github/workflows/cordis.yml`:

```yaml
name: Cordis Invariant Prosecutor

on:
  pull_request:
    types: [opened, synchronize, reopened]

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

      - name: Run Cordis Invariant Prosecutor
        uses: janmejai2002/cordis@v0.2.0
        with:
          base-ref: 'HEAD~1'
```
