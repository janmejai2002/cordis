# CLAUDE.md — Cordis Developer & Agent Guide

> **Cordis: Independent Adversarial AI-PR & AST Invariant Prosecutor**  
> Zero-token, deterministic AST mutation engine, adversarial test tampering firewall, and differential fuzzer for Python & TypeScript/JavaScript codebases.

---

## 1. System Architecture & Core Modules

Cordis inspects code changes using a multi-gate adversarial pipeline designed to prevent AI agents (and human developers) from gaming test suites via tautological assertions, hollow mocks, or silent regressions.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CORDIS PROSECUTOR                             │
├──────────────────┬───────────────────┬──────────────────┬───────────────┤
│      Gate 1      │      Gate 2       │      Gate 3      │   Firewall    │
│  AST Anti-Tamper │   AST Mutator     │ Differential     │ Pre-Tool &    │
│   & Mock Ratio   │  Execution Gate   │ Invariant Fuzz   │ Stop Hooks    │
└─────────┬────────┴─────────┬─────────┴────────┬─────────┴───────┬───────┘
          │                  │                  │                 │
    ast_gate.py         mutator.py          fuzzer.py         hooks.py
    ts_gate.py          repair.py        forge_guard.py    policy_guard.py
```

### Module Responsibilities

| Module | Core Purpose |
| :--- | :--- |
| `cordis/ast_gate.py` | **Gate 1**: Analyzes Python ASTs to detect assertion tampering, tautological tests (`assert True`, `assert x == x`, `assert res is not None`), and computes Mock-to-Assertion Ratio (MAR). |
| `cordis/ts_gate.py` | **TypeScript Gate**: Lexical AST masking, function anchor indexing (BLAKE2b 16-hex), and relational/boolean mutant synthesis for TS/JS files. |
| `cordis/mutator.py` | **Gate 2**: In-memory and disk-based AST mutation engine. Injects boundary flips, constant corruptions, and canary mutations; runs test cycles to measure kill rate. |
| `cordis/repair.py` | **Automated Test Synthesis**: Analyzes surviving mutants, discovers differentiating inputs via candidate generation, and synthesizes concrete unit tests to achieve 100% kill rate. |
| `cordis/fuzzer.py` | **Gate 3**: Differential invariant fuzzer. Harvests `co_consts` and AST constants to expose magic number overfits, boundary slips, and type coercion bugs. |
| `cordis/hooks.py` | **Autonomous Agent Firewall**: Provides `pre-tool` and `stop-gate` hooks for Claude Code / AGY, ensuring unverified diffs are never committed or merged. |
| `cordis/forge_guard.py` | **Provenance Guard**: Detects synthetic AI hallucinations, forged commit signatures, and unverified AI patch artifacts. |
| `cordis/policy_guard.py` | **Pre-Flight Governance**: Scans `CONTRIBUTING.md`, `README.md`, and repository governance rules for anti-AI submission bans. |
| `cordis/cli.py` | Unified CLI entrypoint exposed as `cordis` and `cordis-verify`. |

---

## 2. Development & Testing Commands

Cordis is built to run cleanly with standard Python (>=3.10) without heavy external dependencies.

### Environment Setup
```powershell
# Using uv (recommended)
uv venv
.venv\Scripts\activate
uv pip install -e ".[dev]"
```

### Running the Test Suite
```powershell
# Run the complete test suite (171 tests across all units and stress suites)
python -m unittest discover -s tests -v

# Or run via pytest
pytest -v
```

### Running the Mutation Probe
Probe any Python function to calculate its mutant kill rate and detect hollow assertions:
```powershell
# Probe an isolated function
python -m cordis.cli probe --source cordis/ast_gate.py --test tests/test_cordis.py --func audit_test_tampering

# Probe with automated test synthesis (generates assertions for surviving mutants)
python -m cordis.cli probe --source cordis/mutator.py --test tests/test_cordis.py --func run_repo_mutation_gate --suggest-test
```

### Repository Governance Check
```powershell
# Check for anti-AI bans before opening PRs against open-source repositories
python -m cordis.cli check-policy --repo .
```

### Installing Agent Hooks
```powershell
# Install git pre-commit hook and agent stop-gate
python -m cordis.cli hooks install
```

---

## 3. Strict Rules for AI Agents (Claude / Antigravity)

When working on Cordis or in any repository guarded by Cordis:

1. **Zero-Token Offline Priority**:
   - The entire Cordis prosecution and mutation engine is 100% deterministic and runs offline. Never introduce external API calls or LLM dependencies into the core verification loop.
2. **Never Weaken Assertions**:
   - Never replace a specific check (`assertEqual(res, 42)`) with a weak tautology (`assertIsNotNone(res)` or `assertTrue(True)`). Cordis Gate 1 will flag and block this immediately.
3. **100% Mutant Kill Rate**:
   - Any new core function added to Cordis must achieve a 100% mutant kill rate when evaluated by `cordis.cli probe`. If a mutant survives, write a targeted invariant test in `tests/test_stress_challenger.py`.
4. **Surgical, Targeted Edits**:
   - Never regenerate an entire module when modifying code. Use surgical diffs, match existing naming conventions, and preserve documentation and typing annotations.
5. **AST Integrity & Backward Compatibility**:
   - Maintain compatibility across Python 3.10 through 3.13. For AST operations, always instantiate required fields (such as `ast.BinOp(left=..., op=..., right=...)`) to avoid Python 3.15 deprecation warnings.

---

## 4. Package Build & Deployment Workflow

### Building the Package
```powershell
# Build standard sdist and wheel using uv or build
uv build
```

### Automated PyPI Release via Git Tag
Publishing is automated via GitHub Actions (`.github/workflows/publish-pypi.yml`):
```bash
# 1. Update version in pyproject.toml and cordis/__init__.py
# 2. Commit and tag
git tag v0.3.0
git push origin v0.3.0
```
This triggers the `Publish cordis-verify to PyPI` workflow, builds the wheel, generates release notes, and uploads the package to PyPI using the repository secret `PYPI_API_TOKEN`.
