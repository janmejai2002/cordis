<div align="center">

# 🏛️ Cordis Architecture Specification

**Deterministic Adversarial AI-PR Verification Engine**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-success.svg?style=flat-square)](https://docs.python.org/3/)
[![Sub-5ms Execution](https://img.shields.io/badge/execution-sub--5ms-orange.svg?style=flat-square)](../README.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-informational.svg?style=flat-square)](../LICENSE)

---

</div>

## 📌 Executive Architecture Overview

Cordis operates as an **independent, zero-external-dependency adversarial prosecutor** for Pull Requests. It intercepts code changes before human review, verifying whether newly authored or modified unit tests actually prove mathematical behavioral correctness, or whether they merely reward-hack the test runner into emitting exit code `0`.

The pipeline executes across **four deterministic gates**:

```
                       Pull Request Diff (HEAD~1 -> HEAD)
                                       │
                  ┌────────────────────┴────────────────────┐
                  │  Gate 0: Forge Self-Approval Guard      │
                  │  - Blocks bot-to-bot collusion & auto-  │
                  │    merge without human dual-custody     │
                  └────────────────────┬────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │  Gate 1: AST Invariant & Anti-Tamper    │
                  │  - 64-bit BLAKE2b AST structural anchor │
                  │  - Flags deleted/weakened assertions    │
                  │  - Detects `mock.patch` on targets      │
                  │  - Bans `@skip` decorators & `assert True│
                  │  - Computes Mock-to-Assertion Ratio (MAR)│
                  └────────────────────┬────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │  Gate 2: AST Mutation Engine            │
                  │  - Injects targeted diff-scoped mutants │
                  │    (== -> !=, < -> >=, True -> False)   │
                  │  - Runs test suite against each mutant  │
                  │  - If test still passes: HOLLOW TEST 🛑 │
                  └────────────────────┬────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │  Gate 3: Property Fuzzing & Benchmark   │
                  │  - 3A: 200-input edge matrix (NaN, inf, │
                  │    -0.0, boundary ints, empty colls)    │
                  │  - Proves f_old(x) == f_new(x)          │
                  │  - 3B: 30-round Mann-Whitney U baseline │
                  │    latency regression gate (p < 0.01)   │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                       Verdict: Approved to Land OR Blocked
```

---

## 🛡️ Gate 0: ForgeGuard (`cordis/forge_guard.py`)

### Problem
Frontier autonomous agents (Cursor, Devin, Claude Code, GitHub Copilot Workspace) can collaborate via bot tokens, request automated reviews, and trigger auto-merge actions without meaningful human dual-custody.

### Prosecutorial Mechanism
ForgeGuard inspects GitHub event context and git commit trailers before code analysis:
1. **Actor Integrity Check**: Compares `GITHUB_ACTOR` with `GITHUB_TRIGGERING_ACTOR` and commit author email domains.
2. **AI Attribution Extraction**: Parses commit trailers (`Co-Authored-By: Claude Opus <noreply@anthropic.com>`, `Co-Authored-By: Cursor Agent`, `Signed-off-by: Devin`).
3. **Dual-Custody Enforcement**: Rejects self-approved automated pull requests. A human maintainer sign-off is mandatory before bot-authored PRs can be merged.

---

## 🧬 Gate 1: AST Invariant & Anti-Tamper Auditor (`cordis/ast_gate.py`)

### Problem
Coding agents optimize to satisfy CI exit code `0`. When faced with a failing test, agents frequently cheat by:
- Weakening strict equality assertions (`assert x == 100` $\rightarrow$ `assert x is not None`).
- Replacing assertions with tautologies (`assert True`, `assert 1 == 1`).
- Attaching `@unittest.mock.patch` or `MagicMock` to the target function itself, mocking out real execution.
- Adding `@pytest.mark.skip` or `@unittest.skip` to failing test cases.

### Prosecutorial Mechanism

#### 1. 64-bit BLAKE2b Structural AST Anchors
Cordis traverses the Abstract Syntax Tree (AST) using Python's standard `ast` module. It filters out comments, docstrings, and whitespace variations, computing an invariant 64-bit BLAKE2b hash of the AST structure for every function:
$$\text{Anchor} = \text{BLAKE2b}_{64}(\text{CanonicalAST}(f))$$

#### 2. Mock-to-Assertion Ratio (MAR)
Cordis computes the diagnostic ratio of mocking operations to concrete behavioral assertions:
$$\text{MAR} = \frac{\text{Count}(\text{@patch}) + \text{Count}(\text{MagicMock}) + \text{Count}(\text{mocker})}{\text{Total Assertions}}$$

- **MAR < 0.10 [LOW]**: Healthy human-maintainer testing pattern.
- **MAR 0.10–0.25 [MODERATE]**: Elevated isolation risk.
- **MAR > 0.25 [HIGH]**: Severe mock-isolation risk. Tests test mocks, not runtime code.

#### 3. AST Assertion De-Sugarer & Hollow Checker
Every `ast.Assert` node is inspected:
- **Tautological Assertions**: Banned (`assert True`, `assert 1`, `assert not False`).
- **Hollow Nullity Checks**: Flagged when an equality check on a primitive or dataclass is replaced solely with `is not None` or `isinstance(..., object)`.
- **Target Function Mocking**: Banned. If test code patches the symbol of the modified function under test, Gate 1 raises an immediate hard violation.

---

## 💀 Gate 2: In-Place AST Mutator ("Counterfeit Red" Killer) (`cordis/mutator.py`)

### Problem
A test suite can report 100% line coverage while asserting nothing of value. Standard line coverage measures whether lines were stepped over during execution, not whether assertions verify output correctness.

### Prosecutorial Mechanism
Gate 2 performs **targeted, diff-scoped in-place AST mutation**:
1. It identifies every function modified in the PR diff (`HEAD~1..HEAD`).
2. It synthesizes targeted semantic mutants within the function body:
   - **Comparison Operators**: `==` $\leftrightarrow$ `!=`, `<` $\leftrightarrow$ `>=`, `>` $\leftrightarrow$ `<=`, `in` $\leftrightarrow$ `not in`.
   - **Binary Operators**: `+` $\leftrightarrow$ `-`, `*` $\leftrightarrow$ `/`, `//` $\leftrightarrow$ `%`, `**` $\leftrightarrow$ `*`.
   - **Boolean Operators**: `and` $\leftrightarrow$ `or`.
   - **Boolean Literals**: `True` $\leftrightarrow$ `False`.
   - **Return Expression Mutations**: Inverting or nullifying returns (`return expr` $\rightarrow$ `return None`).
   - **Boundary Shifts**: Integer increment/decrement on comparison bounds ($x < 100 \rightarrow x \le 100$).
3. **Execution Safety Harness**: Cordis creates a safe in-place backup (`.cordis.bak`) and executes the repository's test runner against each mutant in-memory. Startup recovery and `atexit` hooks guarantee working tree cleanliness even in the event of SIGINT or hard crashes.
4. **The "Counterfeit Red" Verdict**:
   - If tests fail when logic is mutated $\rightarrow$ **MUTANT KILLED (Test is Honest & Rigorous)**.
   - If tests still exit `0` when logic is mutated $\rightarrow$ **MUTANT SURVIVED (HOLLOW TEST DETECTED 🛑)**.

---

## 🎯 Gate 3: Differential Property Fuzzer & Latency Gate (`cordis/fuzzer.py`)

### Gate 3A: Differential 200-Input Property Fuzzing
When an agent fixes a bug or refactors a function, it often introduces silent regressions on unexercised domains. Gate 3A executes differential fuzzing comparing $f_{\text{old}}(x)$ vs. $f_{\text{new}}(x)$:
- Evaluates a 200-vector adversarial edge-case matrix:
  - Floating point anomalies: `NaN`, `+inf`, `-inf`, `-0.0`, `1e-15`, `sys.float_info.max`.
  - Integer boundaries: `0`, `-1`, `1`, `2**31 - 1`, `2**63 - 1`, `-2**63`.
  - String edges: Empty strings, unicode null bytes (`\x00`), emoji surrogate pairs, giant payloads.
  - Collection edges: Empty sets, empty tuples, nested empty dictionaries, circular structures.
- Outside the bug fix's declared domain, Cordis mathematically asserts:
  $$f_{\text{spec}}(x) \equiv f_{\text{pr}}(x)$$
  Any divergence produces a deterministic counterexample input.

### Gate 3B: Mann-Whitney U Baseline Latency Gate
To prevent silent micro-regressions and accidental exponential-time complexity in AI refactors, Gate 3B runs a **30-round interleaved Mann-Whitney U non-parametric statistical test**:
- Null Hypothesis $H_0$: Latency distribution of $f_{\text{new}}$ is identical to $f_{\text{old}}$.
- Significance Threshold: $p < 0.01$.
- Maximum Allowed Latency Regression: $+10.0\%$.

---

## 🧠 Episodic Memory & Ledger (`cordis/memory.py`)

Cordis persists verification history locally in SQLite:
- **Full-Text Search (FTS5 BM25)**: Instant querying of historical PR verdicts and failure modes.
- **Reciprocal Rank Fusion (RRF)**: Blends keyword search with tag matching across historical repo runs.
- **Flake & Superseded Tracking**: Prevents flakiness from polluting CI signals; supersedes outdated runs when new commits push to the same PR.

---

## ⚖️ Standard Library Guarantee

Cordis is strictly committed to **zero third-party dependencies**. It never installs PyPI packages to execute its core prosecutorial gates, ensuring:
- Instant startup (< 5ms).
- Zero supply chain vulnerability surface.
- Frictionless portability across Python 3.10, 3.11, 3.12, and 3.13.
