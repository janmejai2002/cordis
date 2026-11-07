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

## 🛡️ Gate 0: ForgeGuard & PolicyGuard (`cordis/forge_guard.py` & `cordis/policy_guard.py`)

### Problem
Frontier autonomous agents (Cursor, Devin, Claude Code, GitHub Copilot Workspace) can collaborate via bot tokens, request automated reviews, and trigger auto-merge actions without meaningful human dual-custody. Additionally, agents routinely ignore repository-specific policies (e.g. anti-AI contribution bans, mandatory issue linking requirements) or bypass git hooks via `--no-verify`.

### Prosecutorial Mechanism
ForgeGuard and PolicyGuard inspect GitHub event context, git commit trailers, cryptographic attestations, and repository governance:
1. **Actor Integrity Check**: Compares `GITHUB_ACTOR` with `GITHUB_TRIGGERING_ACTOR` and commit author email domains.
2. **AI Attribution & Dual-Custody**: Parses commit trailers (`Co-Authored-By: Claude Opus <noreply@anthropic.com>`, `Co-Authored-By: Cursor Agent`, `Signed-off-by: Devin`). Rejects self-approved automated pull requests without verified human dual-custody.
3. **Cryptographic Attestation Receipt**: Generates and verifies 16-hex BLAKE2b digests (`Cordis-Attestation: ¶<16hex>`) across modified AST anchors and kill rates, preventing hook circumvention.
4. **Repository Policy Scraper**: Scans `CONTRIBUTING.md`, `README.md`, `.github/PULL_REQUEST_TEMPLATE/`, and `SECURITY.md` for anti-AI contributor bans and mandatory issue prerequisite rules (`BLOCKED_POLICY` / `ISSUE_REQUIRED`).
5. **Hook Tampering Detection**: Flags stripped executable permissions on `.git/hooks/pre-commit` or `core.hooksPath` overrides targeting `/dev/null` or suppressed targets.

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

#### 2. Weighted Mock-to-Assertion Ratio (Weighted MAR)
Cordis computes the diagnostic ratio of mocking operations to concrete behavioral assertions, separating external I/O boundaries from toxic internal domain mocking:
$$\text{Weighted MAR} = \frac{1.0 \times \text{Internal Mocks} + 0.25 \times \text{Boundary Mocks}}{\max(1, \text{Total Assertions})}$$

- **Boundary Mocks**: Legitimate external I/O (e.g., `requests`, `httpx`, `boto3`, `subprocess`, `os.environ`, `time.sleep`).
- **Internal Mocks**: Toxic intra-package function mocking that isolates execution from real domain logic.
- **Thresholds**: `< 0.10 [LOW]`, `0.10–0.25 [MODERATE]`, `> 0.25 [HIGH_RISK]`.

#### 3. AST Assertion De-Sugarer & Hollow Checker
Every `ast.Assert`, `ast.Try`, and `ast.With` node is inspected:
- **Tautological Assertions**: Direct syntactic tautologies (`assert True`, `assert 1 == 1`, `assert x == x`) and dataflow aliased comparisons (`expected = f(x); actual = f(x); assert actual == expected`).
- **Oracle-Free Comparisons**: Flags test assertions that compare two dynamic function calls without a single concrete literal or ground-truth oracle.
- **Hollow Nullity Checks**: Flagged when an equality check is weakened to `is not None` or `isinstance(..., object)`.
- **Target Function Mocking**: Hard violation if test code patches the function under test.
- **Exception Suppression & Broad Oracles**: Flags bare `except: pass`, `except Exception: pass`, and broad `pytest.raises(Exception)` without `match=` or specific exception subclasses.

---

## 💀 Gate 2: In-Place AST Mutator ("Counterfeit Red" Killer) (`cordis/mutator.py`)

### Problem
A test suite can report 100% line coverage while asserting nothing of value. Standard line coverage measures whether lines were stepped over during execution, not whether assertions verify output correctness. Furthermore, naive mutation testing wastes compute on equivalent mutants and logging code.

### Prosecutorial Mechanism
Gate 2 performs **targeted, diff-scoped in-place AST mutation**:
1. **Google-Style Arid-Node Pruning**: Scans the AST to prune unproductive nodes before mutation:
   - Skips logging (`logging.*`, `logger.*`), `print()`, `warnings.warn()`, and tracing spans.
   - Skips `if TYPE_CHECKING:` and `if __name__ == '__main__':` blocks.
   - Applies **Tie-Boundary Equivalence Filtering**: Prunes `<` $\leftrightarrow$ `<=` shifts in `if x < limit: return limit` clamp patterns where $x = \text{limit}$ yields identical outputs across both branches.
2. **IEEE-754 NaN Canary Poisoning**: Injects `return float('nan')` canaries alongside `return None`. In IEEE 754, `NaN == NaN` is always `False`. If `return None` survives while `return float('nan')` is killed, Gate 2 deterministically fingerprints an **Indirect Wrapper Tautology** (`assert wrapper(x) == target(x)`).
3. **High-Priority Security & Protocol Operators**:
   - **Security Kwarg Inversion**: Flips boolean security flags (`verify=True` $\leftrightarrow$ `False`, `trust_env`, `check_hostname`, `shell`).
   - **Resource Teardown Elision**: Replaces `.close()`, `.aclose()`, `.release()` with `pass` to verify resource cleanup assertions.
4. **Execution Safety Harness**: Cordis creates a safe in-place backup (`.cordis.bak`) and executes the repository's test runner against each mutant in-memory. Startup recovery and `atexit` hooks guarantee working tree cleanliness even in the event of SIGINT or hard crashes.
5. **The "Counterfeit Red" Verdict**:
   - If tests fail when logic is mutated $\rightarrow$ **MUTANT KILLED (Test is Honest & Rigorous)**.
   - If tests still exit `0` when logic is mutated $\rightarrow$ **MUTANT SURVIVED (HOLLOW TEST DETECTED 🛑)**.

---

## 🎯 Gate 3: Differential Property Fuzzer & Latency Gate (`cordis/fuzzer.py`)

### Gate 3A: Constant-Harvesting Differential Property Fuzzing
When an agent fixes a bug or refactors a function, it often introduces silent regressions on unexercised domains. Gate 3A executes differential fuzzing comparing $f_{\text{old}}(x)$ vs. $f_{\text{new}}(x)$:
- **AST Constant Harvesting**: Inspects `co_consts` and AST literals from both functions:
  - Int boundaries: $\{C-1, C, C+1\}$.
  - Multi-hop buffer seeds: If $1024 \le C \le 2\times 10^6$ (e.g. `CHUNK_SIZE = 65536`), generates $\{C-1, C, C+1, 2C+1\}$ bytes/strings.
  - String literals: Injects $\{S, S+\text{'_mut'}, S.\text{upper}()\}$ from comparison operators.
- **200-Vector Adversarial Matrix**: Evaluates floating point anomalies (`NaN`, `+inf`, `-inf`, `-0.0`), integer boundaries, unicode strings, and nested empty collections.
- Outside the bug fix's declared domain, Cordis mathematically asserts:
  $$f_{\text{spec}}(x) \equiv f_{\text{pr}}(x)$$
  Any divergence produces a deterministic counterexample input.

### Gate 3B: GC-Pinned Mann-Whitney U Latency Benchmark
To prevent silent micro-regressions and accidental exponential-time complexity in AI refactors, Gate 3B runs a **30-round interleaved Mann-Whitney U non-parametric statistical test**:
- **GC Isolation**: Pinned execution with `gc.disable()` during measurements eliminates garbage collection jitter.
- **Telemetry**: Reports median speedup, Hodges-Lehmann shift estimator, and Interquartile Range (IQR $P_{75} - P_{25}$).
- Null Hypothesis $H_0$: Latency distribution of $f_{\text{new}}$ is identical to $f_{\text{old}}$ ($p < 0.01$).

---

## ⚡ Autonomous Hook Firewall (`cordis/hooks.py`)

Cordis provides runtime lifecycle integration for agentic harnesses (Claude Code, Antigravity CLI, Cursor):
- **PreToolUse Anti-Bypass Firewall**: Intercepts shell and Python execution before execution, terminating with exit code `2` on attempts to bypass pre-commit hooks (`git commit -n`, `--no-verify`, `core.hooksPath` redirection, `.git/hooks` deletion, or `git stash --keep-index`).
- **Stop Lifecycle Gate**: Intercepts agent turn completion (`SubagentStop`), executing git diff verification. Formats concise (<30 line) remediation directives and enforces a 3-strike circuit breaker ($K_{\max} = 3$) to prevent infinite loops.

---

## 🛠️ Automated Invariant Repair Synthesizer (`cordis/repair.py`)

When surviving mutants are identified by Gate 2 or `cordis probe --suggest-test`:
1. Compiles original function $f_{\text{orig}}$ alongside surviving mutant implementations $f_{\text{mutant}}$.
2. Evaluates constant-harvested boundary inputs to identify minimal differential arguments $\vec{x}^*$ where $f_{\text{orig}}(\vec{x}^*) \ne f_{\text{mutant}}(\vec{x}^*)$.
3. Synthesizes concrete unit test assertions (`assert func(*x) == expected`) that kill 100% of surviving mutants without token consumption.

---

## 🌐 Polyglot TypeScript / JavaScript AST Gate (`cordis/ts_gate.py`)

Cordis provides zero-dependency TypeScript/JavaScript verification using standard Python:
- **Lexical Masking Scanner**: Handles single/multi-line comments, template literals with nested `${...}` expressions, and regex literals without external node binaries.
- **Function Anchor Indexing**: Extracts arrow functions, function declarations, class methods, and computed symbols with deterministic 16-hex BLAKE2b digests.
- **Diff-Scoped Mutation Synthesis**: Synthesizes relational operator mutations (`===` $\leftrightarrow$ `!==`, `<` $\leftrightarrow$ `>=`) and detects hollow assertions (`toBeDefined()`, `not.toBeNull()`).

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
