<div align="center">

# ⚙️ Cordis CLI Command Reference

**Comprehensive manual for the `cordis` and `cordis-verify` command-line interfaces.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-success.svg?style=flat-square)](https://docs.python.org/3/)
[![License: MIT](https://img.shields.io/badge/license-MIT-informational.svg?style=flat-square)](../LICENSE)

---

</div>

## 📌 Global Syntax

```bash
cordis [SUBCOMMAND] [OPTIONS]
# or via the alias
cordis-verify [SUBCOMMAND] [OPTIONS]
```

### Global Options
- `-h, --help`: Display command usage information and exit.
- `-v, --version`: Print the installed Cordis version and exit.

---

## 🛠️ Subcommands

### 1. `cordis demo`
Runs the interactive SWE-bench F2P-killer adversarial PR demonstration. Simulates an AI agent submitting a Pull Request containing a single-input overfit and weakened assertions, demonstrating how standard test runners are fooled while Cordis intercepts and blocks the PR.

```bash
cordis demo [OPTIONS]
```

#### Options:
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--github-comment` | Flag | `False` | Print simulated GitHub PR markdown comment with scorecard tables. |
| `--output-html PATH` | String | `None` | Path to save the interactive dark-mode HTML forensic scorecard. |
| `--output-md PATH` | String | `None` | Path to save the markdown PR verdict scorecard. |

#### Example:
```bash
cordis demo --github-comment --output-html scorecard.html
```

---

### 2. `cordis verify-git`
Extracts the unified AST git diff between the current working tree and a target git reference, then executes the 4-gate adversarial prosecution pipeline.

```bash
cordis verify-git [OPTIONS]
```

#### Options:
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--base-ref REF` | String | `HEAD~1` | Base git reference or commit SHA to diff against. |
| `--github-comment` | Flag | `False` | Format terminal output as a GitHub PR forensic markdown comment. |
| `--output-html PATH` | String | `None` | Export full dark-mode HTML scorecard. |
| `--output-md PATH` | String | `None` | Export markdown verdict report (ideal for `$GITHUB_STEP_SUMMARY`). |
| `--strict-fp` | Flag | `False` | Fail on maintainer PRs if any invariant warnings are raised. |
| `--suggest-test` | Flag | `False` | When surviving mutants are caught, synthesize copy-pasteable, mutant-killing test assertions using differential constant-harvested input generation. |

#### Polyglot TypeScript / JavaScript Support:
`verify-git` automatically detects modified TypeScript and JavaScript files (`.ts`, `.tsx`, `.js`, `.jsx`). When test modifications are encountered, it invokes `cordis/ts_gate.py` to audit Jest/Vitest assertions:
- Identifies transitions from strong equality checks to hollow assertions (`.toBeDefined()`, `.not.toBeNull()`, `.toBeTruthy()`).
- Flags tautological assertions (`expect(true).toBe(true)`, `expect(1).toBe(1)`).
- Computes the Mock-to-Assertion Ratio (MAR) across `vi.mock`, `jest.mock`, `vi.spyOn`, and `jest.spyOn`, raising hard blocks if target functions under test are mocked out.
- Detects newly added skip directives (`it.skip`, `test.skip`, `describe.skip`, `xit`, `xtest`).
- Synthesizes diff-scoped TypeScript in-place AST mutants (`===` $\leftrightarrow$ `!==`, `<=` $\leftrightarrow$ `<`, `&&` $\leftrightarrow$ `||`, `return null`).

#### Example:
```bash
cordis verify-git --base-ref origin/main --output-md cordis_verdict.md --suggest-test
```

---

### 3. `cordis probe`
Headless zero-token mutation probe. Executes Gate 1 (Anti-Tamper & MAR) and Gate 2 (In-Place AST Mutation) against a specific target file and function using the local test suite. Consumes zero LLM tokens and executes 100% deterministically.

```bash
cordis probe --source PATH --test PATH --func NAME [OPTIONS]
```

#### Required Arguments:
- `--source PATH`: Relative or absolute path to the target implementation file (`.py`, `.ts`, `.tsx`, `.js`, `.jsx`).
- `--test PATH`: Relative or absolute path to the associated test file (`test_*.py`, `*.test.ts`, `*.spec.ts`, etc.).
- `--func NAME`: Exact name of the function or method to mutate and probe.

#### Options:
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--pytest-args ARGS` | String | `""` | Pass arbitrary arguments directly to pytest (e.g. `"-k test_exact_name"`). |
| `--max-mutants INT` | Integer | `5` | Maximum number of AST mutants to generate and evaluate. |
| `--timeout SEC` | Float | `10.0` | Maximum test runner execution timeout per mutant in seconds. |
| `--output-json PATH` | String | `None` | Path to export machine-readable JSON forensic probe report. |
| `--suggest-test` | Flag | `False` | When surviving mutants are caught, synthesize a copy-pasteable, mutant-killing test function using differential constant-harvested input generation. |

#### Polyglot Prosecution Support:
`--source` supports both Python (`.py`) and TypeScript/JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`) files. When targeting TypeScript files with associated Jest/Vitest test suites, `probe` applies pure-stdlib AST anchor extraction and in-place mutant evaluation.

#### Example:
```bash
cordis probe \
  --source cordis/policy_guard.py \
  --test tests/test_cordis.py \
  --func audit_repository_policy \
  --pytest-args "-k test_policy_guard_allowed" \
  --suggest-test
```

---

### 4. `cordis benchmark`
Executes the 5-archetype synthetic benchmark suite head-to-head against standard `pytest`, SWE-bench `Fail-to-Pass` (`git revert`), and static LLM diff reviewers.

```bash
cordis benchmark [OPTIONS]
```

#### Options:
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--iterations INT` | Integer | `1` | Number of benchmark runs to average latency telemetry. |
| `--output-json PATH` | String | `None` | Export raw benchmark JSON data. |

---

### 5. `cordis benchmark-repos`
Executes the empirical repository benchmark across the 6 core open-source repositories (`click`, `boltons`, `python-dotenv`, `fastmcp`, `smolagents`, `nao-mgs-workflow`).

```bash
cordis benchmark-repos [OPTIONS]
```

#### Options:
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--output-md PATH` | String | `REAL_GITHUB_BENCHMARK.md` | Path to save updated benchmark report. |

---

### 6. `cordis audit-wild`
Audits unmodified upstream codebases to identify genuine test gaps and surviving AST mutants in production software.

```bash
cordis audit-wild [OPTIONS]
```

#### Options:
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--no-docs-update` | Flag | `False` | Skip auto-updating markdown documentation with discovered mutants. |

---

### 7. `cordis audit-ai`
Audits AI-engineered and `CLAUDE.md`-driven repositories for git attribution trailers, Mock-to-Assertion Ratios (MAR), and hollow test suites.

```bash
cordis audit-ai [OPTIONS]
```

---

### 8. `cordis hooks`
Autonomous agent runtime lifecycle supervisor and pre-commit anti-bypass prosecutor. Protects repository integrity against agent pre-commit bypasses (`git commit --no-verify`), hook tampering, and context compaction eviction.

```bash
cordis hooks [ACTION] [OPTIONS]
```

#### Actions:

##### 1. `cordis hooks check-cmd`
Executes the deterministic `PreToolUse` shell firewall. Evaluates bash and PowerShell command lines to intercept and block circumvention attempts.
- Syntax:
  ```bash
  cordis hooks check-cmd --command "<command-string>"
  # or short flag
  cordis hooks check-cmd -c "<command-string>"
  ```
- Enforced Policies:
  - Blocks `git commit --no-verify` (`-n`).
  - Blocks `git config core.hooksPath` redirection.
  - Blocks deletion or tampering of `.git/hooks`.
  - Blocks stash-based pre-commit bypasses (`git stash; git commit`).
- Exit Codes: Exits with `2` (blocked) if a bypass pattern is detected; exits `0` if safe.

##### 2. `cordis hooks stop-gate`
Executes the `Stop` lifecycle verification prosecutor before an agent turn terminates or claims completion.
- Syntax:
  ```bash
  cordis hooks stop-gate [--repo-dir <path>] [--max-retries <int>]
  ```
- Options:
  | Flag | Type | Default | Description |
  | :--- | :--- | :--- | :--- |
  | `--repo-dir PATH` | String | `.` | Root path of the target git repository. |
  | `--max-retries INT` | Integer | `3` | Maximum retry attempts before the 3-strike circuit breaker trips. |
- Diagnostic Format:
  Emits structured, actionable feedback using Bounded Output Ring Buffering (<30 lines) to avoid context window blowup. Governed by a 3-strike circuit breaker ($K_{\max} = 3$) in episodic state to prevent infinite auto-repair loops.

##### 3. `cordis hooks install`
Automates configuration and installation of lifecycle hooks across local git and coding agent settings.
- Syntax:
  ```bash
  cordis hooks install [--repo-dir <path>] [--target git|claude|all]
  ```
- Options:
  | Flag | Type | Default | Description |
  | :--- | :--- | :--- | :--- |
  | `--repo-dir PATH` | String | `.` | Target repository directory. |
  | `--target TARGET` | String | `all` | Target environment to install hooks: `git` (`.git/hooks/pre-commit`), `claude` (`.claude/settings.local.json`), or `all`. |

---

## 🚦 Exit Codes

Cordis uses POSIX standard exit codes for seamless CI/CD integration:

| Exit Code | Meaning | CI Implication |
| :---: | :--- | :--- |
| `0` | **VERIFIED / APPROVED** | All AST invariants hold; test tampering score 0; 100% mutants killed; zero regressions. |
| `1` | **PROSECUTION BLOCKED** | Counterfeit Red detected (weakened asserts, target mocked, surviving mutant, or fuzz counterexample). |
| `2` | **USAGE / CONFIG ERROR** | Invalid arguments, missing files, or unrecognized CLI flags. |

---

## 🔐 Environment Variables

| Variable | Description |
| :--- | :--- |
| `GITHUB_ACTOR` | Injected by GitHub Actions; inspected by Gate 0 ForgeGuard. |
| `GITHUB_TRIGGERING_ACTOR` | Injected by GitHub Actions to detect automated bot self-triggers. |
| `GITHUB_EVENT_NAME` | Context for PR vs. push vs. schedule evaluation. |
| `CORDIS_STRICT` | If set to `1`, treats warnings as hard blocks. |
