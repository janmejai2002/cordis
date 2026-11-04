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

#### Example:
```bash
cordis verify-git --base-ref origin/main --output-md cordis_verdict.md
```

---

### 3. `cordis probe`
Headless zero-token mutation probe. Executes Gate 1 (Anti-Tamper & MAR) and Gate 2 (In-Place AST Mutation) against a specific target file and function using the local test suite. Consumes zero LLM tokens and executes 100% deterministically.

```bash
cordis probe --source PATH --test PATH --func NAME [OPTIONS]
```

#### Required Arguments:
- `--source PATH`: Relative or absolute path to the target Python implementation file.
- `--test PATH`: Relative or absolute path to the associated test file.
- `--func NAME`: Exact name of the Python function to mutate and probe.

#### Options:
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--pytest-args ARGS` | String | `""` | Pass arbitrary arguments directly to pytest (e.g. `"-k test_exact_name"`). |
| `--max-mutants INT` | Integer | `5` | Maximum number of AST mutants to generate and evaluate. |
| `--timeout SEC` | Float | `10.0` | Maximum test runner execution timeout per mutant in seconds. |
| `--output-json PATH` | String | `None` | Path to export machine-readable JSON forensic probe report. |

#### Example:
```bash
cordis probe \
  --source cordis/policy_guard.py \
  --test tests/test_cordis.py \
  --func audit_repository_policy \
  --pytest-args "-k test_policy_guard_allowed"
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
