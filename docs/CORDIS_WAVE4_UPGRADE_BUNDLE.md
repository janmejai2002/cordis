# Cordis V3 Engine Upgrade: Stream Gate, Polyglot Gate & Hardened Invariant Verification

**Target Notebook**: `@cordis` (`notebooks/59101cbf-fe74-46a4-88a0-c3e547882220`)  
**Specification Ref**: `CORDIS_V3_ENGINE_UPGRADE_SPEC.md` (Upgrade 7.1, Upgrades 11.1–11.2)  
**Standard**: 100% Python 3.10+ Standard Library (0 External Dependencies)

---

## 1. Upgrade 11.1: Stream Gate (`cordis/stream_gate.py`)

### `StreamLifecycleSpy`
- **Purpose**: Wraps both synchronous (`Iterable`, `Iterator`) and asynchronous (`AsyncIterable`, `AsyncIterator`) stream generators to audit lifecycle events.
- **Leak Detection**: Catches unfinished streams on early `break`, uncaught exceptions, and generator suspension by asserting `started=True`, `closed=True`, and `exhausted=True`.
- **Python 3.12+ Normalization**: Standardizes `.throw()` and `.athrow()` signatures from legacy 3-arg `(typ, val, tb)` to single-argument `throw(exc)` / `athrow(exc)`. Accurately increments `yield_count` even when generators handle exceptions and yield recovery values.

### `EphemeralSQLiteSandbox`
- **Purpose**: In-memory database sandboxing (`sqlite3.connect(":memory:")`) enabling stateful database queries, ORM migrations, and SQL functions to be mutated and fuzzed with zero disk I/O and zero state leakage across probes.
- **Savepoint Isolation**: Wraps probed execution within `SAVEPOINT cordis_probe;` and rolls back to `ROLLBACK TO SAVEPOINT cordis_probe;`.
- **CPython `executescript()` Mitigation**: Intercepts CPython's internal pre-execution `COMMIT` in `sqlite3.Connection.executescript` by splitting multi-statement scripts and routing each statement through `_SandboxCursorProxy`.
- **Comment-Stripping & Command Interception**: Strips SQL comments (`--` and `/* */`) and intercepts raw `COMMIT`, `END`, and `RELEASE` commands before driver execution, rewriting SQL `ROLLBACK` to scoped savepoint rollbacks.

---

## 2. Upgrade 11.2 & 7.1: Polyglot Gate & TypeScript Mutants

### `cordis/ts_gate.py` (Upgrade 7.1)
- Cleanly exports `generate_ts_mutants(source_code: str, target_function: Optional[str] = None, max_mutants: int = 5) -> List[Tuple[str, int, str]]` in `__all__` alongside `index_ts_ast_anchors` and `audit_ts_test_tampering`.
- Supports dual signature (`source_code` and `ts_code`), positional arguments, and in-place operator mutations (`===` $\leftrightarrow$ `!==`, `<=` $\leftrightarrow$ `<`, `&&` $\leftrightarrow$ `||`, `return null;`).

### `cordis/polyglot_gate.py` (Upgrade 11.2)
- **Go AST Invariant Engine**:
  - `index_go_ast_anchors`: 64-bit cryptographic BLAKE2b function and method anchors (`¶file.go#16hex`). Strips generic bracketed types (`Cache[K, V]`) before whitespace tokenization.
  - `audit_go_test_tampering`: Detects `t.Skip` / `t.Skipf` / `t.SkipNow`, blank identifier discards (`_ = got`), table-driven slice shrinking, and hollow assertions (`assert.NotNil`).
  - `generate_go_mutants`: Inverts relational and logical operators, replaces return values with zero values (`nil`, `false`, `0`, `""`), and returns `[]` on missing target functions.
- **Rust Invariant Engine** (Grounded in Prusti & Creusot formal verification):
  - `index_rust_ast_anchors`: 64-bit BLAKE2b anchors supporting nested block comments (`/* /* */ */`), raw strings (`r###"..."###`), and lifetimes (`'a`).
  - `audit_rust_test_tampering`: Catches `#[ignore]` attributes, weak status checks (`assert!(x.is_ok())`, `assert!(x.is_some())` without checking inner payloads), tautologies (`assert_eq!(x, x)`), and newly added `.unwrap()` / `.expect()` in production code.
  - `generate_rust_mutants`: Synthesizes mutants (`==`, `<=`, `&&`, `+`, `return Default::default();`).

---

## 3. Git Diff Integration & Roadmap

### `cordis/git_diff.py`
- Added `GO_EXTENSIONS = (".go",)` and `RUST_EXTENSIONS = (".rs",)` to `SUPPORTED_EXTENSIONS`.
- Updated `is_test_file` to detect Go tests (`*_test.go`), Rust test files (`*_test.rs`, `tests.rs`), and inline `#[cfg(test)]`.
- Unified diff routing in `parse_git_diff_text` dynamically routes Go and Rust diff hunks to `index_go_ast_anchors` and `index_rust_ast_anchors`, with deduplication by unique `(identifier, scope_path, lineno, end_lineno)` tuples.

### Verification Suite
- 324 repository unit tests passing (100% pass rate).
- 52 adversarial stress tests across `test_stream_gate_stress.py` (23 tests) and `test_polyglot_gate_stress.py` (29 tests) passing with 0 deficiencies.
- Pre-commit mutation prosecution (`verify-git`) reports zero surviving mutants on all modified functions.
