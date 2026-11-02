# Upstream PR: Add Direct Stream Buffer & Key Parser Branch Unit Tests

- **Target Repository**: [theskumar/python-dotenv](https://github.com/theskumar/python-dotenv)
- **Target Commit**: `bad5771ce54fd643538f177aab1465e4375e2039` (`bad5771`)
- **Target Files**: `tests/test_parser.py`
- **Discovered By**: Cordis Adversarial AST Mutation Gate (Experiment C: Wild Open-Source Audit)

---

## 1. Upstream GitHub PR Submission Template

### PR Title
`test(parser): add unit tests for Reader.read() buffer bounds and parse_key() single-quoted branch`

### PR Description
```markdown
### Summary
This PR adds direct unit tests for internal parser primitives in `dotenv.parser`:
1. `Reader.read`: Verifies incremental slice reads across buffer boundaries and asserts that attempting to read beyond buffer capacity raises `dotenv.parser.Error("read: End of string")`.
2. `parse_key`: Exercises single-quoted keys (`'KEY'=val`), unquoted bare keys (`KEY=val`), and inline comment prefix ignores (`# comment`).

### Problem & Invariant Verification
Existing tests in `tests/test_parser.py` primarily exercise `parse_stream` on composite strings using regular expressions. As a result:
- In `Reader.read()` (`src/dotenv/parser.py:91-97`), shifting `<` to `<=` or flipping `<` to `>=` on line 94, or flipping `+` to `-` on line 93 survived all 58 existing parser tests because `Reader.read()` was unexercised by boundary test cases.
- In `parse_key()` (`src/dotenv/parser.py:113-121`), single-quoted key parsing (`elif char == "'":`) was never invoked in unit tests, allowing line 118 `==` to be flipped to `!=` without test failure.

### Verification
Ran test suite before and after:
```powershell
pytest tests/test_parser.py -q
```
Result: All existing tests continue to pass; all newly added tests pass cleanly.
```

---

## 2. Unified Git Diff Patch

```diff
diff --git a/tests/test_parser.py b/tests/test_parser.py
index 982305a..46d5693 100644
--- a/tests/test_parser.py
+++ b/tests/test_parser.py
@@ -761,3 +761,27 @@ def test_parse_stream(test_input, expected):
     result = parse_stream(io.StringIO(test_input))
 
     assert list(result) == expected
+
+
+def test_reader_read_buffer_bounds():
+    from dotenv.parser import Reader, Error
+    import io, pytest
+    reader = Reader(io.StringIO("abcde"))
+    assert reader.read(2) == "ab"
+    assert reader.read(3) == "cde"
+    with pytest.raises(Error):
+        reader.read(1)
+
+
+def test_parse_key_single_quoted_and_branches():
+    from dotenv.parser import Reader, parse_key
+    import io
+    # Single-quoted key branch
+    r1 = Reader(io.StringIO("'MY_CONFIG_KEY'=some_value"))
+    assert parse_key(r1) == "MY_CONFIG_KEY"
+    assert r1.peek(1) == "="
+    # Comment branch
+    r2 = Reader(io.StringIO("# this is a comment"))
+    assert parse_key(r2) is None
+    # Unquoted key branch
+    r3 = Reader(io.StringIO("BARE_KEY=val"))
+    assert parse_key(r3) == "BARE_KEY"
```

---

## 3. Before vs. After AST Mutation Telemetry

| Target Function | Test Suite | Baseline (Wild `HEAD`) | With Upstream Patch | Status |
| :--- | :--- | :---: | :---: | :---: |
| `dotenv.parser:read()` | `tests/test_parser.py` | 0 Killed / 4 Survived (`100.0%` Survival) | **4 Killed / 0 Survived (`100%` Killed)** | 🛡️ **Gap Closed** |
| `dotenv.parser:parse_key()` | `tests/test_parser.py` | 2 Killed / 2 Survived (`50.0%` Survival) | **4 Killed / 0 Survived (`100%` Killed)** | 🛡️ **Gap Closed** |

### Specific Mutants Defeated
- `read()` Line 93: `Flip + to -` (Defeated by `reader.read(2) == "ab"`)
- `read()` Line 94: `Boundary shift < to <=` (Defeated by exact buffer length read)
- `read()` Line 94: `Flip < to >=` (Defeated by reading within bounds)
- `read()` Line 97: `Replace return with None` (Defeated by return value assertion)
- `parse_key()` Line 117: `Replace return with None` (Defeated by single-quoted assertion)
- `parse_key()` Line 118: `Flip == to !=` (Defeated by single-quoted key parsing)
